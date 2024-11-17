package iface

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/wildberries-tech/pkt-tracer/internal/nl"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Iface - common interface for the interface trace
type Iface interface {
	GetIface(index int) (string, error)
	Run(ctx context.Context) (err error)
	Close() error
}

// ifaceImpl - implementation of the Iface interface
type (
	ifaceImpl struct {
		agentSubject observer.Subject
		cache        *IfaceCache
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}

	// CountIfaceNlErrMemEvent -
	CountIfaceNlErrMemEvent struct {
		observer.EventType
	}
)

var _ Iface = (*ifaceImpl)(nil)

func NewIface(as observer.Subject) Iface {
	return &ifaceImpl{
		agentSubject: as,
		cache:        NewCache(),
		stop:         make(chan struct{}),
	}
}

func (i *ifaceImpl) GetIface(index int) (ifname string, err error) {
	ifc, err := i.cache.GetItemById(index)
	return ifc.ifName, err
}

func (i *ifaceImpl) Run(ctx context.Context) (err error) {
	var doRun bool
	i.onceRun.Do(func() {
		doRun = true
		i.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrIface{Err: errors.New("it has been run or closed yet")}
	}

	nlWatcher, err := nl.NewNetlinkWatcher(1, unix.NETLINK_ROUTE,
		nl.SkWithBufLen(nl.SockBufLen16MB),
		nl.SkWithNlMs(unix.RTMGRP_LINK, unix.RTMGRP_IPV4_IFADDR), //TODO Add support for IPv6
	)

	if err != nil {
		return ErrIface{Err: fmt.Errorf("failed to create iface netlink watcher to monitor new ifaces: %v", err)}
	}

	if err = i.cache.Reload(); err != nil {
		return ErrIface{Err: fmt.Errorf("failed to refresh iface cache: %v", err)}
	}

	log := logger.FromContext(ctx).Named("iface")
	ctx1 := logger.ToContext(ctx, log)
	log.Info("start")
	defer func() {
		log.Info("stop")
		nlWatcher.Close()
		close(i.stopped)
	}()
	reader := nlWatcher.Reader(0)
	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-i.stop:
			log.Info("will exit cause it has closed")
			return nil
		case nlData, ok := <-reader.Read():
			if !ok {
				log.Info("will exit cause iface watcher has already closed")
				return ErrIface{Err: errors.New("iface watcher has already closed")}
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					i.agentSubject.Notify(CountIfaceNlErrMemEvent{})
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return ErrIface{Err: errors.WithMessage(err, "failed to rcv nl message")}
			}

			for _, msg := range messages {
				if err = i.handleMsg(ctx1, nl.NetlinkNfMsg(msg)); err != nil {
					return err
				}
			}
		}
	}
}

// handleMsg - handle netlink message
func (i *ifaceImpl) handleMsg(ctx context.Context, msg nl.NetlinkNfMsg) error {
	log := logger.FromContext(ctx)
	t := msg.MsgType()
	switch t {
	case unix.RTM_DELLINK, unix.RTM_NEWLINK:
		var ifName string

		ad, err := netlink.NewAttributeDecoder(msg.DataOffset(nl.NlRtmAttrOffset))
		if err != nil {
			return errors.WithMessage(err, "failed to create new nl attribute decoder")
		}
		ad.ByteOrder = binary.BigEndian
		for ad.Next() {
			if ad.Type() == unix.IFLA_IFNAME {
				ifName = ad.String()
			}
		}
		if ad.Err() != nil {
			return errors.WithMessage(err, "failed to unmarshal attribute")
		}

		if t == unix.RTM_DELLINK {
			i.cache.RmCacheItemByIfName(ifName)
			log.Debugf("removed iface %s", ifName)
		} else {
			log.Debugf("added new iface %s", ifName)
			ifInfo := (*unix.IfInfomsg)(unsafe.Pointer(&msg.Data[0:unix.SizeofIfInfomsg][0]))
			i.cache.Update(ifCacheItem{ifName, int(ifInfo.Index)})
		}
	}
	return nil
}

// Close trace for the ifaces
func (i *ifaceImpl) Close() error {
	i.onceClose.Do(func() {
		close(i.stop)
		i.onceRun.Do(func() {})
		if i.stopped != nil {
			<-i.stopped
		}
	})
	return nil
}
