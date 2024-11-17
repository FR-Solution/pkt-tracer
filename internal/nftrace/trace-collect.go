package nftrace

import (
	"context"
	"fmt"
	"sync"
	"time"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/nltrace"
	"github.com/wildberries-tech/pkt-tracer/internal/nl"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/pkg/queue"
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// TraceCollector - common interface to collect traces
type TraceCollector interface {
	Run(ctx context.Context) error
	Reader() <-chan []model.NetlinkTrace
	Close() error
}

// traceCollectorImpl - implementation of the TraceCollector interface
type (
	traceCollectorImpl struct {
		agentSubject observer.Subject
		que          queue.FIFO[[]model.NetlinkTrace]
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}
	CountCollectNlErrMemEvent struct {
		observer.EventType
	}
)

var _ TraceCollector = (*traceCollectorImpl)(nil)

func NewCollector(as observer.Subject) (TraceCollector, error) {
	cl := &traceCollectorImpl{
		agentSubject: as,
		que:          queue.NewFIFO[[]model.NetlinkTrace](),
		stop:         make(chan struct{}),
	}

	return cl, nil
}

func (c *traceCollectorImpl) Run(ctx context.Context) (err error) {
	var doRun bool
	c.onceRun.Do(func() {
		doRun = true
		c.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrCollect{Err: errors.New("it has been run or closed yet")}
	}

	nlWatcher, err := nl.NewNetlinkWatcher(1, unix.NETLINK_NETFILTER,
		nl.SkWithBufLen(nl.SockBufLen16MB),
		nl.SkWithNlMs(unix.NFNLGRP_NFTRACE),
	)

	if err != nil {
		return ErrCollect{Err: fmt.Errorf("failed to create trace-watcher: %v", err)}
	}

	log := logger.FromContext(ctx).Named("collector")
	log.Info("start")
	defer func() {
		log.Info("stop")
		nlWatcher.Close()
		close(c.stopped)
	}()
	reader := nlWatcher.Reader(0)
	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-c.stop:
			log.Info("will exit cause it has closed")
			return nil
		case nlData, ok := <-reader.Read():
			if !ok {
				log.Info("will exit cause trace watcher has already closed")
				return ErrCollect{Err: errors.New("trace watcher has already closed")}
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					c.agentSubject.Notify(CountCollectNlErrMemEvent{})
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return ErrCollect{Err: errors.WithMessage(err, "failed to rcv nl message")}
			}
			var traces []model.NetlinkTrace
			t := time.Now()
			for _, msg := range messages {
				tr := new(NftnlTrace)
				if err = tr.InitFromMsg(netlink.Message{
					Data: msg.Data,
					Header: netlink.Header{
						Length:   msg.Header.Len,
						Type:     netlink.HeaderType(msg.Header.Type),
						Flags:    netlink.HeaderFlags(msg.Header.Flags),
						Sequence: msg.Header.Seq,
						PID:      msg.Header.Pid,
					},
				}); err != nil {
					return err
				}

				m := tr.ToModel()
				m.At = t
				traces = append(traces, m)
			}
			c.que.Put(traces)
		}
	}
}

func (c *traceCollectorImpl) Reader() <-chan []model.NetlinkTrace {
	return c.que.Reader()
}

// Close collector
func (c *traceCollectorImpl) Close() error {
	c.onceClose.Do(func() {
		close(c.stop)
		c.onceRun.Do(func() {})
		if c.stopped != nil {
			<-c.stopped
		}
		_ = c.que.Close()
	})
	return nil
}
