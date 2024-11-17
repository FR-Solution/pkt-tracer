package nftmonitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/dto"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	nfte "github.com/wildberries-tech/pkt-tracer/internal/nftables/encoders"
	"github.com/wildberries-tech/pkt-tracer/internal/nftables/parser"
	"github.com/wildberries-tech/pkt-tracer/internal/nl"
	proto "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/dict"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/golang/protobuf/ptypes/empty"
	nftLib "github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type (
	TableWatcher interface {
		Run(ctx context.Context) (err error)
		Close() error
	}
	StreamCli interface {
		Send(*proto.SyncTableReq) error
		CloseAndRecv() (*empty.Empty, error)
		Context() context.Context
	}
	NetlinkWatcher interface {
		Read() chan nl.NlData
	}
	cacheFace interface {
		dict.Dict[TableEntryKey, TableEntry]
		PutTable(entry TableEntry)
		Refresh() error
	}
	// Deps - dependency
	Deps struct {
		// Adapters
		Client       StreamCli
		AgentSubject observer.Subject
		NlWatcher    NetlinkWatcher
	}
	tableWatcherImpl struct {
		Deps
		syncInterval time.Duration
		cache        cacheFace
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}
	// CountTableWatcherNlErrMemEvent -
	CountTableWatcherNlErrMemEvent struct {
		observer.EventType
	}
)

func NewTableWatcher(d Deps, si time.Duration) TableWatcher {
	if si < time.Second {
		panic(
			fmt.Errorf("'TableWatcher/TableSyncInterval' is (%v) less than 1s", si),
		)
	}
	return &tableWatcherImpl{
		Deps:         d,
		syncInterval: si,
		cache:        &tableCache{},
		stop:         make(chan struct{}),
	}
}

func (t *tableWatcherImpl) Run(ctx context.Context) (err error) {
	var (
		doRun bool
	)

	t.onceRun.Do(func() {
		doRun = true
		t.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrTableWatcher{Err: errors.New("it has been run or closed yet")}
	}

	log := logger.FromContext(ctx).Named("nftable-watcher")
	ctx1 := logger.ToContext(ctx, log)

	log.Info("start")
	defer func() {
		if _, e := t.Deps.Client.CloseAndRecv(); e != nil {
			log.Warnf("on closing grpc stream for transmitting tables: %v", e)
		}
		log.Info("stop")
		close(t.stopped)
	}()

	err = t.cache.Refresh()
	if err != nil {
		return ErrTableWatcher{Err: errors.WithMessage(err, "failed to refresh cache of tables")}
	}

	tc := time.NewTicker(t.syncInterval)
	defer tc.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-t.stop:
			log.Info("will exit cause it has closed")
			return nil
		case <-tc.C:
			var (
				tablesEntry []TableEntry
			)
			t.cache.Iterate(func(_ TableEntryKey, te TableEntry) bool {
				if time.Since(te.UpdatedAt) >= t.syncInterval && te.UpdatedAt.After(te.UsedAt) {
					tablesEntry = append(tablesEntry, te)
				}
				return true
			})
			for _, te := range tablesEntry {
				tblStr, err := te.String()
				if err != nil {
					return ErrTableWatcher{Err: errors.WithMessage(err, "failed to encode nft table to string")}
				}
				te.UsedAt = time.Now()
				t.cache.PutTable(te)

				tblModel := model.NftTableModel{
					TableName:   te.Table.Name,
					TableFamily: parser.TableFamily(te.Table.Family).String(),
					TableStr:    tblStr,
				}
				ruleStr := ""
				te.OrderedChains.Iterate(func(ce *ChainEntry) bool {
					ce.OrderedRules.Iterate(func(re *RuleEntry) bool {
						ruleStr, err = re.String()
						if err != nil {
							return false
						}
						tblModel.Rules = append(tblModel.Rules, &model.NftRule{
							ChainName: ce.Chain.Name,
							Rule:      ruleStr,
						})
						return true
					})

					return err == nil
				})
				if err != nil {
					return ErrTableWatcher{Err: err}
				}
				if err = t.sendTable(&tblModel); err != nil {
					return ErrTableWatcher{Err: err}
				}
			}

		case nlData, ok := <-t.Deps.NlWatcher.Read():
			if !ok {
				log.Info("will exit cause netlink table watcher has already closed")
				return ErrTableWatcher{Err: errors.New("netlink table watcher has already closed")}
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					t.Deps.AgentSubject.Notify(CountTableWatcherNlErrMemEvent{})
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return ErrTableWatcher{Err: errors.WithMessage(err, "failed to receive netlink message")}
			}

			for _, msg := range messages {
				if err = t.handleMsg(ctx1, nl.NetlinkNfMsg(msg)); err != nil {
					return err
				}
			}
		}
	}
}

func (t *tableWatcherImpl) sendTable(md *model.NftTableModel) error {
	tblDto := dto.NftTableDTO{}
	tblDto.InitFromModel(md)
	return t.Deps.Client.Send(&proto.SyncTableReq{
		Table: append(([]*proto.NftTable)(nil), tblDto.ToProto()),
	})
}

// handleMsg - handle netlink message
func (t *tableWatcherImpl) handleMsg(ctx context.Context, msg nl.NetlinkNfMsg) error {
	log := logger.FromContext(ctx)
	nlMsg := netlink.Message{
		Data: msg.Data,
		Header: netlink.Header{
			Length:   msg.Header.Len,
			Type:     netlink.HeaderType(msg.Header.Type),
			Flags:    netlink.HeaderFlags(msg.Header.Flags),
			Sequence: msg.Header.Seq,
			PID:      msg.Header.Pid,
		},
	}
	msgType := msg.MsgType()
	switch msgType {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
		table := new(parser.Table)
		err := table.InitFromMsg(nlMsg)
		if err != nil {
			return errors.WithMessage(err, "failed to get nft table from netlink message")
		}

		switch msgType {
		case unix.NFT_MSG_NEWTABLE:
			t.cache.PutTable(TableEntry{Table: (*nftLib.Table)(table), UpdatedAt: time.Now()})
			log.Debugf("added new table name='%s', family='%s'", table.Name, table.Family)
		case unix.NFT_MSG_DELTABLE:
			t.cache.Del(TableEntryKey{
				TableName:   table.Name,
				TableFamily: table.Family,
			})
			log.Debugf("removed table name='%s', family='%s'", table.Name, table.Family)
		}
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
		chain := new(parser.Chain)
		err := chain.InitFromMsg(nlMsg)
		if err != nil {
			return errors.WithMessage(err, "failed to get chain from netlink message")
		}
		table, ok := t.cache.Get(TableEntryKey{
			TableName:   chain.Table.Name,
			TableFamily: chain.Table.Family,
		})
		if !ok {
			return errors.Errorf("failed to find table '%s' family '%s' in cache by related chain '%s'",
				chain.Table.Name, parser.TableFamily(chain.Table.Family), chain.Name)
		}
		switch msgType {
		case unix.NFT_MSG_NEWCHAIN:
			table.PutChains((*nftLib.Chain)(chain))
			log.Debugf("added new chain name='%s' into the table '%s' with family='%s'",
				chain.Name, chain.Table.Name, parser.TableFamily(chain.Table.Family))
		case unix.NFT_MSG_DELCHAIN:
			table.RmChains((*nftLib.Chain)(chain))
			log.Debugf("removed chain name='%s' from the table '%s' with family='%s'",
				chain.Name, chain.Table.Name, parser.TableFamily(chain.Table.Family))
		}
		t.cache.PutTable(table.Timed())

	case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET:
		set := new(parser.Set)
		err := set.InitFromMsg(nlMsg)
		if err != nil {
			return errors.WithMessage(err, "failed to get set from netlink message")
		}
		table, ok := t.cache.Get(TableEntryKey{
			TableName:   set.Table.Name,
			TableFamily: set.Table.Family,
		})
		if !ok {
			return errors.Errorf("failed to find table '%s' family '%s' in cache by related set '%s'",
				set.Table.Name, parser.TableFamily(set.Table.Family), set.Name)
		}
		switch msgType {
		case unix.NFT_MSG_NEWSET:
			table.PutSets(set.Set)
			log.Debugf("added new set name='%s' into the table '%s' with family='%s'",
				set.Name, set.Table.Name, parser.TableFamily(set.Table.Family))
		case unix.NFT_MSG_DELSET:
			table.RmSets(set.Set)
			log.Debugf("removed set name='%s' from the table '%s' with family='%s'",
				set.Name, set.Table.Name, parser.TableFamily(set.Table.Family))
		}
		t.cache.PutTable(table.Timed())

	case unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:
		set := new(parser.Set)
		err := set.GetElementsFromMsg(nlMsg)
		if err != nil {
			return errors.WithMessage(err, "failed to get set and its elements from the netlink message")
		}
		table, ok := t.cache.Get(TableEntryKey{
			TableName:   set.Table.Name,
			TableFamily: set.Table.Family,
		})
		if !ok {
			return errors.Errorf("failed to find table with name='%s' and family='%s' in cache by related set name='%s' and set id=%d",
				set.Table.Name, parser.TableFamily(set.Table.Family), set.Name, set.ID)
		}
		se, ok := table.GetSetEntry(SetEntryKey{
			TableEntryKey: TableEntryKey{
				TableName:   set.Table.Name,
				TableFamily: set.Table.Family,
			},
			SetName: set.Name,
		})
		if !ok {
			return errors.Errorf(
				"failed to find set with name='%s' and id=%d in the cache for the table with name='%s' and family='%s'",
				set.Name, set.ID, set.Table.Name, parser.TableFamily(set.Table.Family),
			)
		}
		switch msgType {
		case unix.NFT_MSG_NEWSETELEM:
			se.PutElements(set.Elems...)
			log.Debugf("added new set elements: %s into set='%s'", parser.Set{Set: se.Set, Elems: set.Elems}.String(), se.Set.Name)

		case unix.NFT_MSG_DELSETELEM:
			se.RmElements(set.Elems...)
			log.Debugf("removed set elements: %s from set='%s'", parser.Set{Set: se.Set, Elems: set.Elems}.String(), se.Set.Name)
		}
		t.cache.PutTable(table.Timed())
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		rl := new(parser.Rule)
		err := rl.InitFromMsg(nlMsg)
		if err != nil {
			return errors.WithMessage(err, "failed to get rule from netlink message")
		}

		table, ok := t.cache.Get(TableEntryKey{
			TableName:   rl.Table.Name,
			TableFamily: rl.Table.Family,
		})
		if !ok {
			return errors.Errorf(
				"failed to find table '%s' family '%s' in cache by related rule handle=%d",
				rl.Table.Name, parser.TableFamily(rl.Table.Family), rl.Handle,
			)
		}
		chain, ok := table.GetChainEntry(ChainEntryKey{
			TableEntryKey: TableEntryKey{
				TableName:   rl.Table.Name,
				TableFamily: rl.Table.Family,
			},
			ChainName: rl.Chain.Name,
		})
		if !ok {
			return errors.Errorf(
				"failed to find chain '%s' from table '%s' and family '%s' in cache by related rule handle=%d",
				rl.Chain.Name, rl.Table.Name, parser.TableFamily(rl.Table.Family), rl.Handle,
			)
		}

		strRule, err := (*nfte.RuleEncode)(rl).String()
		if err != nil {
			return err
		}

		switch msgType {
		case unix.NFT_MSG_NEWRULE:
			chain.PutRules((*nftLib.Rule)(rl))
			log.Debugf("added new rule=%d, expr: %s", rl.Handle, strRule)
		case unix.NFT_MSG_DELRULE:
			chain.RmRule((*nftLib.Rule)(rl))
			log.Debugf("removed rule=%d, expr: %s", rl.Handle, strRule)
		}
		t.cache.PutTable(table.Timed())
	}
	return nil
}

func (t *tableWatcherImpl) Close() error {
	t.onceClose.Do(func() {
		close(t.stop)
		t.onceRun.Do(func() {})
		if t.stopped != nil {
			<-t.stopped
		}
	})
	return nil
}
