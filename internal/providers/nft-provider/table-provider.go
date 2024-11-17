package nftprovider

import (
	"context"
	"fmt"
	"sync"
	"time"

	thAPI "github.com/wildberries-tech/pkt-tracer/internal/api/tracehub"
	proto "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type (
	Client interface {
		FetchNftTable(context.Context, *proto.FetchNftTableQry, ...grpc.CallOption) (*proto.NftTableList, error)
	}

	THClient = thAPI.Client

	TableProvider interface {
		Run(context.Context) error
		GetTableById(id uint64) (tbl string, err error)
		Close() error
	}
	cacheFace interface {
		Get(k uint64) (v string, ok bool)
		Put(k uint64, v string)
	}
	// Deps - dependency
	Deps struct {
		// Adapters
		Cli Client
	}
	tblProviderImpl struct {
		Deps
		syncInterval time.Duration
		cache        cacheFace
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}
)

func NewTableProvider(d Deps, si time.Duration) TableProvider {
	if si < time.Second {
		panic(
			fmt.Errorf("'TableProvider/TableSyncInterval' is (%v) less than 1s", si),
		)
	}
	return &tblProviderImpl{
		Deps:         d,
		syncInterval: si,
		cache:        &cache{},
		stop:         make(chan struct{}),
	}
}

func (t *tblProviderImpl) GetTableById(id uint64) (tbl string, err error) {
	tbl, ok := t.cache.Get(id)
	if !ok {
		tbl, err = "", ErrCacheMiss
	}
	return tbl, err
}

func (t *tblProviderImpl) Run(ctx context.Context) (err error) {
	var doRun bool
	t.onceRun.Do(func() {
		doRun = true
		t.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrTblProvider{Err: errors.New("it has been run or closed yet")}
	}
	log := logger.FromContext(ctx).Named("nftable-watcher")
	log.Info("start")
	defer func() {
		log.Info("stop")
		close(t.stopped)
	}()

	err = t.refreshCache(ctx)
	if err != nil {
		return ErrTblProvider{Err: errors.WithMessage(err, "failed to refresh cache of tables")}
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
			err = t.refreshCache(ctx)
			if err != nil {
				err = ErrTblProvider{Err: errors.WithMessage(err, "failed to refresh cache of tables")}
				return err
			}
		}
	}
}

func (t *tblProviderImpl) Close() error {
	t.onceClose.Do(func() {
		close(t.stop)
		t.onceRun.Do(func() {})
		if t.stopped != nil {
			<-t.stopped
		}
	})
	return nil
}

func (t *tblProviderImpl) refreshCache(ctx context.Context) error {
	tblList, err := t.Cli.FetchNftTable(
		ctx,
		&proto.FetchNftTableQry{Scoped: &proto.FetchNftTableQry_NoScope{}},
	)
	if err != nil {
		return err
	}
	for _, table := range tblList.GetTables() {
		t.cache.Put(table.GetTableId(), table.GetTableStr())
	}
	return nil
}
