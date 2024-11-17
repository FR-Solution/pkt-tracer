package tracehub

import (
	"errors"
	"io"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/dto"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	"github.com/wildberries-tech/pkt-tracer/internal/registry"
	th "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CountNftablesSyncEvent -
type CountNftablesSyncEvent struct {
	Cnt int
	observer.EventType
}

type NftablesWriter interface {
	PutNftTable(*model.NftTableModel) error
	Flush() error
	Close() error
}

func (srv *thService) SyncNftTables(stream th.TraceHubService_SyncNftTablesServer) (err error) {
	var (
		wr          NftablesWriter
		ctxInc      = stream.Context()
		dbTableName = "nftables_tmp"
		flushTimer  = time.NewTicker(srv.flushTimeInterval)
		flushedAt   *time.Time
	)
	defer flushTimer.Stop()
	onFlush := func(_ int) {
		at := time.Now()
		flushedAt = &at
	}
	wr, err = srv.reg.BatchWriter(ctxInc, dbTableName, registry.BatchFlushedCountReporter(onFlush))
	if err != nil {
		return err
	}
	defer wr.Close()
	incoming := make(chan any, 1)
	go func() {
		defer close(incoming)
		var e error
		var v any
		for e == nil {
			if v, e = stream.Recv(); e != nil {
				v = e
			}
			select {
			case <-srv.appCtx.Done():
				return
			case incoming <- v:
			}
		}
	}()

loop:
	for err == nil {
		select {
		case v, ok := <-incoming:
			if !ok {
				break loop
			}
			switch t := v.(type) {
			case error:
				err = t
			case *th.SyncTableReq:
				tables := t.GetTable()
				for _, tbl := range tables {
					var dtoTable dto.NftTableDTO
					dtoTable.InitFromProto(tbl)
					tblMd := dtoTable.ToModel()
					err = wr.PutNftTable(tblMd)
					if err != nil {
						break
					}
				}
			}
		case <-srv.appCtx.Done():
			err = srv.appCtx.Err()
		case <-flushTimer.C:
			if flushedAt == nil || time.Since(*flushedAt) >= srv.flushTimeInterval {
				err = wr.Flush()
			}
		}
	}
	_ = stream.SendAndClose(&emptypb.Empty{})

	if err == nil || errors.Is(err, io.EOF) {
		err = wr.Flush()
	}
	return err
}
