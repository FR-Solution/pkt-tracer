package registry

import (
	"context"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	atm "github.com/H-BF/corlib/pkg/atomic"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/pkg/errors"
)

var (
	// ErrNoRegistry -
	ErrNoRegistry = errors.New("no registry available")

	// ErrWriterClosed -
	ErrWriterClosed = errors.New("writer is closed")
)

// NewRegistryFromClickHouse creates registry from ClickHouse
func NewRegistryFromClickHouse(
	db string,
	rows int,
	conn driver.Conn,
	subj observer.Subject) Registry {
	ret := &clickDbRegistry{
		db:              db,
		maxRowsToFlush:  rows,
		registrySubject: subj,
	}
	ret.pool.Store(conn, nil)

	return ret
}

var _ Registry = (*clickDbRegistry)(nil)

type (
	clickDbRegistry struct {
		pool            atm.Value[driver.Conn]
		db              string
		maxRowsToFlush  int
		registrySubject observer.Subject
	}
	CountDBWriteEvent struct {
		Cnt int
		observer.EventType
	}
)

// BatchWriter impl Registry interface
func (impl *clickDbRegistry) BatchWriter(ctx context.Context, table string, opts ...BatchWriterOpt) (w BatchWriter, err error) {
	var wr *clickDbBatcher
	_ = impl.pool.Fetch(func(_ driver.Conn) {
		wr = &clickDbBatcher{
			reg:   impl,
			table: table,
			cap:   BatchCapacity(impl.maxRowsToFlush),
			ctx:   ctx,
		}
	})
	if wr == nil {
		err = ErrNoRegistry
	} else {
		for _, o := range opts {
			switch t := o.(type) {
			case BatchCapacity:
				wr.cap = t
			case BatchFlushedCountReporter:
				wr.batchReporter = t
			}
		}
	}
	return wr, errors.WithMessage(err, "Click/BatchWriter")
}

// Reader impl Registry interface
func (impl *clickDbRegistry) Reader(_ context.Context) (r Reader, err error) {
	var rd *clickDbReader
	_ = impl.pool.Fetch(func(_ driver.Conn) {
		rd = &clickDbReader{
			reg: impl,
		}
	})
	if rd == nil {
		err = ErrNoRegistry
	}

	return rd, errors.WithMessage(err, "Click/Reader")
}

// Close impl Registry interface
func (imp *clickDbRegistry) Close() error {
	imp.pool.Clear(func(p driver.Conn) {
		p.Close()
	})
	return nil
}
