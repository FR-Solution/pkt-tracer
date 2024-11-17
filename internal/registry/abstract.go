package registry

import (
	"context"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"

	"github.com/H-BF/corlib/pkg/filter"
)

type (

	//Reader db reader abstract
	Reader interface {
		FetchTraces(context.Context, *model.TraceScopeModel) ([]model.FetchTraceModel, error)
		FetchNftTable(context.Context, Scope) ([]model.FetchNftTableModel, error)
		Close() error
	}

	//BatchWriter db batch writer abstract
	BatchWriter interface {
		PutTrace(*model.TraceModel) error
		PutNftTable(*model.NftTableModel) error
		Flush() error
		Close() error
	}

	BatchWriterOpt interface {
		isBatchWriterOption()
	}

	//Registry abstract db registry
	Registry interface {
		BatchWriter(ctx context.Context, table string, opts ...BatchWriterOpt) (BatchWriter, error)
		Reader(ctx context.Context) (Reader, error)
		Close() error
	}

	// BatchCapacity  max batch capacity before flush
	BatchCapacity int

	// BatchFlushedCountReporter reports count rows were flushed by batch
	BatchFlushedCountReporter func(int)

	// Scope -
	Scope = filter.Scope
)

func (BatchCapacity) isBatchWriterOption()             {}
func (BatchFlushedCountReporter) isBatchWriterOption() {}
