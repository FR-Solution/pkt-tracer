package registry

import (
	"context"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	ch "github.com/wildberries-tech/pkt-tracer/internal/registry/clickhouse"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	sq "github.com/Masterminds/squirrel"
	"github.com/pkg/errors"
)

var _ Reader = (*clickDbReader)(nil)

type clickDbReader struct {
	reg *clickDbRegistry
}

func (c *clickDbReader) FetchTraces(ctx context.Context, scope *model.TraceScopeModel) (res []model.FetchTraceModel, err error) {
	const (
		table = "swarm.vu_fetch_trace"
	)

	var (
		traces []ch.FetchTraceDB
		filter ch.TraceFilter
	)
	filter.InitFromModel(scope)

	sql, args, err := sq.Select(new(ch.FetchTraceDB).Columns()...).
		From(table).
		Where(filter.Filters()).
		ToSql()
	if err != nil {
		return nil, errors.WithMessage(err, "on building query")
	}

	ok := c.reg.pool.Fetch(func(conn driver.Conn) {
		err = conn.Select(ctx, &traces, sql, args...)
	})
	if !ok {
		err = ErrNoRegistry
	}
	for _, tr := range traces {
		res = append(res, tr.ToModel())
	}
	return res, errors.WithMessage(err, "on obtaining traces from db")
}

func (c *clickDbReader) FetchNftTable(ctx context.Context, scope Scope) (res []model.FetchNftTableModel, err error) {
	const (
		table = "swarm.nftables"
		sel   = "*"
	)
	var (
		nftTables []ch.FetchNftTablesDB
		filter    ch.NftTablesFilter
	)
	filter.InitFromScope(scope)

	sql, args, err := sq.Select(sel).
		From(table).
		Where(filter.Filters()).
		ToSql()
	if err != nil {
		return nil, errors.WithMessage(err, "on building query")
	}

	ok := c.reg.pool.Fetch(func(conn driver.Conn) {
		err = conn.Select(ctx, &nftTables, sql, args...)
	})
	if !ok {
		err = ErrNoRegistry
	}
	for _, tb := range nftTables {
		res = append(res, tb.ToModel())
	}
	return res, errors.WithMessage(err, "on obtaining nftables from db")
}

func (c *clickDbReader) Close() (err error) {
	return nil
}
