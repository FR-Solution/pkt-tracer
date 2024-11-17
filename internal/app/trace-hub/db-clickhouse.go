package tracehub

import (
	"context"

	appdb "github.com/wildberries-tech/pkt-tracer/internal/registry"

	"github.com/H-BF/corlib/logger"
)

func newClickHouseDB(ctx context.Context) (r appdb.Registry, err error) {
	var dsn string
	if dsn, err = ClickHouseDSN.Value(ctx); err != nil {
		return nil, err
	}
	bld, err := appdb.BuildFromDSN(dsn)
	if err != nil {
		return nil, err
	}

	lvl, err := AppLoggerLevel.Value(ctx)
	if err != nil {
		return nil, err
	}
	if lvl == "DEBUG" {
		bld.WithDebug(logger.FromContext(ctx).Named("click"))
	}

	conn, err := bld.New(ctx)
	if err != nil {
		return nil, err
	}

	maxRowsToFlush, err := ClickMaxRowsInBatch.Value(ctx)
	if err != nil {
		return nil, err
	}

	return appdb.NewRegistryFromClickHouse(
		bld.Auth.Database,
		maxRowsToFlush,
		conn, ServerSubject()), nil
}
