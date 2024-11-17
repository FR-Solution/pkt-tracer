package registry

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/H-BF/corlib/logger"
)

type ClickOptions clickhouse.Options

// BuildFromDSN - create build from the dsn link
func BuildFromDSN(dsn string) (*ClickOptions, error) {
	opt, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}

	opt.DialContext = func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return (*ClickOptions)(opt), nil
}

// WithClientInfo - some client information
func (bld *ClickOptions) WithClientInfo(name, version string) *ClickOptions {
	bld.ClientInfo = clickhouse.ClientInfo{
		Products: []struct {
			Name    string
			Version string
		}{
			{Name: name, Version: version},
		},
	}
	return bld
}

// WithDebug - enable debugging
func (bld *ClickOptions) WithDebug(log logger.TypeOfLogger) *ClickOptions {
	bld.Debug = true
	bld.Debugf = func(format string, v ...interface{}) {
		log.Debugf(format, v)
	}
	return bld
}

// WithMaxExecutionTime - max time for one transaction
func (bld *ClickOptions) WithMaxExecutionTime(t int) *ClickOptions {
	bld.Settings = clickhouse.Settings{
		"max_execution_time": t,
	}
	return bld
}

// WithCompression - enable compression for blocks
func (bld *ClickOptions) WithCompression() *ClickOptions {
	bld.Compression = &clickhouse.Compression{
		Method: clickhouse.CompressionLZ4,
	}
	return bld
}

// WithDialTimeout - the maximum time to establish a connection. Defaults to 1s
func (bld *ClickOptions) WithDialTimeout(d time.Duration) *ClickOptions {
	bld.DialTimeout = d
	return bld
}

// WithMaxOpenConns - max connections for use at any time. More or fewer connections
// may be in the idle pool, but only this number can be used at any time.
// Defaults to MaxIdleConns+5
func (bld *ClickOptions) WithMaxOpenConns(c int) *ClickOptions {
	bld.MaxOpenConns = c
	return bld
}

// WithMaxIdleConns - number of connections to maintain in the pool.
// Connections will be reused if possible. Defaults to 5
func (bld *ClickOptions) WithMaxIdleConns(c int) *ClickOptions {
	bld.MaxIdleConns = c
	return bld
}

// WithConnMaxLifetime - maximum lifetime to keep a connection available. Defaults to 1hr.
// Connections are destroyed after this time,
// with new connections added to the pool as required.
func (bld *ClickOptions) WithConnMaxLifetime(d time.Duration) *ClickOptions {
	bld.ConnMaxLifetime = d
	return bld
}

// WithConnOpenStrategy - determines how the list of node addresses should be consumed and used to open connections
func (bld *ClickOptions) WithConnOpenStrategy(s clickhouse.ConnOpenStrategy) *ClickOptions {
	bld.ConnOpenStrategy = s
	return bld
}

// WithBlockBufferSize - maximum number of blocks to decode into the buffer at once.
// Larger values will increase parallelization at the expense of memory.
// Block sizes are query dependent so while you can set this on the connection,
// we recommend you override per query based on the data it returns. Defaults to 2.
func (bld *ClickOptions) WithBlockBufferSize(size uint8) *ClickOptions {
	bld.BlockBufferSize = size
	return bld
}

func (bld *ClickOptions) WithMaxCompressionBuffer(size int) *ClickOptions {
	bld.MaxCompressionBuffer = size
	return bld
}

// WithTLSConf - TLS options. A non-nil value enables TLS
func (bld *ClickOptions) WithTLSConf(tls *tls.Config) {
	bld.TLS = tls.Clone()
}

// New -
func (bld *ClickOptions) New(ctx context.Context) (driver.Conn, error) {
	return clickhouse.Open((*clickhouse.Options)(bld))
}
