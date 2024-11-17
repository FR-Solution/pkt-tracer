package tracehub

import (
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/config"
)

/*//Sample of config
logger:
  level: INFO

metrics:
  enable: true

healthcheck:
  enable: true

server:
  endpoint: tcp://127.0.0.1:9006
  graceful-shutdown: 30s

storage:
   type: clickhouse
   clickhouse:
       rows-for-flush: 10
	   flushing-interval: 3s
	   checking-interval: 1s
	   url: tcp://user:password@localhost:9000/database?max_execution_time=60&dial_timeout=10s&client_info_product=trace-hub/0.0.1&compress=lz4&block_buffer_size=10&max_compression_buffer=10240&skip_verify=true
*/

const (
	// LoggerLevel log level
	AppLoggerLevel config.ValueT[string] = "logger/level"

	// ServerEndpoint server endpoint
	ServerEndpoint config.ValueT[string] = "server/endpoint"

	// ServerGracefulShutdown graceful shutdown period
	ServerGracefulShutdown config.ValueT[time.Duration] = "server/graceful-shutdown"

	// MetricsEnable enable api metrics
	MetricsEnable config.ValueT[bool] = "metrics/enable"

	// HealthcheckEnable enables|disables health check handler
	HealthcheckEnable config.ValueT[bool] = "healthcheck/enable"

	// StorageType selects storage DB backend
	StorageType config.ValueT[string] = "storage/type"

	// ClickHouseDSN URL to connect to ClickHouse DB
	ClickHouseDSN config.ValueT[string] = "storage/clickhouse/url"

	// ClickMaxRowsInBatch number of rows saved before flush
	ClickMaxRowsInBatch config.ValueT[int] = "storage/clickhouse/rows-for-flush"

	// ClickFlushTimeInterval maximum time interval between flushing stored rows
	ClickFlushTimeInterval config.ValueT[time.Duration] = "storage/clickhouse/flushing-interval"

	// ClickCheckTimeInterval time interval between checking new records in DB
	ClickCheckTimeInterval config.ValueT[time.Duration] = "storage/clickhouse/checking-interval"
)
