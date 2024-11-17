package pkttracer

import (
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/config"
)

/*//Sample of config

graceful-shutdown: 10s

logger:
  level: INFO

extapi:
  svc:
    def-daial-duration: 10s
    tracehub:
      dial-duration: 3s #override default-connect-tmo
      address: tcp://127.0.0.1:9006
	  use-compression: false
	  sync-interval: 1s
	sgroups:
      dial-duration: 3s #override default-connect-tmo
      address: tcp://127.0.0.1:9006
	  sync-status:
        interval: 20s #mandatory
        push: true

telemetry:
  useragent: "string"
  endpoint: 127.0.0.1:5000
  metrics:
    enable: true
  healthcheck:
    enable: true

*/

const (
	// AppGracefulShutdown [optional]
	AppGracefulShutdown config.ValueT[time.Duration] = "graceful-schutdown"

	// LoggerLevel log level
	AppLoggerLevel config.ValueT[string] = "logger/level"

	// ServicesDefDialDuration default dial duraton to conect a service [optional]
	ServicesDefDialDuration config.ValueT[time.Duration] = "extapi/svc/def-daial-duration"

	// TrDialDuration trace-hub service dial duration [optional]
	TrDialDuration config.ValueT[time.Duration] = "extapi/svc/tracehub/dial-duration"

	// TrAddress service address [mandatory]
	TrAddress config.ValueT[string] = "extapi/svc/tracehub/address"

	// UseCompression enable compression for grpc messages
	UseCompression config.ValueT[bool] = "extapi/svc/tracehub/use-compression"

	// TableSyncInterval time interval to update new state of nftables on server
	TableSyncInterval config.ValueT[time.Duration] = "extapi/svc/tracehub/sync-interval"

	// TelemetryEndpoint server endpoint
	TelemetryEndpoint config.ValueT[string] = "telemetry/endpoint"

	// MetricsEnable enable api metrics
	MetricsEnable config.ValueT[bool] = "telemetry/metrics/enable"

	// HealthcheckEnable enables|disables health check handler
	HealthcheckEnable config.ValueT[bool] = "telemetry/healthcheck/enable"

	// UserAgent
	UserAgent config.ValueT[string] = "telemetry/useragent"

	//SGroupsAddress service address [mandatory]
	SGroupsAddress config.ValueT[string] = "extapi/svc/sgroups/address"
	//SGroupsDialDuration sgroups service dial duration [optional]
	SGroupsDialDuration config.ValueT[time.Duration] = "extapi/svc/sgroups/dial-duration"
	//SGroupsSyncStatusInterval interval(duration) backend 'sync-status' check [mandatory]
	SGroupsSyncStatusInterval config.ValueT[time.Duration] = "extapi/svc/sgroups/sync-status/interval"
	//SGroupsSyncStatusPush use push model of 'sync-status'
	SGroupsSyncStatusPush config.ValueT[bool] = "extapi/svc/sgroups/sync-status/push"
)
