package visor

import (
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/config"
)

/*//Sample of config

logger:
  level: INFO

useragent: "string"

extapi:
  svc:
    def-daial-duration: 10s
    tracehub:
      dial-duration: 3s #override default-connect-tmo
      address: tcp://127.0.0.1:9006
	  use-compression: false

*/

const (
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

	// UserAgent
	UserAgent config.ValueT[string] = "useragent"
)
