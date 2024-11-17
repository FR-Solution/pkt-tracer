package tracehub

import (
	"context"
	"os"

	"github.com/wildberries-tech/pkt-tracer/internal/app"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/prometheus/client_golang/prometheus"
)

type ServerMetrics struct {
	traceCount   prometheus.Counter
	dbWriteCount prometheus.Counter
}

var serverMetricsHolder atomic.Value[*ServerMetrics]

const (
	labelHostName = "host_name"
	nsServer      = "server"
	nsDB          = "db"
)

// SetupMetrics -
func SetupMetrics(ctx context.Context) error {
	if !MetricsEnable.MustValue(ctx) {
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	labels := prometheus.Labels{
		labelHostName: hostname,
	}
	am := new(ServerMetrics)
	am.init(labels)
	metricsOpt := app.AddMetrics{
		Metrics: []prometheus.Collector{
			app.NewHealthcheckMetric(labels),
			am.traceCount,
			am.dbWriteCount,
		},
	}
	err = app.SetupMetrics(metricsOpt)
	if err == nil {
		serverMetricsHolder.Store(am, nil)
	}
	return err
}

// GetMetrics -
func GetMetrics() *ServerMetrics {
	v, _ := serverMetricsHolder.Load()
	return v
}

func (am *ServerMetrics) init(labels prometheus.Labels) {
	am.traceCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsServer,
		Name:        "traces_counter",
		Help:        "count of data received through grpc",
		ConstLabels: labels,
	})
	am.dbWriteCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsDB,
		Name:        "write_counter",
		Help:        "count of data wrote to DB",
		ConstLabels: labels,
	})
}

// ObserveTracesCounter -
func (am *ServerMetrics) ObserveTracesCounter() {
	am.traceCount.Inc()
}

// ObserveTracesCounter -
func (am *ServerMetrics) ObserveDBWriteCounter(cnt int) {
	am.dbWriteCount.Add(float64(cnt))
}
