package pkttracer

import (
	"context"
	"os"

	"github.com/wildberries-tech/pkt-tracer/internal/app"
	grpc_client "github.com/wildberries-tech/pkt-tracer/internal/grpc-client"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/prometheus/client_golang/prometheus"
)

type AgentMetrics struct {
	traceCount    prometheus.Counter
	errNlMemCount *prometheus.CounterVec
}

var agentMetricsHolder atomic.Value[*AgentMetrics]

const (
	labelUserAgent = "user_agent"
	labelHostName  = "host_name"
	nsAgent        = "agent"
	labelSource    = "source"
)

const ( // error sources
	// ESrcIface -
	ESrcIface = "iface"

	// ESrcCollector -
	ESrcCollector = "collector"

	// ESrcRuler -
	ESrcRuler = "ruler"
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
		labelUserAgent: UserAgent.MustValue(ctx),
		labelHostName:  hostname,
	}
	am := new(AgentMetrics)
	am.init(labels)
	metricsOpt := app.AddMetrics{
		Metrics: []prometheus.Collector{
			app.NewHealthcheckMetric(labels),
			grpc_client.GRPCClientMetrics(),
			am.traceCount,
			am.errNlMemCount,
		},
	}
	err = app.SetupMetrics(metricsOpt)
	if err == nil {
		agentMetricsHolder.Store(am, nil)
	}
	return err
}

// GetAgentMetrics -
func GetAgentMetrics() *AgentMetrics {
	v, _ := agentMetricsHolder.Load()
	return v
}

func (am *AgentMetrics) init(labels prometheus.Labels) {
	am.traceCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsAgent,
		Name:        "traces_counter",
		Help:        "count of traces send through grpc",
		ConstLabels: labels,
	})
	am.errNlMemCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   nsAgent,
		Name:        "err_nl_mem_counter",
		Help:        "count of netlink receive buffer overload",
		ConstLabels: labels,
	}, []string{labelSource})
}

// ObserveTracesCounter -
func (am *AgentMetrics) ObserveTracesCounter(cnt int) {
	am.traceCount.Add(float64(cnt))
}

// ObserveErrNlMemCounter -
func (am *AgentMetrics) ObserveErrNlMemCounter(errSource string) {
	am.errNlMemCount.WithLabelValues(errSource).Inc()
}
