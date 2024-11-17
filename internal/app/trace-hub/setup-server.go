package tracehub

import (
	"context"

	"github.com/wildberries-tech/pkt-tracer/internal/api/tracehub"
	"github.com/wildberries-tech/pkt-tracer/internal/app"

	"github.com/H-BF/corlib/server"
	"github.com/H-BF/corlib/server/interceptors"
	serverPrometheusMetrics "github.com/H-BF/corlib/server/metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// HandleMetrics -
	HandleMetrics = "metrics"

	// HandleHealthcheck -
	HandleHealthcheck = "healthcheck"

	// HandleDebug -
	HandleDebug = "debug"
)

func SetupTraceHubServer(ctx context.Context) (*server.APIServer, error) {
	flushTimeInterval, err := ClickFlushTimeInterval.Value(ctx)
	if err != nil {
		return nil, err
	}
	checkTimeInterval, err := ClickCheckTimeInterval.Value(ctx)
	if err != nil {
		return nil, err
	}
	srv := tracehub.NewTraceHubeService(ctx, getAppRegistry(), ServerSubject(), flushTimeInterval, checkTimeInterval)

	opts := []server.APIServerOption{
		server.WithServices(srv),
	}

	//если есть регистр Прометеуса то - подклчим метрики
	app.WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
		pm := serverPrometheusMetrics.NewMetrics(
			serverPrometheusMetrics.WithSubsystem("grpc"),
			serverPrometheusMetrics.WithNamespace("server"),
		)
		if err := reg.Register(pm); err != nil {
			return
		}
		recovery := interceptors.NewRecovery(
			interceptors.RecoveryWithObservers(pm.PanicsObserver()), //подключаем prometheus счетчик паник
		)
		//подключаем prometheus метрики
		opts = append(opts, server.WithRecovery(recovery))
		opts = append(opts, server.WithStatsHandlers(pm.StatHandlers()...))
		promHandler := promhttp.InstrumentMetricHandler(
			reg,
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		)
		//экспанируем метрики через 'metrics' обработчик
		opts = append(opts, server.WithHttpHandler("/"+HandleMetrics, promHandler))
	})

	if hc, _ := HealthcheckEnable.Value(ctx); hc { // add healthcheck handler
		opts = append(opts, server.WithHttpHandler("/"+HandleHealthcheck, app.HcHandler{}))
	}
	opts = append(opts, server.WithHttpHandler("/"+HandleDebug, app.PProfHandler()))
	return server.NewAPIServer(opts...)
}
