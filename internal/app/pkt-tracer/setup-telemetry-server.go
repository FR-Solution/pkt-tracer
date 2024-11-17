package pkttracer

import (
	"context"

	"github.com/wildberries-tech/pkt-tracer/internal/app"

	"github.com/H-BF/corlib/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// WhenSetupTelemtryServer -
func WhenSetupTelemtryServer(ctx context.Context, f func(*server.APIServer) error) error {
	var (
		opts []server.APIServerOption
		err  error
	)
	app.WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
		//подключаем prometheus метрики
		promHandler := promhttp.InstrumentMetricHandler(
			reg,
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		)
		opts = append(opts, server.WithHttpHandler("/metrics", promHandler))
	})
	if hc, _ := HealthcheckEnable.Value(ctx); hc {
		opts = append(opts, server.WithHttpHandler("/healthcheck", app.HcHandler{}))
	}
	opts = append(opts, server.WithHttpHandler("/debug", app.PProfHandler()))
	if len(opts) == 0 {
		return nil
	}
	var srv *server.APIServer
	if srv, err = server.NewAPIServer(opts...); err == nil {
		err = f(srv)
	}
	return err
}
