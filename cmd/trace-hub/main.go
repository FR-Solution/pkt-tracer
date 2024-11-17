package main

import (
	"github.com/wildberries-tech/pkt-tracer/internal/api/tracehub"
	"github.com/wildberries-tech/pkt-tracer/internal/app"
	. "github.com/wildberries-tech/pkt-tracer/internal/app/trace-hub" //nolint:revive
	"github.com/wildberries-tech/pkt-tracer/internal/config"
	"github.com/wildberries-tech/pkt-tracer/internal/registry"

	_ "github.com/H-BF/corlib/app/identity"
	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/server"
	"github.com/pkg/errors"
	_ "go.uber.org/automaxprocs"
	"go.uber.org/zap"
)

func main() {
	SetupContext()
	SetupSubject()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")
	err := config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "TH"},
		config.WithSourceFile{FileName: ConfigFile},
		config.WithDefValue{Key: AppLoggerLevel, Val: "DEBUG"},
		config.WithDefValue{Key: MetricsEnable, Val: true},
		config.WithDefValue{Key: HealthcheckEnable, Val: true},
		config.WithDefValue{Key: ServerGracefulShutdown, Val: "10s"},
		config.WithDefValue{Key: ServerEndpoint, Val: "tcp://127.0.0.1:9000"},
		config.WithDefValue{Key: StorageType, Val: "clickhouse"},
		config.WithDefValue{Key: ClickHouseDSN, Val: "tcp://localhost:19000/swarm?max_execution_time=60&dial_timeout=10s&client_info_product=trace-hub/0.0.1&compress=lz4&block_buffer_size=10&max_compression_buffer=10240&skip_verify=true"},
		config.WithDefValue{Key: ClickMaxRowsInBatch, Val: 10000},
		config.WithDefValue{Key: ClickFlushTimeInterval, Val: "5s"},
		config.WithDefValue{Key: ClickCheckTimeInterval, Val: "3s"},
	)
	if err != nil {
		logger.Fatal(ctx, err)
	}
	if err = SetupLogger(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "when setup logger"))
	}
	if err = SetupMetrics(ctx); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup metrics"))
	}

	ServerSubject().ObserversAttach(
		observer.NewObserver(serverMetricsObserver, false,
			tracehub.CountTraceEvent{}, registry.CountDBWriteEvent{}),
	)

	var ep *pkgNet.Endpoint
	_, err = ServerEndpoint.Value(ctx, ServerEndpoint.OptSink(func(v string) error {
		var e error
		if ep, e = pkgNet.ParseEndpoint(v); e != nil {
			logger.Fatalf(ctx, "parse server endpoint (%s): %v", v, err)
		}
		return nil
	}))
	if err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "server endpoint is absent"))
	}
	if err = SetupRegistry(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "on opening db storade"))
	}
	var srv *server.APIServer
	if srv, err = SetupTraceHubServer(ctx); err != nil {
		logger.Fatalf(ctx, "setup server: %v", err)
	}
	gracefulDuration, _ := ServerGracefulShutdown.Value(ctx)
	app.SetHealthState(true)
	if err = srv.Run(ctx, ep, server.RunWithGracefulStop(gracefulDuration)); err != nil {
		logger.Fatalf(ctx, "run server: %v", err)
	}
	app.SetHealthState(false)
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}

func serverMetricsObserver(ev observer.EventType) {
	if metrics := GetMetrics(); metrics != nil {
		switch o := ev.(type) {
		case tracehub.CountTraceEvent:
			metrics.ObserveTracesCounter()
		case registry.CountDBWriteEvent:
			metrics.ObserveDBWriteCounter(o.Cnt)
		}
	}
}
