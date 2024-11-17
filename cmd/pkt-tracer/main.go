package main

import (
	"context"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/app"
	. "github.com/wildberries-tech/pkt-tracer/internal/app/pkt-tracer" //nolint:revive
	"github.com/wildberries-tech/pkt-tracer/internal/config"
	iftrace "github.com/wildberries-tech/pkt-tracer/internal/iface"
	"github.com/wildberries-tech/pkt-tracer/internal/nfrule"
	"github.com/wildberries-tech/pkt-tracer/internal/nftmonitor"
	"github.com/wildberries-tech/pkt-tracer/internal/nftrace"
	"github.com/wildberries-tech/pkt-tracer/internal/nl"
	sgnw "github.com/wildberries-tech/pkt-tracer/internal/providers/sg-network"

	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/H-BF/corlib/pkg/parallel"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/server"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func main() {
	SetupContext()
	SetupAgentSubject()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")

	err := config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "PT"},
		config.WithSourceFile{FileName: ConfigFile},

		config.WithDefValue{Key: AppLoggerLevel, Val: "DEBUG"},
		config.WithDefValue{Key: AppGracefulShutdown, Val: 10 * time.Second},
		config.WithDefValue{Key: ServicesDefDialDuration, Val: 30 * time.Second},
		config.WithDefValue{Key: TrAddress, Val: "tcp://127.0.0.1:9000"},
		config.WithDefValue{Key: UseCompression, Val: false},
		config.WithDefValue{Key: TableSyncInterval, Val: "3s"},
		config.WithDefValue{Key: SGroupsAddress, Val: "tcp://127.0.0.1:9001"},
		config.WithDefValue{Key: SGroupsSyncStatusInterval, Val: "10s"},
		config.WithDefValue{Key: SGroupsSyncStatusPush, Val: false},

		//telemetry group
		config.WithDefValue{Key: TelemetryEndpoint, Val: "127.0.0.1:5000"},
		config.WithDefValue{Key: MetricsEnable, Val: true},
		config.WithDefValue{Key: HealthcheckEnable, Val: true},
		config.WithDefValue{Key: UserAgent, Val: "tracer0"},
	)
	if err != nil {
		logger.Fatal(ctx, err)
	}
	if err = SetupLogger(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}

	if err = SetupMetrics(ctx); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup metrics"))
	}

	err = WhenSetupTelemtryServer(ctx, func(srv *server.APIServer) error {
		addr := TelemetryEndpoint.MustValue(ctx)
		ep, e := pkgNet.ParseEndpoint(addr)
		if e != nil {
			return errors.WithMessagef(e, "parse telemetry endpoint (%s): %v", addr, e)
		}
		go func() { //start telemetry endpoint
			if e1 := srv.Run(ctx, ep); e1 != nil {
				logger.Fatalf(ctx, "telemetry server is failed: %v", e1)
			}
		}()
		return nil
	})
	if err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup telemetry server"))
	}

	AgentSubject().ObserversAttach(
		observer.NewObserver(agentMetricsObserver, false,
			nftrace.CountTraceEvent{},
			iftrace.CountIfaceNlErrMemEvent{},
			nfrule.CountRulerNlErrMemEvent{},
			nftrace.CountCollectNlErrMemEvent{},
		),
	)

	gracefulDuration := AppGracefulShutdown.MustValue(ctx)
	errc := make(chan error, 1)

	go func() {
		defer close(errc)
		errc <- runJobs(ctx)
	}()
	var jobErr error

	select {
	case <-ctx.Done():
		if gracefulDuration >= time.Second {
			logger.Infof(ctx, "%s in shutdowning...", gracefulDuration)
			_ = gs.ForDuration(gracefulDuration).Run(
				gs.Chan(errc).Consume(
					func(_ context.Context, err error) {
						jobErr = err
					},
				),
			)
		}
	case jobErr = <-errc:
	}

	if jobErr != nil {
		logger.Fatal(ctx, jobErr)
	}

	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}

func agentMetricsObserver(ev observer.EventType) {
	if metrics := GetAgentMetrics(); metrics != nil {
		switch o := ev.(type) {
		case nftrace.CountTraceEvent:
			metrics.ObserveTracesCounter(o.Cnt)
		case iftrace.CountIfaceNlErrMemEvent:
			metrics.ObserveErrNlMemCounter(ESrcIface)
		case nfrule.CountRulerNlErrMemEvent:
			metrics.ObserveErrNlMemCounter(ESrcRuler)
		case nftrace.CountCollectNlErrMemEvent:
			metrics.ObserveErrNlMemCounter(ESrcCollector)
		}
	}
}

type mainJob struct {
	thClient    *THClient
	sgClient    *SGClient
	sgCollector sgnw.SGCollector
	ifTracer    iftrace.Iface
	nlWatcher   nl.NetlinkWatcher
	nfruler     nfrule.RuleTracer
	tblWatcher  nftmonitor.TableWatcher
	trCollect   nftrace.TraceCollector
	trSender    nftrace.TraceSender
	trMerge     nftrace.TraceMerger
}

func (m *mainJob) cleanup() {
	if m.thClient != nil {
		_ = m.thClient.CloseConn()
	}

	if m.sgClient != nil {
		_ = m.sgClient.CloseConn()
	}

	if m.sgCollector != nil {
		_ = m.sgCollector.Close()
	}

	if m.ifTracer != nil {
		_ = m.ifTracer.Close()
	}
	if m.nlWatcher != nil {
		_ = m.nlWatcher.Close()
	}
	if m.nfruler != nil {
		_ = m.nfruler.Close()
	}
	if m.tblWatcher != nil {
		_ = m.tblWatcher.Close()
	}
	if m.trCollect != nil {
		_ = m.trCollect.Close()
	}
	if m.trSender != nil {
		_ = m.trSender.Close()
	}
	if m.trMerge != nil {
		_ = m.trMerge.Close()
	}
}

func (m *mainJob) init(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			m.cleanup()
		}
	}()

	as := AgentSubject()

	if m.thClient, err = NewTHClient(ctx); err != nil {
		return err
	}

	if m.sgClient, err = NewSGClient(ctx); err != nil {
		return err
	}

	if m.sgCollector, err = sgnw.NewSgCollector(
		ctx,
		*m.sgClient,
		SGroupsSyncStatusInterval.MustValue(ctx),
		SGroupsSyncStatusPush.MustValue(ctx)); err != nil {
		return err
	}

	m.ifTracer = iftrace.NewIface(as)

	if m.nlWatcher, err = nl.NewNetlinkWatcher(2, unix.NETLINK_NETFILTER,
		nl.SkWithBufLen(nl.SockBufLen16MB),
		nl.SkWithNlMs(unix.NFNLGRP_NFTABLES),
	); err != nil {
		return err
	}

	nlWatchers := map[string]nl.NlReader{
		"rule-watcher":  m.nlWatcher.Reader(0),
		"table-watcher": m.nlWatcher.Reader(1),
	}

	m.nfruler = nfrule.NewRuleTrace(nfrule.Deps{
		AgentSubject: as,
		NlWatcher:    nlWatchers["rule-watcher"],
	})
	tblCli, err := m.thClient.SyncNftTables(ctx)
	if err != nil {
		return err
	}
	m.tblWatcher = nftmonitor.NewTableWatcher(nftmonitor.Deps{
		Client:       tblCli,
		AgentSubject: as,
		NlWatcher:    nlWatchers["table-watcher"],
	},
		TableSyncInterval.MustValue(ctx),
	)

	if m.trCollect, err = nftrace.NewCollector(as); err != nil {
		return err
	}

	m.trMerge = nftrace.NewTraceMerge(m.trCollect, m.ifTracer, m.nfruler, m.sgCollector)

	m.trSender = nftrace.NewTraceSend(*m.thClient, m.trMerge, AgentSubject())

	return nil
}

func (m *mainJob) run(ctx context.Context) error {
	defer m.cleanup()
	ctx1, cancel := context.WithCancel(ctx)
	defer cancel()
	ff := [...]func() error{
		func() error {
			return m.ifTracer.Run(ctx1)
		},
		func() error {
			return m.nfruler.Run(ctx1)
		},
		func() error {
			return m.tblWatcher.Run(ctx1)
		},
		func() error {
			return m.trCollect.Run(ctx1)
		},
		func() error {
			return m.sgCollector.Run(ctx1)
		},
		func() error {
			return m.trMerge.Run(ctx1)
		},
		func() error {
			return m.trSender.Run(ctx1)
		},
	}
	errs := make([]error, len(ff))
	_ = parallel.ExecAbstract(len(ff), int32(len(ff))-1, func(i int) error {
		defer cancel()
		errs[i] = ff[i]()
		return nil
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return multierr.Combine(errs...)
}

func runJobs(ctx context.Context) (err error) {
	defer func() {
		app.SetHealthState(false)
	}()

	var jb mainJob
	if err = jb.init(ctx); err != nil {
		return err
	}
	app.SetHealthState(true)
	if err = jb.run(ctx); err != nil {
		return err
	}

	return err
}
