package visor_cli

import (
	"context"

	. "github.com/wildberries-tech/pkt-tracer/internal/app/visor" //nolint:revive
	"github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	"github.com/wildberries-tech/pkt-tracer/internal/nftrace/printer"

	"github.com/H-BF/corlib/logger"
)

type mainJob struct {
	thClient *THClosableClient
	visor    Visor
}

func (m *mainJob) cleanup() {
	if m.thClient != nil {
		m.thClient.CloseConn() //nolint:errcheck
	}
	if m.visor != nil {
		m.visor.Close() //nolint:errcheck
	}
}

func (m *mainJob) init(ctx context.Context, jsonFlag bool) (err error) {
	defer func() {
		if err != nil {
			m.cleanup()
		}
	}()

	if m.thClient, err = NewTHClient(ctx); err != nil {
		return err
	}

	printOpt := append(([]printer.Option)(nil),
		printer.WithLogger(logger.FromContext(ctx).Named("visor")))
	if jsonFlag {
		printOpt = append(printOpt, printer.WithJsonFormat())
	}

	m.visor = NewVisor(
		Deps{
			Client:       THClient{TraceHubServiceClient: m.thClient.TraceHubServiceClient},
			TracePrinter: printer.NewTracePrinter(printOpt...),
		},
	)
	return nil
}

func RunJobs(ctx context.Context, traceScope trace.TraceScopeModel, jsonFlag bool) (err error) {
	var jb mainJob
	if err = jb.init(ctx, jsonFlag); err != nil {
		return err
	}
	return jb.visor.Run(ctx, traceScope)
}
