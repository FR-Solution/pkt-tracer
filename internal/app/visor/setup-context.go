package visor

import (
	"context"

	"github.com/wildberries-tech/pkt-tracer/internal/app"

	"github.com/H-BF/corlib/pkg/signals"
)

// SetupContext setup app ctx
func SetupContext() {
	ctx, cancel := context.WithCancel(context.Background())
	signals.WhenSignalExit(func() error {
		cancel()
		return nil
	})
	app.SetContext(ctx)
}
