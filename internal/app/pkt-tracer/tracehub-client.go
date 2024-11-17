package pkttracer

import (
	"context"
	"time"

	thAPI "github.com/wildberries-tech/pkt-tracer/internal/api/tracehub"
	"github.com/wildberries-tech/pkt-tracer/internal/config"
	grpc_client "github.com/wildberries-tech/pkt-tracer/internal/grpc-client"

	"github.com/pkg/errors"
	"google.golang.org/grpc/encoding/gzip"
)

// THClient is an alias to 'thAPI.ClosableClient'
type THClient = thAPI.ClosableClient

// NewTHClient makes 'trace-hub' API client
func NewTHClient(ctx context.Context) (*THClient, error) {
	const api = "NewTHClient"

	addr, err := TrAddress.Value(ctx)
	if err != nil {
		return nil, errors.WithMessage(err, api)
	}
	var dialDuration time.Duration
	dialDuration, err = TrDialDuration.Value(ctx)
	if errors.Is(err, config.ErrNotFound) {
		dialDuration, err = ServicesDefDialDuration.Value(ctx)
		if errors.Is(err, config.ErrNotFound) {
			err = nil
		}
	}
	if err != nil {
		return nil, errors.WithMessage(err, api)
	}
	bld := grpc_client.FromAddress(addr).
		WithDialDuration(dialDuration).
		WithUserAgent(UserAgent.MustValue(ctx))

	if uc, _ := UseCompression.Value(ctx); uc {
		bld = bld.WithCompression(gzip.Name)
	}

	var c THClient
	if c, err = thAPI.NewClosableClient(ctx, bld); err != nil {
		return nil, err
	}
	return &c, err
}
