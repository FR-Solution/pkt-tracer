package pkttracer

import (
	"context"
	"time"

	sgAPI "github.com/wildberries-tech/pkt-tracer/internal/api/sgroups"
	"github.com/wildberries-tech/pkt-tracer/internal/config"
	grpc_client "github.com/wildberries-tech/pkt-tracer/internal/grpc-client"

	"github.com/pkg/errors"
)

// SGClient is an alias to 'sgAPI.ClosableClient'
type SGClient = sgAPI.ClosableClient

// NewSGClient makes 'sgroups' API client
func NewSGClient(ctx context.Context) (*SGClient, error) {
	const api = "NewSGClient"

	addr, err := SGroupsAddress.Value(ctx)
	if err != nil {
		return nil, errors.WithMessage(err, api)
	}
	var dialDuration time.Duration
	dialDuration, err = SGroupsDialDuration.Value(ctx)
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
	var c SGClient
	if c, err = sgAPI.NewClosableClient(ctx, bld); err != nil {
		return nil, err
	}
	return &c, err
}
