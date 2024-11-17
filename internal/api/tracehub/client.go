package tracehub

import (
	"context"

	grpc_client "github.com/wildberries-tech/pkt-tracer/internal/grpc-client"
	th "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	grpcClient "github.com/H-BF/corlib/client/grpc"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type (
	// Client TraceHubService server client
	Client struct {
		th.TraceHubServiceClient
	}

	// ClosableClient TraceHubService server client
	ClosableClient struct {
		th.TraceHubServiceClient
		grpcClient.Closable
	}
)

// NewClient constructs 'tracehub' API Client
func NewClient(c grpc.ClientConnInterface) Client {
	return Client{
		TraceHubServiceClient: th.NewTraceHubServiceClient(
			grpcClient.WithErrorWrapper(c, "trace-hub"),
		),
	}
}

// NewClosableClient constructs closable 'tracehub' API Client
func NewClosableClient(ctx context.Context, p grpc_client.ConnProvider) (ClosableClient, error) {
	const api = "tracehub/new-closable-client"

	c, err := p.New(ctx)
	if err != nil {
		return ClosableClient{}, errors.WithMessage(err, api)
	}
	closable := grpcClient.MakeCloseable(
		grpcClient.WithErrorWrapper(c, "tracehub"),
	)
	return ClosableClient{
		TraceHubServiceClient: th.NewTraceHubServiceClient(closable),
		Closable:              closable,
	}, nil
}
