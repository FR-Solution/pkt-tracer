package sgroups

import (
	"context"

	grpc_client "github.com/wildberries-tech/pkt-tracer/internal/grpc-client"
	sg "github.com/wildberries-tech/sgroups/v2/pkg/api/sgroups"

	grpcClient "github.com/H-BF/corlib/client/grpc"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type (
	// Client SecGrpups server client
	Client struct {
		sg.SecGroupServiceClient
	}

	// ClosableClient SecGrpups server client
	ClosableClient struct {
		sg.SecGroupServiceClient
		grpcClient.Closable
	}
)

// NewClient constructs 'sgroups' API Client
func NewClient(c grpc.ClientConnInterface) Client {
	return Client{
		SecGroupServiceClient: sg.NewSecGroupServiceClient(
			grpcClient.WithErrorWrapper(c, "sgroups"),
		),
	}
}

// NewClosableClient constructs closable 'sgroups' API Client
func NewClosableClient(ctx context.Context, p grpc_client.ConnProvider) (ClosableClient, error) {
	const api = "sgroups/new-closable-client"

	c, err := p.New(ctx)
	if err != nil {
		return ClosableClient{}, errors.WithMessage(err, api)
	}
	closable := grpcClient.MakeCloseable(
		grpcClient.WithErrorWrapper(c, "sgroups"),
	)
	return ClosableClient{
		SecGroupServiceClient: sg.NewSecGroupServiceClient(closable),
		Closable:              closable,
	}, nil
}
