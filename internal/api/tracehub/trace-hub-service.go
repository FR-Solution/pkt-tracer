package tracehub

import (
	"context"
	"time"

	registry "github.com/wildberries-tech/pkt-tracer/internal/registry"
	th "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/server"
	"google.golang.org/grpc"
)

type thService struct {
	appCtx            context.Context
	reg               registry.Registry
	serverSubject     observer.Subject
	flushTimeInterval time.Duration
	checkDBInterval   time.Duration
	th.UnimplementedTraceHubServiceServer
}

var (
	_ th.TraceHubServiceServer = (*thService)(nil)
	_ server.APIService        = (*thService)(nil)
)

// NewTraceHubeService creates service
func NewTraceHubeService(
	ctx context.Context,
	r registry.Registry,
	subj observer.Subject,
	flushTime time.Duration,
	dbTime time.Duration) server.APIService {
	return &thService{
		appCtx:            ctx,
		reg:               r,
		serverSubject:     subj,
		flushTimeInterval: flushTime,
		checkDBInterval:   dbTime,
	}
}

// Description impl server.APIService
func (srv *thService) Description() grpc.ServiceDesc {
	return th.TraceHubService_ServiceDesc
}

// RegisterGRPC impl server.APIService
func (srv *thService) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	th.RegisterTraceHubServiceServer(s, srv)
	return nil
}
