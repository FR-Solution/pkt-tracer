package grpc_client

import (
	"sync"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
)

var (
	grpcClientMetricInst *grpc_prometheus.ClientMetrics
	once                 sync.Once
)

func GRPCClientMetrics() *grpc_prometheus.ClientMetrics {
	once.Do(func() {
		grpcClientMetricInst = grpc_prometheus.NewClientMetrics()
	})

	return grpcClientMetricInst
}
