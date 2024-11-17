package tracehub

import (
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/dto"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	"github.com/wildberries-tech/pkt-tracer/internal/registry"
	th "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"
)

func (srv *thService) FetchTraces(msg *th.TraceScope, stream th.TraceHubService_FetchTracesServer) error {
	var dtoTraceScope dto.TraceScopeDTO
	dtoTraceScope.InitFromProto(msg)
	flt := dtoTraceScope.ToModel()
	rd, err := srv.reg.Reader(srv.appCtx)
	if err != nil {
		return err
	}

	if flt.FollowMode {
		return srv.traceWatcher(rd, flt, stream)
	}
	return srv.fetchAndSendTrace(rd, flt, stream)
}

func (srv *thService) traceWatcher(rd registry.Reader, flt *model.TraceScopeModel, stream th.TraceHubService_FetchTracesServer) error {
	var (
		err          error
		checkDBTimer = time.NewTicker(srv.checkDBInterval)
		ctxInc       = stream.Context()
	)
	defer checkDBTimer.Stop()
	for err == nil {
		select {
		case <-srv.appCtx.Done():
			err = srv.appCtx.Err()
		case <-ctxInc.Done():
			err = ctxInc.Err()
		case <-checkDBTimer.C:
			t := time.Now()
			err = srv.fetchAndSendTrace(rd, flt, stream)
			if err != nil {
				break
			}
			flt.Time.From = flt.Time.To
			flt.Time.To = t
		}
	}
	return err
}

func (srv *thService) fetchAndSendTrace(rd registry.Reader, flt *model.TraceScopeModel, stream th.TraceHubService_FetchTracesServer) error {
	traces, err := rd.FetchTraces(srv.appCtx, flt)
	if err != nil {
		return err
	}
	for i, tr := range traces {
		var (
			obj      th.TraceList
			dtoTrace dto.FetchTraceDTO
		)
		dtoTrace.InitFromModel(&tr)
		obj.Traces = append(obj.Traces, dtoTrace.ToProto())
		if err = stream.Send(&obj); err != nil {
			return err
		}

		if i == len(traces)-1 {
			err = stream.Send(&th.TraceList{}) //empty means end of batch
		}
	}
	return err
}
