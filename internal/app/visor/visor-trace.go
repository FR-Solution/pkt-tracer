package visor

import (
	"context"
	"io"
	"sync"
	"time"

	thAPI "github.com/wildberries-tech/pkt-tracer/internal/api/tracehub"
	"github.com/wildberries-tech/pkt-tracer/internal/dto"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	proto "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
)

type (
	THClient = thAPI.Client
)

type (
	Printer interface {
		Print([]model.FetchTraceModel)
	}
	Visor interface {
		Run(context.Context, model.TraceScopeModel) error
		Close() error
	}
	// Deps - dependency
	Deps struct {
		// Adapters
		Client       THClient
		TracePrinter Printer
	}
	visorImpl struct {
		Deps
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

func NewVisor(d Deps) Visor {
	return &visorImpl{
		Deps: d,
		stop: make(chan struct{}),
	}
}

func (v *visorImpl) Run(ctx context.Context, flt model.TraceScopeModel) error {
	var (
		err           error
		dtoTraceScope dto.TraceScopeDTO
		doRun         bool
	)
	v.onceRun.Do(func() {
		doRun = true
		v.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrVisor{Err: ErrVisorRunOrStopped}
	}

	v.stopped = make(chan struct{})
	log := logger.FromContext(ctx).Named("visor")
	log.Debug("start")
	defer func() {
		log.Debug("stop")
		close(v.stopped)
	}()

	dtoTraceScope.InitFromModel(&flt)

	stream, err := v.Client.FetchTraces(ctx, dtoTraceScope.ToProto())

	if err != nil {
		return errors.WithMessage(err, "failed to obtain trace dump stream from server")
	}

	log.Debug("connected to trace-hub server")

	const timtToPrint = time.Second
	timer := time.NewTicker(timtToPrint)
	defer timer.Stop()

	incoming := make(chan any)

	go func() {
		defer close(incoming)
		var e error
		var val any
		for e == nil {
			if val, e = stream.Recv(); e != nil {
				val = e
			}
			select {
			case <-ctx.Done():
				return
			case <-v.stop:
				return
			default:
				select {
				case <-ctx.Done():
					return
				case <-v.stop:
					return
				case incoming <- val:
				}
			}
		}
	}()
	var traces []model.FetchTraceModel
	for err == nil {
		select {
		case <-timer.C:
			v.TracePrinter.Print(traces)
		case val := <-incoming:
			switch t := val.(type) {
			case error:
				err = t
			case *proto.TraceList:
				if len(t.GetTraces()) == 0 { //empty means end of batch
					v.TracePrinter.Print(traces)
					traces = traces[:0]
					break
				}
				for _, tr := range t.GetTraces() {
					var dtoTrace dto.FetchTraceDTO
					dtoTrace.InitFromProto(tr)
					traces = append(traces, *dtoTrace.ToModel())
				}
			}
		case <-ctx.Done():
			err = ctx.Err()
		case <-v.stop:
			err = ErrVisorStopped
		}
	}
	v.TracePrinter.Print(traces) // print tails
	if errors.Is(err, io.EOF) {
		err = nil
		log.Debug("receive completed")
	}
	if errors.Is(err, ErrVisorStopped) {
		err = nil
		log.Debug(ErrVisorStopped)
	}

	return err
}

// Close sender
func (v *visorImpl) Close() error {
	var doStop bool
	v.onceClose.Do(func() {
		close(v.stop)
		v.onceRun.Do(func() {})
		if v.stopped != nil {
			<-v.stopped
		}
		doStop = true
	})
	if !doStop {
		return ErrVisorAlreadyPaused
	}
	return nil
}
