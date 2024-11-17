package nftrace

import (
	"context"
	"sync"

	thAPI "github.com/wildberries-tech/pkt-tracer/internal/api/tracehub"
	"github.com/wildberries-tech/pkt-tracer/internal/dto"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	proto "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
)

type (
	THClient = thAPI.ClosableClient
)

type (
	// CountTraceEvent -
	CountTraceEvent struct {
		Cnt int
		observer.EventType
	}

	TraceSender interface {
		Run(ctx context.Context) (err error)
		Close() error
	}

	mergedTracesSource interface {
		Reader() <-chan model.TraceModel
	}

	traceSendImpl struct {
		agentSubject observer.Subject
		client       THClient
		traceSourse  mergedTracesSource
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}
)

var _ TraceSender = (*traceSendImpl)(nil)

func NewTraceSend(cl THClient, m mergedTracesSource, subj observer.Subject) TraceSender {
	return &traceSendImpl{
		agentSubject: subj,
		client:       cl,
		traceSourse:  m,
		stop:         make(chan struct{}),
	}
}

func (t *traceSendImpl) Run(ctx context.Context) (err error) {
	var doRun bool
	t.onceRun.Do(func() {
		doRun = true
		t.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrSend{Err: errors.New("it has been run or closed yet")}
	}
	var streamer *traceSendStream
	log := logger.FromContext(ctx).Named("trace-sender")
	log.Info("start")
	defer func() {
		if streamer != nil {
			if _, e := streamer.stream.CloseAndRecv(); e != nil {
				log.Warnf("on closing 'trace-send' stream: %v", e)
			}
		}
		log.Info("stop")
		close(t.stopped)
	}()

	streamer, err = t.newStreamer(ctx)
	if err != nil {
		return ErrSend{Err: errors.WithMessage(err, "on create 'trace-send' stream")}
	}

	for que := t.traceSourse.Reader(); err == nil; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			err = ctx.Err()
		case <-t.stop:
			log.Info("will exit cause it has closed")
			return nil
		case trace, ok := <-que:
			if !ok {
				log.Info("failed to read merged trace from queue")
				err = ErrSend{Err: errors.New("failed to read merged trace from queue")}
			} else {
				e := streamer.sendTraceMsg(trace)
				if e != nil {
					err = ErrSend{Err: e}
				} else {
					t.agentSubject.Notify(CountTraceEvent{Cnt: 1})
				}
			}
		}
	}
	return err
}

// Close sender
func (t *traceSendImpl) Close() error {
	t.onceClose.Do(func() {
		close(t.stop)
		t.onceRun.Do(func() {})
		if t.stopped != nil {
			<-t.stopped
		}
	})
	return nil
}

func (t *traceSendImpl) newStreamer(ctx context.Context) (*traceSendStream, error) {
	s, err := t.client.TraceStream(ctx)
	if err != nil {
		return nil, err
	}
	return &traceSendStream{
		stream: s,
	}, nil
}

type traceSendStream struct {
	stream interface {
		Send(*proto.Traces) error
		CloseAndRecv() (*empty.Empty, error)
		Context() context.Context
	}
}

func (ts *traceSendStream) sendTraceMsg(m model.TraceModel) error {
	var (
		obj      proto.Traces
		dtoTrace dto.TraceDTO
	)
	dtoTrace.InitFromModel(&m)
	obj.Traces = append(obj.Traces, dtoTrace.ToProto())
	return ts.stream.Send(&obj)
}
