package printer

import (
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"

	"github.com/H-BF/corlib/logger"
	"go.uber.org/zap"
)

type Option func(*printerImpl)

func WithLogger(log logger.TypeOfLogger) Option {
	return func(p *printerImpl) {
		p.log = log
	}
}

func WithJsonFormat() Option {
	return func(p *printerImpl) {
		p.jsonFormat = true
	}
}

type TracePrinter interface {
	Print([]model.FetchTraceModel)
}

type (
	PrinterF    func(msg string, keysAndValues ...interface{})
	printerImpl struct {
		log        logger.TypeOfLogger
		jsonFormat bool
	}
)

func NewTracePrinter(options ...Option) TracePrinter {
	p := &printerImpl{
		log: logger.New(zap.InfoLevel),
	}
	for _, opt := range options {
		opt(p)
	}
	return p
}

func (p printerImpl) Print(traces []model.FetchTraceModel) {
	print := p.log.Infow
	if !p.jsonFormat {
		print = p.log.Infof
	}
	PrintTrace(traces, p.jsonFormat, print, nil)
}

func PrintTrace(traces []model.FetchTraceModel, jsonFormat bool, print PrinterF, callback func(trace model.FetchTraceModel)) {
	cntUniqueTrace := make(map[string]int, len(traces))
	uniqueTrace := make(map[string]model.FetchTraceModel, len(traces))

	for _, trace := range traces {
		key := trace.FiveTuple()
		if jsonFormat {
			key = trace.JsonString()
		}
		cntUniqueTrace[key]++
		uniqueTrace[key] = trace
	}
	for k, v := range cntUniqueTrace {
		if !jsonFormat {
			print("[%s] %s cnt=%d\n", uniqueTrace[k].Timestamp, k, v)
		} else {
			print("", "trace", uniqueTrace[k], "cnt", v)
		}
		if callback != nil {
			callback(uniqueTrace[k])
		}
	}
}
