package visor

import (
	"io"
	"os"

	"github.com/wildberries-tech/pkt-tracer/internal/app"

	log "github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(l zapcore.Level, jsonMode bool, options ...zap.Option) {
	if jsonMode {
		log.SetLogger(log.New(l, options...))
		return
	}
	log.SetLogger(NewTextLoggerWithSink(l, os.Stdout, options...))
}

// SetupLogger setup app logger
func SetupLogger(jsonMode bool) error {
	ctx := app.Context()
	_, err := AppLoggerLevel.Value(ctx, AppLoggerLevel.OptSink(func(v string) error {
		var l log.LogLevel
		if e := l.UnmarshalText([]byte(v)); e != nil {
			return errors.Wrapf(e, "recognize '%s' logger level from config", v)
		}
		NewLogger(l, jsonMode)
		return nil
	}))
	return err
}

func NewTextLoggerWithSink(level log.LevelEnabler, sink io.Writer, options ...zap.Option) log.TypeOfLogger {
	conf := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "lvl",
		CallerKey:      "at",
		MessageKey:     "msg",
		StacktraceKey:  "stack",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	if level == zap.DebugLevel {
		conf.NameKey = "log-of"
	}
	return log.TypeOfLogger{
		LevelEnabler: level,
		SugaredLogger: zap.New(
			zapcore.NewCore(
				zapcore.NewConsoleEncoder(conf),
				zapcore.AddSync(sink),
				level,
			),
			options...,
		).Sugar(),
	}
}
