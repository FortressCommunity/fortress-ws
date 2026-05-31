package logger

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewZapLogger creates a structured JSON zap.Logger with configurable level and output to stderr.
func NewZapLogger(level string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(lvl),
		Encoding:         "json",
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:     "message",
			LevelKey:       "level",
			TimeKey:        "timestamp",
			NameKey:        "logger",
			CallerKey:      "caller",
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
		},
	}
	return cfg.Build()
}

// TracerProvider returns a no-op trace provider.
// In production, replace with an OTLP exporter configured via environment variables.
func TracerProvider() trace.TracerProvider {
	return otel.GetTracerProvider()
}

// StartSpan starts a new span from the global tracer provider with the given name and attributes.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tracer := otel.Tracer("fortress-ws")
	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// AuditLog writes a structured audit log entry via the provided logger.
func AuditLog(logger *zap.Logger, event string, fields ...zap.Field) {
	logger.Info(event, fields...)
}

// FatalExit logs a fatal message and exits with code 1.
func FatalExit(logger *zap.Logger, msg string, err error) {
	logger.Fatal(msg, zap.Error(err))
	os.Exit(1)
}
