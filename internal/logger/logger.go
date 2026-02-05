// Package logger provides structured logging using zap
package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.SugaredLogger for convenience
type Logger struct {
	*zap.SugaredLogger
	zap *zap.Logger
}

// New creates a new logger instance
func New(level, format string) (*Logger, error) {
	// Parse level
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	// Configure encoder
	var encoderConfig zapcore.EncoderConfig
	var encoder zapcore.Encoder

	if format == "json" {
		encoderConfig = zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "timestamp"
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Create core
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		zapLevel,
	)

	// Create logger
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		SugaredLogger: zapLogger.Sugar(),
		zap:           zapLogger,
	}, nil
}

// NewNop creates a no-op logger for testing
func NewNop() *Logger {
	return &Logger{
		SugaredLogger: zap.NewNop().Sugar(),
		zap:           zap.NewNop(),
	}
}

// Zap returns the underlying zap.Logger
func (l *Logger) Zap() *zap.Logger {
	return l.zap
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.zap.Sync()
}

// With creates a child logger with additional fields
func (l *Logger) With(args ...interface{}) *Logger {
	return &Logger{
		SugaredLogger: l.SugaredLogger.With(args...),
		zap:           l.zap,
	}
}

// Named creates a named child logger
func (l *Logger) Named(name string) *Logger {
	return &Logger{
		SugaredLogger: l.SugaredLogger.Named(name),
		zap:           l.zap.Named(name),
	}
}

// Global logger instance
var globalLogger *Logger

// SetGlobal sets the global logger
func SetGlobal(l *Logger) {
	globalLogger = l
}

// Global returns the global logger
func Global() *Logger {
	if globalLogger == nil {
		globalLogger, _ = New("info", "console")
	}
	return globalLogger
}

// Package-level convenience functions

// Debug logs a debug message
func Debug(msg string, args ...interface{}) {
	Global().Debugw(msg, args...)
}

// Info logs an info message
func Info(msg string, args ...interface{}) {
	Global().Infow(msg, args...)
}

// Warn logs a warning message
func Warn(msg string, args ...interface{}) {
	Global().Warnw(msg, args...)
}

// Error logs an error message
func Error(msg string, args ...interface{}) {
	Global().Errorw(msg, args...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, args ...interface{}) {
	Global().Fatalw(msg, args...)
}
