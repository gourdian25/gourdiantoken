// File: logger.go

package gourdiantoken

// Logger is an optional, structured logging interface JWTMaker accepts for
// background cleanup goroutine diagnostics, in addition to (not instead
// of) the printf-style WithLogger/logf hook. Its four methods match
// *slog.Logger's own signatures exactly, so *slog.Logger — including one
// backed by grlog via slog.New(grlog.NewSlogHandler(...)) — satisfies it
// with no adapter, and any other slog-based logger works too.
//
// This is additive: gourdiantoken predates this shape (see WithLogger's own
// doc comment), so the original bare-callback hook is unchanged and
// continues to work exactly as before. When a Logger is configured via
// WithStructuredLogger, it is used instead of logf for the same two
// background-cleanup error reports; when it isn't, logf's existing
// behavior is completely unaffected.
//
// Example:
//
//	import (
//		"log/slog"
//
//		"github.com/gourdian25/grlog"
//	)
//
//	logger := slog.New(grlog.NewSlogHandler(grlog.NewDefaultLogger()))
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(
//		ctx, config, redisClient,
//		gourdiantoken.WithStructuredLogger(logger), // *slog.Logger satisfies Logger directly
//	)
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}

// NopLogger returns a Logger that discards every message. It is the
// default used when no Logger is configured via WithStructuredLogger.
//
// Returns:
//   - Logger: a non-nil, no-op implementation safe to call from any goroutine
func NopLogger() Logger { return noopLogger{} }

// OrNop returns l if it is non-nil, otherwise NopLogger().
//
// Parameters:
//   - l: Logger — may be nil
//
// Returns:
//   - Logger: l unchanged if non-nil, otherwise NopLogger()
func OrNop(l Logger) Logger {
	if l == nil {
		return NopLogger()
	}
	return l
}

// WithStructuredLogger sets a structured Logger for background cleanup
// goroutine diagnostics. When set, it is used instead of the printf-style
// logf hook (see WithLogger) for the same two error reports; passing nil
// is a no-op and leaves logf as the reporting path.
func WithStructuredLogger(logger Logger) Option {
	return func(maker *JWTMaker) {
		if logger != nil {
			maker.structuredLogger = logger
		}
	}
}
