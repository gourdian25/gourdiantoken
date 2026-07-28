// File: logger_test.go

package gourdiantoken

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNopLogger proves the no-op implementation never panics.
func TestNopLogger(t *testing.T) {
	l := NopLogger()
	l.Debug("noop")
	l.Info("noop")
	l.Warn("noop")
	l.Error("noop")
}

// recordingLogger is safe for concurrent use: cleanupRotatedTokens/cleanupRevokedTokens run
// as separate goroutines and may both call Error concurrently.
type recordingLogger struct {
	mu     sync.Mutex
	errors []string
}

func (r *recordingLogger) Debug(string, ...any) {}
func (r *recordingLogger) Info(string, ...any)  {}
func (r *recordingLogger) Warn(string, ...any)  {}
func (r *recordingLogger) Error(msg string, _ ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, msg)
}

func TestOrNop(t *testing.T) {
	rec := &recordingLogger{}
	assert.Equal(t, Logger(rec), OrNop(rec))
	assert.Equal(t, NopLogger(), OrNop(nil))
}

func TestNewGourdianTokenMaker_AppliesStructuredLoggerOption(t *testing.T) {
	rec := &recordingLogger{}
	config := DefaultTestConfig()
	maker, err := NewGourdianTokenMaker(context.Background(), config, nil, WithStructuredLogger(rec))
	require.NoError(t, err)

	jwtMaker := maker.(*JWTMaker)
	assert.Equal(t, Logger(rec), jwtMaker.structuredLogger)
}

func TestNewGourdianTokenMaker_StructuredLoggerNilIsNoop(t *testing.T) {
	config := DefaultTestConfig()
	maker, err := NewGourdianTokenMaker(context.Background(), config, nil, WithStructuredLogger(nil))
	require.NoError(t, err)

	jwtMaker := maker.(*JWTMaker)
	assert.Nil(t, jwtMaker.structuredLogger)
}
