package ratelimit

import (
	"context"
	"testing"
	"time"
)

type mockRedisClient struct{}

func TestSlidingWindowLimiter_Creation(t *testing.T) {
	l := NewSlidingWindowLimiter(nil, 60, time.Minute)
	if l == nil {
		t.Fatal("NewSlidingWindowLimiter() returned nil")
	}
	if l.limit != 60 {
		t.Errorf("limit = %d, want 60", l.limit)
	}
	if l.window != time.Minute {
		t.Errorf("window = %v, want 1m", l.window)
	}
}

func TestSlidingWindowLimiter_NilClient(t *testing.T) {
	l := NewSlidingWindowLimiter(nil, 10, time.Second)
	_, err := l.Allow(context.Background(), "test-key")
	if err == nil {
		t.Error("Allow() with nil client should return error")
	}
}
