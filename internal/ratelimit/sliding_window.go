package ratelimit

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// SlidingWindowLimiter implements a sliding window rate limiter using a Redis sorted set.
type SlidingWindowLimiter struct {
	client *redis.Client
	limit  int64
	window time.Duration
}

// NewSlidingWindowLimiter creates a new rate limiter with the given Redis client, limit, and window.
func NewSlidingWindowLimiter(client *redis.Client, limit int64, window time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		client: client,
		limit:  limit,
		window: window,
	}
}

// Allow checks whether the given key is allowed to proceed under the rate limit.
//
// It returns (true, nil) if allowed, (false, nil) if rate limited (never returns error for limit exceeded).
func (l *SlidingWindowLimiter) Allow(ctx context.Context, key string) (bool, error) {
	now := time.Now().UnixMilli()
	windowMillis := l.window.Milliseconds()
	score := float64(now)
	key = "fw:rl:" + key

	pipe := l.client.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: strconv.FormatInt(now, 10)})
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(now-windowMillis, 10))
	pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, l.window*2)
	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}

	zcardCmd := cmders[2].(*redis.IntCmd)
	count, err := zcardCmd.Result()
	if err != nil {
		return false, err
	}

	if count > l.limit {
		return false, nil
	}
	return true, nil
}
