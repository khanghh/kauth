package store

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestXxx(t *testing.T) {
	rdb := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    []string{"localhost:6379"},
		DB:       0,
		Username: "default",
		Password: "123456",
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		panic(err)
	}
	storage := &RedisStorage{rdb: rdb}
	data := map[string]any{
		"field1": "value1",
		"field2": 42,
		"field3": time.Now().UnixMilli(),
	}

	err := storage.Set(context.Background(), "aaaa", data, time.Minute)
	if err != nil {
		panic(err)
	}
}
