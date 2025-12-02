package store

import (
	"context"
	"time"
)

type prefixedStorage struct {
	underlying Storage
	prefix     string
}

func (p *prefixedStorage) Get(ctx context.Context, key string, val any) error {
	return p.underlying.Get(ctx, p.prefix+key, val)
}

func (p *prefixedStorage) Set(ctx context.Context, key string, val any, expiresIn time.Duration) error {
	return p.underlying.Set(ctx, p.prefix+key, val, expiresIn)
}

func (p *prefixedStorage) Delete(ctx context.Context, key string) error {
	return p.underlying.Delete(ctx, p.prefix+key)
}

func (p *prefixedStorage) Expire(ctx context.Context, key string, expiresAt time.Time) error {
	return p.underlying.Expire(ctx, p.prefix+key, expiresAt)
}

func (p *prefixedStorage) SetAttr(ctx context.Context, key string, values ...any) error {
	return p.underlying.SetAttr(ctx, p.prefix+key, values...)
}

func (p *prefixedStorage) GetAttr(ctx context.Context, key string, field string, val any) error {
	return p.underlying.GetAttr(ctx, p.prefix+key, field, val)
}

func (p *prefixedStorage) IncrAttr(ctx context.Context, key string, field string, delta int64) (int64, error) {
	return p.underlying.IncrAttr(ctx, p.prefix+key, field, delta)
}

func (p *prefixedStorage) ExpireAttr(ctx context.Context, key string, expires time.Time, fields ...string) error {
	return p.underlying.ExpireAttr(ctx, p.prefix+key, expires, fields...)
}

func StorageWithPrefix(storage Storage, prefix string) Storage {
	return &prefixedStorage{
		underlying: storage,
		prefix:     prefix,
	}
}
