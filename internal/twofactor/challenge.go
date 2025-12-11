package twofactor

import (
	"context"
	"time"

	"github.com/khanghh/kauth/internal/store"
	"github.com/khanghh/kauth/params"
)

const (
	ChallengeTypeOTP   = "otp"
	ChallengeTypeTOTP  = "totp"
	ChallengeTypeToken = "token"
	ChallengeTypeJWT   = "jwt"
)

type ChallengeStatus string

type Challenge struct {
	ID            string    `redis:"id"`
	Type          string    `redis:"type"`
	Subject       string    `redis:"subject"`
	Secret        string    `redis:"secret"`
	Attempts      int       `redis:"attempts"`
	FinalizeToken string    `redis:"finalize_token"`
	Success       int       `redis:"success"`
	UpdateAt      time.Time `redis:"update_at"`
	VerifiedAt    time.Time `redis:"verified_at"`
	ExpiresAt     time.Time `redis:"expires_at"`
}

func (c *Challenge) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

func (c *Challenge) CanVerify() bool {
	return !c.IsExpired() && c.Attempts < params.TwoFactorChallengeMaxAttempts
}

type challengeStore struct {
	store.Store[Challenge]
}

func (s *challengeStore) IncreaseAttempts(ctx context.Context, cid string) (int, error) {
	attempts, err := s.IncrAttr(ctx, cid, "attempts", 1)
	return int(attempts), err
}

func (s *challengeStore) MarkSuccess(ctx context.Context, cid string) error {
	count, err := s.IncrAttr(ctx, cid, "success", 1)
	if err != nil {
		return err
	}
	if count == 1 {
		s.SetAttr(ctx, cid, "verified_at", time.Now())
		return nil
	}
	return ErrChallengeAlreadyVerified
}

func newChallengeStore(storage store.Storage) *challengeStore {
	return &challengeStore{
		Store: store.New[Challenge](storage, params.ChallengeKeyPrefix),
	}
}
