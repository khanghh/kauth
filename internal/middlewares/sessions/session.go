package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/khanghh/kauth/internal/store"
)

type SessionData struct {
	IP                 string    `mapstructure:"ip,omitempty"                   redis:"ip"`                   // client ip address
	UserID             uint      `mapstructure:"user_id,omitempty"              redis:"user_id"`              // user id
	OAuthID            uint      `mapstructure:"oauth_id,omitempty"             redis:"oauth_id"`             // user oauth id
	LastSeen           time.Time `mapstructure:"last_seen,omitempty"            redis:"last_seen"`            // last request time
	LoginTime          time.Time `mapstructure:"login_time,omitempty"           redis:"login_time"`           // last login time
	TwoFARequired      bool      `mapstructure:"two_fa_required,omitempty"      redis:"two_fa_required"`      // is 2fa required
	TwoFAChallengeID   string    `mapstructure:"two_fa_challenge_id,omitempty"  redis:"two_fa_challenge_id"`  // 2fa challenge id
	TwoFASuccessAt     time.Time `mapstructure:"two_fa_success_at,omitempty"    redis:"two_fa_success_at"`    // 2fa success time
	StateEncryptionKey string    `mapstructure:"state_encryption_key,omitempty" redis:"state_encryption_key"` // state encryption key
	ExpireTime         time.Time `mapstructure:"expire_time,omitempty"          redis:"expire_time"`          // session expire time
}

func (s *SessionData) IsLoggedIn() bool {
	return s.UserID != 0
}

func (s *SessionData) Is2FARequired() bool {
	return s.UserID != 0 && s.TwoFARequired
}

func (s *SessionData) IsAuthenticated() bool {
	return s.UserID != 0 && !s.TwoFARequired
}

type Session struct {
	SessionData               // basic session info
	id          string        // session id
	storage     store.Storage // storage backend
	fresh       bool          // is session newly created
}

func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Could not generate session id", "error", err)
		return ""
	}
	return hex.EncodeToString(b)
}

func newSession(storage store.Storage) *Session {
	return &Session{
		id:      generateSessionID(),
		storage: storage,
		fresh:   true,
	}
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) IsFresh() bool {
	return s.fresh
}

func (s *Session) Get(ctx context.Context, val any) error {
	return s.storage.Get(ctx, s.id, val)
}

func (s *Session) Set(ctx context.Context, val any) error {
	if info, ok := val.(SessionData); ok {
		s.SessionData = info
	}
	return s.storage.Save(ctx, s.id, val)
}

func (s *Session) SetAttr(ctx context.Context, key string, val any) error {
	return s.storage.SetAttr(ctx, s.id, key, val)
}

func (s *Session) GetAttr(ctx context.Context, key string, val any) error {
	return s.storage.GetAttr(ctx, s.id, key, val)
}

func (s *Session) Reset(ctx context.Context, val any) error {
	if err := s.storage.Delete(ctx, s.id); err != nil {
		if err != store.ErrNotFound {
			return err
		}
	}

	s.id = generateSessionID()
	s.SessionData = SessionData{}
	if info, ok := val.(SessionData); ok {
		s.SessionData = info
	}
	s.fresh = true
	return nil
}

func (s *Session) Save(ctx context.Context) error {
	return nil
}
