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
	IP               string    `mapstructure:"ip,omitempty"                   redis:"ip"`                 // client ip address
	UserID           uint      `mapstructure:"user_id,omitempty"              redis:"user_id"`            // user id
	OAuthID          uint      `mapstructure:"oauth_id,omitempty"             redis:"oauth_id"`           // user oauth id
	LastSeen         time.Time `mapstructure:"last_seen,omitempty"            redis:"last_seen"`          // last request time
	LoginTime        time.Time `mapstructure:"login_time,omitempty"           redis:"login_time"`         // last login time
	TwoFARequired    bool      `mapstructure:"twofa_required,omitempty"       redis:"twofa_required"`     // is 2fa required
	TwoFAChallengeID string    `mapstructure:"twofa_challenge_id,omitempty"   redis:"twofa_challenge_id"` // 2fa challenge id
	TwoFASuccessAt   time.Time `mapstructure:"twofa_success_at,omitempty"     redis:"twofa_success_at"`   // 2fa success time
	SecretKey        string    `mapstructure:"secret_key,omitempty"           redis:"secret_key"`         // session secret key
	ExpireTime       time.Time `mapstructure:"expire_time,omitempty"          redis:"expire_time"`        // session expire time
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

func (s *Session) GetData(ctx context.Context, val any) error {
	return s.storage.Get(ctx, s.id, val)
}

func (s *Session) SetData(ctx context.Context, val any) error {
	if info, ok := val.(SessionData); ok {
		s.SessionData = info
	}
	return s.storage.Save(ctx, s.id, val)
}

func (s *Session) SetField(ctx context.Context, field string, val any, exp ...time.Duration) error {
	return s.storage.SetAttr(ctx, s.id, field, val, exp...)
}

func (s *Session) GetField(ctx context.Context, field string, val any) error {
	return s.storage.GetAttr(ctx, s.id, field, val)
}

func (s *Session) IncrField(ctx context.Context, field string, delta int64) (int64, error) {
	return s.storage.IncrAttr(ctx, s.id, field, delta)
}

func (s *Session) DeleteField(ctx context.Context, field string) error {
	return s.storage.DelAttr(ctx, s.id, field)
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
	return s.storage.Save(ctx, s.id, s.SessionData)
}
