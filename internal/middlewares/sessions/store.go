package sessions

import (
	"context"
	"time"
)

type Store struct {
	Config
}

func (s *Store) Get(ctx context.Context, id string) (*Session, error) {
	info := SessionData{}
	if err := s.Storage.Get(ctx, id, &info); err != nil {
		return nil, err
	}

	return &Session{
		SessionData: info,
		id:          id,
		storage:     s.Storage,
	}, nil
}

// saveChanges persists the session data to the storage, if session is fresh create with expiration.
func (s *Store) Save(ctx context.Context, sess *Session) error {
	sess.LastSeen = time.Now()
	renew := time.Until(sess.ExpireTime) < (s.SessionMaxAge / 2)
	if sess.fresh || renew {
		sess.ExpireTime = time.Now().Add(s.SessionMaxAge)
		return s.Storage.Set(ctx, sess.id, &sess.SessionData, s.SessionMaxAge)
	} else {
		return s.Storage.Save(ctx, sess.id, &sess.SessionData)
	}
}

func (s *Store) Delete(ctx context.Context, id string) error {
	return s.Storage.Delete(ctx, id)
}
