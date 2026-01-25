package audit

import (
	"context"
	"time"

	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
)

type AuditLogRepository interface {
	RecordEvent(ctx context.Context, event *model.AuditEvent) error
	GetEventsByUserID(ctx context.Context, userID uint, cursorMs uint64) ([]*model.AuditEvent, bool, error)
}

type auditLogRepository struct {
	query *query.Query
}

func (r *auditLogRepository) RecordEvent(ctx context.Context, event *model.AuditEvent) error {
	return r.query.AuditEvent.WithContext(ctx).Create(event)
}

func (r *auditLogRepository) GetEventsByUserID(ctx context.Context, userID uint, cursorMs uint64) ([]*model.AuditEvent, bool, error) {
	const pageSize = 20

	q := r.query.AuditEvent.WithContext(ctx).
		Where(r.query.AuditEvent.UserID.Eq(userID))

	if cursorMs != 0 {
		q = q.Where(r.query.AuditEvent.CreatedAt.Lt(time.UnixMilli(int64(cursorMs))))
	}

	events, err := q.
		Order(r.query.AuditEvent.CreatedAt.Desc()).
		Limit(pageSize + 1).
		Find()
	if err != nil {
		return nil, false, err
	}

	hasMore := len(events) > pageSize
	if hasMore {
		events = events[:pageSize]
	}

	return events, hasMore, nil
}

func NewAuditLogRepository(query *query.Query) AuditLogRepository {
	return &auditLogRepository{
		query: query,
	}
}
