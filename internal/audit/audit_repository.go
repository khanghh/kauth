package audit

import (
	"context"

	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
)

type AuditLogRepository interface {
	RecordEvent(ctx context.Context, event *model.AuditEvent) error
}

type auditLogRepository struct {
	query *query.Query
}

func (r *auditLogRepository) RecordEvent(ctx context.Context, event *model.AuditEvent) error {
	return r.query.AuditEvent.Create(event)
}

func NewAuditLogRepository(query *query.Query) AuditLogRepository {
	return &auditLogRepository{
		query: query,
	}
}
