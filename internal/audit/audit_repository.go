package audit

import (
	"context"

	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
)

type AuditEventRepository interface {
	RecordEvent(ctx context.Context, event *model.AuditEvent) error
}

type auditEventRepository struct {
	query *query.Query
}

func (r *auditEventRepository) RecordEvent(ctx context.Context, event *model.AuditEvent) error {
	return nil
}

func NewAuditEventRepository(query *query.Query) AuditEventRepository {
	return &auditEventRepository{
		query: query,
	}
}
