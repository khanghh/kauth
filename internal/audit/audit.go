package audit

import (
	"context"
	"sync"

	"github.com/khanghh/kauth/model"
)

var auditRepo AuditEventRepository
var initOnce sync.Once

func Initialize(repo AuditEventRepository) {
	initOnce.Do(func() {
		auditRepo = repo
	})
}

const (
	EventTypeLoginSuccess           = "login_success"
	EventTypeLoginFailure           = "login_failure"
	EventTypeServiceAuthorized      = "service_authorized"
	EventTypeTwoFAChallengeCreated  = "2fa_challenge_created"
	EventTypeTwoFAChallengeVerified = "2fa_challenge_verified"
	EventTypeTwoFAChallengeFailed   = "2fa_challenge_failed"
	EventTypeTwoFAAttemptSuccess    = "2fa_attempt_success"
	EventTypeTwoFAAttemptFailure    = "2fa_attempt_failure"
)

const (
	TwoFAStateCreated uint = iota
	TwoFAStateVerified
	TwoFAStateFailed
)

type LoginRecord struct {
	UserID    uint
	Username  string
	Method    string
	IP        string
	UserAgent string
	Success   bool
	Reason    string
}

type ServiceAuthorizedRecord struct {
	UserID      uint
	Username    string
	ServiceID   uint
	ServiceName string
	IP          string
	UserAgent   string
}

type TwoFAChallengeRecord struct {
	UserID     uint
	Username   string
	TwoFAState uint
	IP         string
	UserAgent  string
	Reason     string
}

type TwoFAChallengeAttemptRecord struct {
	UserID    uint
	Username  string
	Success   bool
	IP        string
	UserAgent string
	Reason    string
}

func RecordLogin(ctx context.Context, record LoginRecord) error {
	loginEventType := EventTypeLoginFailure
	if record.Success {
		loginEventType = EventTypeLoginSuccess
	}
	return auditRepo.RecordEvent(ctx, &model.AuditEvent{
		UserID:     record.UserID,
		Username:   record.Username,
		EventType:  loginEventType,
		AuthMethod: record.Method,
		IP:         record.IP,
		UserAgent:  record.UserAgent,
		Reason:     record.Reason,
	})
}

func RecordServiceAuthorized(ctx context.Context, record ServiceAuthorizedRecord) error {
	return auditRepo.RecordEvent(ctx, &model.AuditEvent{
		UserID:    record.UserID,
		Username:  record.Username,
		EventType: EventTypeServiceAuthorized,
		IP:        record.IP,
		UserAgent: record.UserAgent,
	})
}

func RecordTwoFAChallenge(ctx context.Context, record TwoFAChallengeRecord) error {
	var eventType string
	switch record.TwoFAState {
	case TwoFAStateVerified:
		eventType = EventTypeTwoFAChallengeVerified
	case TwoFAStateFailed:
		eventType = EventTypeTwoFAChallengeFailed
	default:
		eventType = EventTypeTwoFAChallengeCreated
	}
	return auditRepo.RecordEvent(ctx, &model.AuditEvent{
		UserID:    record.UserID,
		Username:  record.Username,
		EventType: eventType,
		IP:        record.IP,
		UserAgent: record.UserAgent,
		Reason:    record.Reason,
	})
}

func Record2FAChallengeAttempt(ctx context.Context, record TwoFAChallengeAttemptRecord) error {
	eventType := EventTypeTwoFAAttemptFailure
	if record.Success {
		eventType = EventTypeTwoFAAttemptSuccess
	}
	return auditRepo.RecordEvent(ctx, &model.AuditEvent{
		UserID:    record.UserID,
		Username:  record.Username,
		EventType: eventType,
		IP:        record.IP,
		UserAgent: record.UserAgent,
		Reason:    record.Reason,
	})
}
