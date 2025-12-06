package audit

import (
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/model"
)

var auditRepo AuditLogRepository
var initOnce sync.Once

func Initialize(repo AuditLogRepository) {
	initOnce.Do(func() {
		auditRepo = repo
	})
}

const (
	EventTypeLoginSuccess        = "login_success"
	EventTypeLoginFailure        = "login_failure"
	EventTypeUserLogout          = "logout"
	EventTypeServiceAuthorized   = "service_authorized"
	EventType2FAChallengeCreated = "2fa_challenge_created"
	EventType2FAAttemptSuccess   = "2fa_attempt_success"
	EventType2FAAttemptFailure   = "2fa_attempt_failure"
)

const (
	AuthMethodPassword = "password"
	AuthMethodOAuth    = "oauth"
)

func RecordLoginSuccess(ctx *fiber.Ctx, user *model.User, method string) error {
	return auditRepo.RecordEvent(ctx.Context(), &model.AuditEvent{
		UserID:     user.ID,
		Username:   user.Username,
		EventType:  EventTypeLoginSuccess,
		AuthMethod: method,
		IP:         ctx.IP(),
		UserAgent:  ctx.Get("User-Agent"),
	})
}

func RecordLoginFailure(ctx *fiber.Ctx, user *model.User, method string, reason string) error {
	return auditRepo.RecordEvent(ctx.Context(), &model.AuditEvent{
		UserID:     user.ID,
		Username:   user.Username,
		EventType:  EventTypeLoginFailure,
		AuthMethod: method,
		Reason:     reason,
		IP:         ctx.IP(),
		UserAgent:  ctx.Get("User-Agent"),
	})
}

func RecordUserLogout(ctx *fiber.Ctx, userID uint, username string) error {
	return auditRepo.RecordEvent(ctx.Context(), &model.AuditEvent{
		UserID:    userID,
		Username:  username,
		EventType: EventTypeUserLogout,
		IP:        ctx.IP(),
		UserAgent: ctx.Get("User-Agent"),
	})
}

func RecordServiceAuthorized(ctx *fiber.Ctx, user *model.User, service *model.Service, callbackURL string) error {
	return auditRepo.RecordEvent(ctx.Context(), &model.AuditEvent{
		UserID:      user.ID,
		Username:    user.Username,
		EventType:   EventTypeServiceAuthorized,
		ServiceID:   service.ID,
		ServiceName: service.Name,
		CallbackURL: callbackURL,
		IP:          ctx.IP(),
		UserAgent:   ctx.Get("User-Agent"),
	})
}

func Record2FAChallengeCreated(ctx *fiber.Ctx, user *model.User, cid string, ctype string, callbackURL string) error {
	return auditRepo.RecordEvent(ctx.Context(), &model.AuditEvent{
		UserID:        user.ID,
		Username:      user.Username,
		EventType:     EventType2FAChallengeCreated,
		ChallengeID:   cid,
		ChallengeType: ctype,
		CallbackURL:   callbackURL,
		IP:            ctx.IP(),
		UserAgent:     ctx.Get("User-Agent"),
	})
}

func Record2FAAttemptSuccess(ctx *fiber.Ctx, user *model.User, cid string, ctype string) error {
	return auditRepo.RecordEvent(ctx.Context(), &model.AuditEvent{
		UserID:        user.ID,
		Username:      user.Username,
		EventType:     EventType2FAAttemptSuccess,
		ChallengeID:   cid,
		ChallengeType: ctype,
		IP:            ctx.IP(),
		UserAgent:     ctx.Get("User-Agent"),
	})
}

func Record2FAAttemptFailure(ctx *fiber.Ctx, user *model.User, cid string, ctype string, reason string) error {
	return auditRepo.RecordEvent(ctx.Context(), &model.AuditEvent{
		UserID:        user.ID,
		Username:      user.Username,
		EventType:     EventType2FAAttemptFailure,
		ChallengeID:   cid,
		ChallengeType: ctype,
		Reason:        reason,
		IP:            ctx.IP(),
		UserAgent:     ctx.Get("User-Agent"),
	})
}
