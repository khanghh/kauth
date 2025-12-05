package web

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/auth"
	"github.com/khanghh/kauth/internal/common"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/urlutil"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

func (h *AuthHandler) getAuthorizedTime(ctx *fiber.Ctx, serviceURL string) time.Time {
	session := sessions.Get(ctx)
	key := "authz:" + common.CalculateHash(session.StateEncryptionKey, serviceURL)
	var miliSec int64
	if err := session.GetAttr(ctx.Context(), key, &miliSec); err == nil {
		return time.UnixMilli(miliSec)
	}
	return time.Time{}
}

func (h *AuthHandler) setAuthorizedTime(ctx *fiber.Ctx, serviceURL string, expiresAt time.Time) {
	session := sessions.Get(ctx)
	key := "authz:" + common.CalculateHash(session.StateEncryptionKey, serviceURL)
	session.SetAttr(ctx.Context(), key, expiresAt.UnixMilli())
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, session *sessions.Session, serviceURL string) error {
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), session.UserID, serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderDeniedErrorPage(ctx)
	} else if err != nil {
		return err
	}
	return redirect(ctx, ticket.CallbackURL, "ticket", ticket.TicketID)
}

func (h *AuthHandler) GetAuthorize(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")
	serviceURL := urlutil.NormalizeURL(ctx.Query("service"))
	if serviceURL == "" {
		return render.RenderNotFoundErrorPage(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceURL)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}
	service, err := h.authorizeService.GetServiceByCallbackURL(ctx.Context(), serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderNotFoundErrorPage(ctx)
	} else if err != nil {
		return err
	}

	authorizeTime := h.getAuthorizedTime(ctx, service.LoginURL)
	challengeRequired := service.ChallengeRequired && time.Since(authorizeTime) > service.ChallengeValidity
	if !challengeRequired && service.AutoLogin {
		return h.handleAuthorizeServiceAccess(ctx, session, serviceURL)
	}
	if challengeRequired && cid != "" {
		sub := getChallengeSubject(ctx, sessions.Get(ctx))
		endpoint := urlutil.AppendQuery("/authorize", "service", serviceURL)
		err = h.twoFactorService.FinalizeChallenge(ctx.Context(), cid, sub, endpoint)
		if err == nil {
			h.setAuthorizedTime(ctx, serviceURL, time.Now())
			return h.handleAuthorizeServiceAccess(ctx, session, serviceURL)
		}
	}

	pageData := render.AuthorizeServicePageData{
		Email:       user.Email,
		ServiceName: service.Name,
		ServiceURL:  service.LoginURL,
	}
	return render.RenderAuthorizeServiceAccessPage(ctx, pageData)
}

func (h *AuthHandler) PostAuthorize(ctx *fiber.Ctx) error {
	serviceURL := urlutil.NormalizeURL(ctx.Query("service"))
	confirm := ctx.FormValue("confirm")

	if serviceURL == "" {
		return render.RenderNotFoundErrorPage(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceURL)
	}

	if confirm != "true" {
		return ctx.Redirect("/")
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	service, err := h.authorizeService.GetServiceByCallbackURL(ctx.Context(), serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderNotFoundErrorPage(ctx)
	}

	challengeRequired := service.ChallengeRequired && time.Since(h.getAuthorizedTime(ctx, service.LoginURL)) > service.ChallengeValidity
	if challengeRequired {
		state := TwoFactorState{
			Action:      "authorize",
			CallbackURL: urlutil.AppendQuery("/authorize", "service", serviceURL),
			Timestamp:   time.Now().UnixMilli(),
		}
		return redirect(ctx, "/2fa/challenge", "state", encryptState(ctx, state))
	}

	h.setAuthorizedTime(ctx, service.LoginURL, time.Now())
	return h.handleAuthorizeServiceAccess(ctx, session, serviceURL)
}

func (h *AuthHandler) GetHome(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsAuthenticated() {
		return redirect(ctx, "/profile")
	}
	return redirect(ctx, "/login")
}

func (h *AuthHandler) GetProfile(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}
	isTwoFAEnabled, err := h.twoFactorService.IsTwoFAEnabled(ctx.Context(), user.ID)
	if err != nil {
		return err
	}

	return render.RenderProfilePage(ctx, render.ProfilePageData{
		Username:     user.Username,
		FullName:     user.FullName,
		Email:        user.Email,
		Picture:      user.Picture,
		TwoFAEnabled: isTwoFAEnabled,
	})
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
