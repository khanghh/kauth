package web

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/audit"
	"github.com/khanghh/kauth/internal/auth"
	"github.com/khanghh/kauth/internal/common"
	"github.com/khanghh/kauth/internal/middlewares/captcha"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/oauth"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/urlutil"
	"github.com/khanghh/kauth/model"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
	oauthProviders   []oauth.OAuthProvider
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

func mapLoginError(errorCode string) string {
	switch errorCode {
	case "email_conflict":
		return MsgLoginEmailConflict
	case "unsupported_provider":
		return MsgLoginUnsupportedOAuth
	case "tfa_failed":
		return MsgTwoFactorChallengeFailed
	case "login_locked":
		return MsgTooManyFailedLogin
	default:
		return ""
	}
}

func doServerCallback(ctx *fiber.Ctx, callbackURL string) error {
	resp, err := http.Get(callbackURL)
	if err != nil {
		log.Printf("Error during callback to %s: %v", callbackURL, err)
		return render.RenderInternalServerErrorPage(ctx)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return render.RenderAccessDeniedPage(ctx)
	}
	return render.RenderAccessGrantedPage(ctx)
}

// handleLogin2FA triggers 2FA challenge if user has enabled 2FA
func (h *AuthHandler) handleLogin2FA(ctx *fiber.Ctx, session *sessions.Session, user *model.User, serviceNameOrURL string, serviceState string) error {
	redirectURL := "/"
	if serviceNameOrURL != "" {
		redirectURL = urlutil.AppendQuery("/authorize", "service", serviceNameOrURL, "state", serviceState)
	}

	isTwoFAEnabled, err := h.twoFactorService.IsTwoFAEnabled(ctx.Context(), user.ID)
	if err != nil {
		return err
	}

	session.Set(ctx.Context(), sessions.SessionData{
		IP:            ctx.IP(),
		UserID:        user.ID,
		LoginTime:     time.Now(),
		TwoFARequired: isTwoFAEnabled,
	})

	if !isTwoFAEnabled {
		return redirect(ctx, redirectURL)
	}

	state := TwoFactorState{
		Action:      "login",
		CallbackURL: redirectURL,
		Timestamp:   time.Now().UnixMilli(),
	}
	return redirect(ctx, "/2fa/challenge", "state", encryptState(ctx, state))
}

func (h *AuthHandler) getOAuthLoginURLs(serviceURL string) map[string]string {
	query := url.Values{
		"service": {serviceURL},
	}
	oauthLoginURLs := make(map[string]string)
	for _, provider := range h.oauthProviders {
		oauthLoginURLs[provider.Name()] = provider.GetAuthCodeURL(query.Encode())
	}
	return oauthLoginURLs
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, user *model.User, session *sessions.Session, service *model.Service, serviceCallbackURL string) error {
	h.setAuthorizedTime(ctx, service.CallbackURL, time.Now())
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), session.UserID, serviceCallbackURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderAccessDeniedPage(ctx)
	} else if err != nil {
		return render.RenderInternalServerErrorPage(ctx)
	}

	audit.RecordServiceAuthorized(ctx, user, service, fmt.Sprintf("%s?ticket=%s", ticket.CallbackURL, ticket.TicketID))

	callbackURL := urlutil.AppendQuery(ticket.CallbackURL, "ticket", ticket.TicketID)
	if service.IsServerCallback {
		return doServerCallback(ctx, callbackURL)
	}
	return ctx.Redirect(callbackURL)
}

func (h *AuthHandler) GetAuthorize(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")
	serviceNameOrURL := urlutil.NormalizeURL(ctx.Query("service"))
	serviceState := ctx.Query("state")
	if serviceNameOrURL == "" {
		return render.RenderNotFoundErrorPage(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceNameOrURL, "state", serviceState)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	service, err := h.authorizeService.GetServiceByNameOrURL(ctx.Context(), serviceNameOrURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderNotFoundErrorPage(ctx)
	} else if err != nil {
		return err
	}

	serviceCallbackURL := urlutil.AppendQuery(service.CallbackURL, "state", serviceState)

	authorizeTime := h.getAuthorizedTime(ctx, service.CallbackURL)
	challengeRequired := service.ChallengeRequired && time.Since(authorizeTime) > service.ChallengeValidity
	if !challengeRequired && service.AutoLogin {
		return h.handleAuthorizeServiceAccess(ctx, user, session, service, serviceCallbackURL)
	}
	if challengeRequired && cid != "" {
		sub := getChallengeSubject(ctx, sessions.Get(ctx))
		endpoint := urlutil.AppendQuery("/authorize", "service", serviceNameOrURL, "state", serviceState)
		err = h.twoFactorService.FinalizeChallenge(ctx.Context(), cid, sub, endpoint)
		if err == nil {
			return h.handleAuthorizeServiceAccess(ctx, user, session, service, serviceCallbackURL)
		}
	}

	pageData := render.AuthorizeServicePageData{
		Email:       user.Email,
		ServiceName: service.Name,
		ServiceURL:  service.CallbackURL,
	}
	return render.RenderAuthorizeServiceAccessPage(ctx, pageData)
}

func (h *AuthHandler) PostAuthorize(ctx *fiber.Ctx) error {
	serviceNameOrURL := urlutil.NormalizeURL(ctx.Query("service"))
	serviceState := ctx.Query("state")
	confirm := ctx.FormValue("confirm")

	if serviceNameOrURL == "" {
		return render.RenderNotFoundErrorPage(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceNameOrURL, "state", serviceState)
	}

	if confirm != "true" {
		return ctx.Redirect("/")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	service, err := h.authorizeService.GetServiceByNameOrURL(ctx.Context(), serviceNameOrURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderNotFoundErrorPage(ctx)
	}

	authorizeTime := h.getAuthorizedTime(ctx, service.CallbackURL)
	challengeRequired := service.ChallengeRequired && time.Since(authorizeTime) > service.ChallengeValidity
	if challengeRequired {
		state := TwoFactorState{
			Action:      "authorize",
			CallbackURL: urlutil.AppendQuery("/authorize", "service", serviceNameOrURL, "state", serviceState),
			Timestamp:   time.Now().UnixMilli(),
		}
		return redirect(ctx, "/2fa/challenge", "state", encryptState(ctx, state))
	}

	serviceCallbackURL := urlutil.AppendQuery(service.CallbackURL, "state", serviceState)
	return h.handleAuthorizeServiceAccess(ctx, user, session, service, serviceCallbackURL)
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

func (h *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceNameOrURL := urlutil.RemoveQuery(ctx.Query("service"))
	errorCode := ctx.Query("error")

	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return render.RenderLoginPage(ctx, render.LoginPageData{
			OAuthLoginURLs: h.getOAuthLoginURLs(serviceNameOrURL),
			ErrorMsg:       mapLoginError(errorCode),
		})
	}

	if serviceNameOrURL == "" {
		return ctx.Redirect("/")
	}
	return redirect(ctx, "/authorize", "service", serviceNameOrURL)
}

func (h *AuthHandler) PostLogin(ctx *fiber.Ctx) error {
	serviceNameOrURL := urlutil.RemoveQuery(ctx.Query("service"))
	serviceState := ctx.Query("state")
	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	session := sessions.Get(ctx)
	if session != nil && session.IsAuthenticated() {
		return ctx.Redirect("/")
	}

	pageData := render.LoginPageData{
		OAuthLoginURLs: h.getOAuthLoginURLs(serviceNameOrURL),
	}

	if err := captcha.Verify(ctx); err != nil {
		pageData.ErrorMsg = MsgInvalidCaptcha
		return render.RenderLoginPage(ctx, pageData)
	}

	user, err := h.userService.GetUserByUsernameOrEmail(ctx.Context(), username)
	if err != nil {
		pageData.ErrorMsg = MsgLoginWrongCredentials
		return render.RenderLoginPage(ctx, pageData)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		pageData.ErrorMsg = MsgLoginWrongCredentials
		audit.RecordLoginFailure(ctx, user, audit.AuthMethodPassword, "")
		return render.RenderLoginPage(ctx, pageData)
	}

	audit.RecordLoginSuccess(ctx, user, audit.AuthMethodPassword)
	return h.handleLogin2FA(ctx, session, user, serviceNameOrURL, serviceState)
}

func (h *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	audit.RecordUserLogout(ctx, session.UserID, "")
	return forceLogout(ctx, "")
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService, oauthProviders []oauth.OAuthProvider) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
		oauthProviders:   oauthProviders,
	}
}
