package web

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/mail"
	"github.com/khanghh/kauth/internal/middlewares/captcha"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/khanghh/kauth/internal/urlutil"
	"github.com/khanghh/kauth/internal/users"
)

type ResetPasswordHandler struct {
	userService      UserService
	twoFactorService TwoFactorService
	mailSender       mail.MailSender
}

type ResetPasswordClaims struct {
	Email     string `json:"email"`
	Timestamp int64  `json:"timestamp"`
}

func (h *ResetPasswordHandler) generateResetPasswordToken(ctx *fiber.Ctx, email string) (string, error) {
	sub := twofactor.Subject{IPAddress: ctx.IP()}
	claims := ResetPasswordClaims{Email: email, Timestamp: time.Now().Unix()}
	token, _, err := h.twoFactorService.Token().Create(ctx.Context(), sub, "", claims, 5*time.Minute)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (h *ResetPasswordHandler) verifyResetPasswordToken(ctx *fiber.Ctx, cid, token string) (ResetPasswordClaims, error) {
	var claims ResetPasswordClaims
	err := h.twoFactorService.Token().Verify(ctx.Context(), token, &claims)
	if err != nil {
		return claims, err
	}
	return claims, nil
}

func (h *ResetPasswordHandler) GetResetPassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	token := ctx.Query("token")
	state := ctx.Query("state")

	if state != "" {
		var claims ResetPasswordClaims
		if err := decryptState(ctx, state, &claims); err != nil {
			return render.RenderNotFoundErrorPage(ctx)
		}
		return render.RenderSetNewPasswordPage(ctx, "")
	}

	if token != "" {
		claims, err := h.verifyResetPasswordToken(ctx, "", token)
		if err != nil {
			return render.RenderNotFoundErrorPage(ctx)
		}
		// session.SetExpiry(15 * time.Minute)
		return redirect(ctx, "/reset-password", "state", encryptState(ctx, claims))
	}

	return render.RenderNotFoundErrorPage(ctx)
}

func (h *ResetPasswordHandler) PostResetPassword(ctx *fiber.Ctx) error {
	encryptedState := ctx.Query("state")
	newPassword := ctx.FormValue("newPassword")

	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	if encryptedState == "" {
		return render.RenderNotFoundErrorPage(ctx)
	}

	var claims ResetPasswordClaims
	if err := decryptState(ctx, encryptedState, &claims); err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}

	if err := captcha.Verify(ctx); err != nil {
		return render.RenderSetNewPasswordPage(ctx, MsgInvalidCaptcha)
	}

	if err := validatePassword(newPassword); err != nil {
		return render.RenderSetNewPasswordPage(ctx, err.Error())
	}

	err := h.userService.UpdatePassword(ctx.Context(), claims.Email, newPassword)
	if err != nil {
		return err
	}

	sessions.Destroy(ctx)
	return render.RenderPasswordUpdatedPage(ctx)
}

func (h *ResetPasswordHandler) GetForogtPassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	return render.RenderForgotPasswordPage(ctx, render.ForgotPasswordPageData{})
}

func (h *ResetPasswordHandler) PostForgotPassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	username := ctx.FormValue("username")
	email := ctx.FormValue("email")

	pageData := render.ForgotPasswordPageData{}
	if err := validateEmail(email); err != nil {
		pageData.ErrorMsg = err.Error()
		return render.RenderForgotPasswordPage(ctx, pageData)
	}

	if err := captcha.Verify(ctx); err != nil {
		pageData.ErrorMsg = MsgInvalidCaptcha
		return render.RenderForgotPasswordPage(ctx, pageData)
	}

	user, err := h.userService.GetUserByEmail(ctx.Context(), email)
	if errors.Is(err, users.ErrUserNotFound) {
		pageData.ErrorMsg = MsgUserNotFound
		return render.RenderForgotPasswordPage(ctx, pageData)
	}
	if err != nil {
		return err
	}

	if user.Username != username {
		pageData.ErrorMsg = MsgUserNotFound
		return render.RenderForgotPasswordPage(ctx, pageData)
	}

	token, err := h.generateResetPasswordToken(ctx, email)
	if err != nil {
		if errorMsg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = errorMsg
			return render.RenderForgotPasswordPage(ctx, pageData)
		}
		return err
	}

	resetPasswordLink := urlutil.AppendQuery(fmt.Sprintf("%s/reset-password", ctx.BaseURL()), "token", token)
	err = mail.SendResetPasswordLink(h.mailSender, user.Email, resetPasswordLink)
	if err != nil {
		return err
	}
	return render.RenderForgotPasswordPage(ctx, render.ForgotPasswordPageData{EmailSent: true})
}

func NewResetPasswordHandler(userService UserService, twoFactorService TwoFactorService, mailSender mail.MailSender) *ResetPasswordHandler {
	return &ResetPasswordHandler{
		userService:      userService,
		twoFactorService: twoFactorService,
		mailSender:       mailSender,
	}
}
