package web

import (
	"errors"
	"fmt"
	"log/slog"

	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/mail"
	"github.com/khanghh/kauth/internal/middlewares/captcha"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/users"
)

var (
	MsgUsernameTaken   = "Username is already taken."
	MsgEmailRegistered = "Email is already registered."
)

type RegisterForm struct {
	Username string `form:"username"`
	Password string `form:"password"`
	Email    string `form:"email"`
}

type RegisterHandler struct {
	userService UserService
	mailSender  mail.MailSender
}

func NewRegisterHandler(userService UserService, mailSender mail.MailSender) *RegisterHandler {
	return &RegisterHandler{
		userService: userService,
		mailSender:  mailSender,
	}
}

func validateRegisterForm(username string, password string, email string) map[string]string {
	formErrors := make(map[string]string)
	if err := validateUsername(username); err != nil {
		formErrors["username"] = err.Error()
	}

	if err := validatePassword(password); err != nil {
		formErrors["password"] = err.Error()
	}

	if err := validateEmail(email); err != nil {
		formErrors["email"] = err.Error()
	}
	return formErrors
}

func (h *RegisterHandler) GetRegister(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || session.IsLoggedIn() {
		return ctx.Redirect("/")
	}
	return render.RenderRegisterPage(ctx, render.RegisterPageData{})
}

type RegisterClaims struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	TimeStamp int64  `json:"timestamp"`
}

func (h *RegisterHandler) PostRegister(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	var (
		username = strings.ToLower(ctx.FormValue("username"))
		email    = strings.ToLower(ctx.FormValue("email"))
		password = ctx.FormValue("password")
	)

	pageData := render.RegisterPageData{
		Username: username,
		Email:    email,
	}

	if err := captcha.Verify(ctx); err != nil {
		pageData.ErrorMsg = MsgInvalidCaptcha
		return render.RenderRegisterPage(ctx, pageData)
	}

	pageData.FormErrors = validateRegisterForm(username, password, email)
	if len(pageData.FormErrors) > 0 {
		return render.RenderRegisterPage(ctx, pageData)
	}

	userOpts := users.CreateUserOptions{
		Username: username,
		Email:    email,
		Password: password,
	}
	pendingUser, err := h.userService.RegisterUser(ctx.Context(), userOpts)
	if err != nil {
		if errors.Is(err, users.ErrUsernameTaken) {
			pageData.FormErrors["username"] = MsgUsernameTaken
			return render.RenderRegisterPage(ctx, pageData)
		} else if errors.Is(err, users.ErrEmailRegisterd) {
			pageData.FormErrors["email"] = MsgEmailRegistered
			return render.RenderRegisterPage(ctx, pageData)
		}
		slog.Error("Failed to create user", "error", err)
		return err
	}

	verifyURL := fmt.Sprintf("%s/register/verify?email=%s&token=%s", ctx.BaseURL(), email, pendingUser.ActiveToken)
	if err := mail.SendRegisterVerification(h.mailSender, email, verifyURL); err != nil {
		return err
	}

	return render.RenderRegisterVerifyEmailPage(ctx, email)
}

func (h *RegisterHandler) GetRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || session.IsLoggedIn() || session.OAuthID == 0 {
		return ctx.Redirect("/login")
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return err
	}

	return render.RenderOAuthRegisterPage(ctx, render.RegisterPageData{
		Email:         userOAuth.Email,
		FullName:      userOAuth.DisplayName,
		Picture:       userOAuth.Picture,
		OAuthProvider: userOAuth.Provider,
	})
}

func (h *RegisterHandler) PostRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || session.IsLoggedIn() || session.OAuthID == 0 {
		return ctx.Redirect("/")
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return err
	}

	var (
		username = ctx.FormValue("username")
		password = ctx.FormValue("password")
	)

	pageData := render.RegisterPageData{
		Username:      username,
		Email:         userOAuth.Email,
		FullName:      userOAuth.DisplayName,
		Picture:       userOAuth.Picture,
		OAuthProvider: userOAuth.Provider,
	}

	if err := captcha.Verify(ctx); err != nil {
		pageData.ErrorMsg = MsgInvalidCaptcha
		return render.RenderOAuthRegisterPage(ctx, pageData)
	}

	pageData.FormErrors = validateRegisterForm(username, password, userOAuth.Email)
	if len(pageData.FormErrors) > 0 {
		return render.RenderOAuthRegisterPage(ctx, pageData)
	}

	userOpts := users.CreateUserOptions{
		Username:  username,
		FullName:  userOAuth.DisplayName,
		Email:     userOAuth.Email,
		Picture:   userOAuth.Picture,
		UserOAuth: userOAuth,
		Password:  password,
	}
	user, err := h.userService.CreateUser(ctx.Context(), userOpts)
	if err != nil {
		if errors.Is(err, users.ErrUsernameTaken) {
			pageData.FormErrors["username"] = MsgUsernameTaken
			return render.RenderOAuthRegisterPage(ctx, pageData)
		} else if errors.Is(err, users.ErrEmailRegisterd) {
			pageData.FormErrors["email"] = MsgEmailRegistered
			return render.RenderOAuthRegisterPage(ctx, pageData)
		}
		slog.Error("Failed to create user", "error", err)
		return err
	}

	session.UserID = user.ID
	serviceURL := ctx.Query("service")
	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	serviceState := ctx.Query("state")
	return redirectAuthorize(ctx, session, serviceURL, serviceState)
}

func (h *RegisterHandler) GetRegisterVerify(ctx *fiber.Ctx) error {
	email := ctx.Query("email")
	token := ctx.Query("token")

	if _, err := h.userService.ApprovePendingUser(ctx.Context(), email, token); err != nil {
		return render.RenderEmailVerificationFailurePage(ctx)
	}

	return render.RenderEmailVerificationSuccessPage(ctx, email)
}
