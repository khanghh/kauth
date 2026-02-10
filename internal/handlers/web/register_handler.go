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
	"github.com/khanghh/kauth/model"
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
	pageData := render.RegisterPageData{}

	oauthID := ctx.QueryInt("oauth_id")
	if session.OAuthID != 0 && uint(oauthID) == session.OAuthID {
		userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
		if err == nil {
			pageData.Email = userOAuth.Email
			pageData.FullName = userOAuth.DisplayName
			pageData.Picture = userOAuth.Picture
			pageData.OAuthProvider = userOAuth.Provider
		}
	}

	return render.RenderRegisterPage(ctx, pageData)
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

	var userOAuth *model.UserOAuth
	if session.OAuthID != 0 {
		var err error
		userOAuth, err = h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
		if err != nil {
			return err
		}
		email = strings.ToLower(userOAuth.Email)
		pageData.Email = email
		pageData.FullName = userOAuth.DisplayName
		pageData.Picture = userOAuth.Picture
		pageData.OAuthProvider = userOAuth.Provider
	}

	if err := captcha.Verify(ctx); err != nil {
		pageData.ErrorMsg = MsgInvalidCaptcha
		return render.RenderRegisterPage(ctx, pageData)
	}

	pageData.FormErrors = validateRegisterForm(username, password, email)
	if len(pageData.FormErrors) > 0 {
		return render.RenderRegisterPage(ctx, pageData)
	}

	if userOAuth != nil {
		// OAuth registration flow
		userOpts := users.CreateUserOptions{
			Username:  username,
			FullName:  userOAuth.DisplayName,
			Email:     email,
			Picture:   userOAuth.Picture,
			UserOAuth: userOAuth,
			Password:  password,
		}
		user, err := h.userService.CreateUser(ctx.Context(), userOpts)
		if err != nil {
			if errors.Is(err, users.ErrUsernameTaken) {
				pageData.FormErrors["username"] = MsgUsernameTaken
				return render.RenderRegisterPage(ctx, pageData)
			} else if errors.Is(err, users.ErrEmailRegisterd) {
				pageData.FormErrors["email"] = MsgEmailRegistered
				return render.RenderRegisterPage(ctx, pageData)
			}
			slog.Error("Failed to create user with OAuth", "error", err)
			return err
		}

		session.UserID = user.ID
		session.Username = user.Username
		serviceURL := ctx.Query("service")
		if serviceURL == "" {
			return ctx.Redirect("/")
		}
		serviceState := ctx.Query("state")
		return redirectAuthorize(ctx, session, serviceURL, serviceState)
	}

	// Normal registration flow
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
		slog.Error("Failed to register user", "error", err)
		return err
	}

	verifyURL := fmt.Sprintf("%s/register/verify?email=%s&token=%s", ctx.BaseURL(), email, pendingUser.ActiveToken)
	if err := mail.SendRegisterVerification(h.mailSender, email, verifyURL); err != nil {
		return err
	}

	return render.RenderRegisterVerifyEmailPage(ctx, render.VerifyEmailPageData{Email: email})
}

func (h *RegisterHandler) GetRegisterVerify(ctx *fiber.Ctx) error {
	email := ctx.Query("email")
	token := ctx.Query("token")

	if email == "" || token == "" {
		return ctx.Redirect("/")
	}

	if _, err := h.userService.ApprovePendingUser(ctx.Context(), email, token); err != nil {
		return render.RenderRegisterVerifyEmailPage(ctx, render.VerifyEmailPageData{Success: false})
	}

	return render.RenderRegisterVerifyEmailPage(ctx, render.VerifyEmailPageData{Success: true})
}
