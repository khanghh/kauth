package api

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/captcha"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/khanghh/kauth/model"
	"golang.org/x/crypto/bcrypt"
)

var ()

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

type loginRequest struct {
	Username     string `json:"username" form:"username"`
	Password     string `json:"password" form:"password"`
	ClientID     string `json:"clientId" form:"client_id"`
	ClientSecret string `json:"clientSecret" form:"client_secret"`
}

type loginUserInfo struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Picture  string `json:"picture,omitempty"`
}

type loginResponse struct {
	User          loginUserInfo `json:"user"`
	TwoFARequired bool          `json:"twoFaRequired"`
	Methods       []string      `json:"methods,omitempty"`
}

type login2FAChallengeResponse struct {
	CID    string `json:"cid"`
	Method string `json:"method"`
	OTP    string `json:"otp,omitempty"` // mock/testing only
}

// helper to build twofactor.Subject from ctx
func twoFactorSubjectFromCtx(ctx *fiber.Ctx, uid uint) twofactor.Subject {
	return twofactor.Subject{
		UserID:    uid,
		SessionID: "",
		IPAddress: ctx.IP(),
		UserAgent: ctx.Get("User-Agent"),
	}
}

func get2FAMethodNames(factors []*model.UserFactor) []string {
	methods := make([]string, 0, len(factors))
	for _, factor := range factors {
		methods = append(methods, factor.Type)
	}
	return methods
}

func toLoginUserInfo(user *model.User) loginUserInfo {
	return loginUserInfo{
		UserID:   strconv.FormatUint(uint64(user.ID), 10),
		Username: user.Username,
		FullName: user.FullName,
		Email:    user.Email,
		Picture:  user.Picture,
	}
}

func (h *AuthHandler) PostLogin(ctx *fiber.Ctx) error {
	var req loginRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ErrMissingParameters
	}
	if req.Username == "" || req.Password == "" {
		return ErrMissingParameters
	}

	var (
		service *model.Service
		err     error
	)
	if req.ClientID != "" && req.ClientSecret != "" {
		service, err = h.authorizeService.GetServiceByClientID(ctx.Context(), req.ClientID)
		if err != nil || service.ClientSecret != req.ClientSecret {
			return ErrUnAuthorized
		}
	} else if err = captcha.Verify(ctx); err != nil {
		return ErrCaptchaVerificationFailed
	}

	user, err := h.userService.GetUserByUsernameOrEmail(ctx.Context(), req.Username)
	if err != nil {
		return ErrIncorrectPassword
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return ErrIncorrectPassword
	}

	authFactors, err := h.twoFactorService.GetEnabledAuthFactors(ctx.Context(), user.ID)
	if err == nil && len(authFactors) > 0 {
		return ctx.Status(fiber.StatusOK).JSON(
			NewDataResponse(loginResponse{
				User:          toLoginUserInfo(user),
				TwoFARequired: true,
				Methods:       get2FAMethodNames(authFactors),
			}),
		)
	}

	sessions.Save(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	})

	return ctx.Status(fiber.StatusOK).JSON(
		NewDataResponse(loginResponse{
			User:          toLoginUserInfo(user),
			TwoFARequired: false,
		}),
	)
}

// POST /api/login/2fa
func (h *AuthHandler) PostLogin2FA(ctx *fiber.Ctx) error {
	return nil
}

func (h *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	return nil
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
