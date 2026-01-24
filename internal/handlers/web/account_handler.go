package web

import (
	"encoding/base32"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/pquerna/otp/totp"
)

type AccountHandler struct {
	userService      UserService
	twoFactorService TwoFactorService
}

func NewAccountHandler(userService UserService, twoFactorService TwoFactorService) *AccountHandler {
	return &AccountHandler{
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}

func (h *AccountHandler) GetAccountHomePage(ctx *fiber.Ctx) error {
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

	return render.RenderAccountHomePage(ctx, render.AccountHomePageData{
		Username:     user.Username,
		FullName:     user.FullName,
		Email:        user.Email,
		Picture:      user.Picture,
		TwoFAEnabled: isTwoFAEnabled,
	})
}

func (h *AccountHandler) GetPersonalInfo(ctx *fiber.Ctx) error {
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

	return render.RenderPersonalInfoPage(ctx, render.AccountHomePageData{
		Username:     user.Username,
		FullName:     user.FullName,
		Email:        user.Email,
		Picture:      user.Picture,
		TwoFAEnabled: isTwoFAEnabled,
	})
}

func (h *AccountHandler) GetChangePassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return redirect(ctx, "/login")
	}

	return render.RenderAccountChangePasswordPage(ctx, "")
}

// GetTwoFactorSettings returns the 2FA settings page
// GET /two-factor
func (h *AccountHandler) GetTwoFactorSettings(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}
	authFactors, err := h.userService.GetAuthFactors(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	pageData := render.AccountTwoFASettingsPageData{
		Email:        user.Email,
		EmailEnabled: isFactorEnabled(authFactors, string(twofactor.AuthFactorEmail)),
		TOTPEnabled:  isFactorEnabled(authFactors, string(twofactor.AuthFactorTOTP)),
	}
	return render.RenderAccount2FASettingsPage(ctx, pageData)
}

func (h *AccountHandler) generateTOTPEnrollmentURL(issuer string, username string, secret string) (string, error) {
	base32Secret, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
		Period:      30,
		Secret:      base32Secret,
	})

	if err != nil {
		return "", err
	}
	return key.String(), nil
}

func (h *AccountHandler) GetTwoFactorTOTPEnroll(ctx *fiber.Ctx) error {
	renew := ctx.Query("renew")
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	var secret string
	err = session.GetField(ctx.Context(), totpEnrollSecretSessionKey, &secret)
	if err != nil || renew == "true" {
		secret = generateTOTPSecret()
		err := session.SetField(ctx.Context(), totpEnrollSecretSessionKey, secret)
		if err != nil {
			return err
		}
	}

	issuer, _ := render.GetValue("siteName").(string)
	enrollmentURL, err := h.generateTOTPEnrollmentURL(issuer, user.Username, secret)
	if err != nil {
		return err
	}

	pageData := render.AccountTOTPEnrollmentPageData{
		SecretKey:     secret,
		EnrollmentURL: enrollmentURL,
	}
	return render.RenderAccountTOTPEnrollmentPage(ctx, pageData)
}
