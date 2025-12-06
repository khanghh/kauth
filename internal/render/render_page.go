package render

import (
	"github.com/gofiber/fiber/v2"
)

func RenderInternalServerErrorPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("error-internal", nil)
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusInternalServerError).SendString(body)
}

func RenderNotFoundErrorPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("error-not-found", nil)
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusNotFound).SendString(body)
}

func RenderForbiddenErrorPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("error-forbidden", nil)
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusForbidden).SendString(body)
}

func RenderBadRequestErrorPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("error-bad-request", nil)
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusBadRequest).SendString(body)
}

func RenderLoginPage(ctx *fiber.Ctx, data LoginPageData) error {
	body, err := RenderHTML("login", fiber.Map{
		"siteName":          globalVars["siteName"],
		"turnstileSiteKey":  globalVars["turnstileSiteKey"],
		"identifier":        data.Identifier,
		"googleOAuthURL":    data.OAuthLoginURLs["google"],
		"facebookOAuthURL":  data.OAuthLoginURLs["facebook"],
		"discordOAuthURL":   data.OAuthLoginURLs["discord"],
		"microsoftOAuthURL": data.OAuthLoginURLs["microsoft"],
		"appleOAuthURL":     data.OAuthLoginURLs["apple"],
		"errorMsg":          data.ErrorMsg,
	})
	if err != nil {
		return err
	}

	ctx.Set("Content-Type", "text/html; charset=utf-8")
	statusCode := fiber.StatusOK
	if data.ErrorMsg != "" {
		statusCode = fiber.StatusUnauthorized
	}
	return ctx.Status(statusCode).SendString(body)
}

func RenderRegisterPage(ctx *fiber.Ctx, data RegisterPageData) error {
	body, err := RenderHTML("register", fiber.Map{
		"siteName":         globalVars["siteName"],
		"turnstileSiteKey": globalVars["turnstileSiteKey"],
		"username":         data.Username,
		"email":            data.Email,
		"usernameError":    data.FormErrors["username"],
		"passwordError":    data.FormErrors["password"],
		"emailError":       data.FormErrors["email"],
		"errorMsg":         data.ErrorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderOAuthRegisterPage(ctx *fiber.Ctx, data RegisterPageData) error {
	body, err := RenderHTML("oauth-register", fiber.Map{
		"siteName":         globalVars["siteName"],
		"turnstileSiteKey": globalVars["turnstileSiteKey"],
		"username":         data.Username,
		"fullName":         data.FullName,
		"email":            data.Email,
		"picture":          data.Picture,
		"oauthProvider":    data.OAuthProvider,
		"usernameError":    data.FormErrors["username"],
		"passwordError":    data.FormErrors["password"],
		"emailError":       data.FormErrors["email"],
		"errorMsg":         data.ErrorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderAccessDeniedPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("access-denied", fiber.Map{
		"siteName": globalVars["siteName"],
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusForbidden).SendString(body)
}

func RenderAccessGrantedPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("access-granted", fiber.Map{
		"siteName": globalVars["siteName"],
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderProfilePage(ctx *fiber.Ctx, data ProfilePageData) error {
	displayName := data.FullName
	if displayName == "" {
		displayName = data.Username
	}
	body, err := RenderHTML("profile", fiber.Map{
		"siteName":     globalVars["siteName"],
		"displayName":  displayName,
		"email":        data.Email,
		"picture":      data.Picture,
		"twoFAEnabled": data.TwoFAEnabled,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderVerificationRequiredPage(ctx *fiber.Ctx, data VerificationRequiredPageData) error {
	email := data.Email
	phone := formatPhone(data.Phone)
	if data.IsMasked {
		email = maskEmail(email)
		phone = maskPhone(phone)
	}
	body, err := RenderHTML("verification-required", fiber.Map{
		"siteName":     globalVars["siteName"],
		"emailEnabled": data.EmailEnabled,
		"smsEnabled":   data.SMSEnableled,
		"totpEnabled":  data.TOTPEnabled,
		"email":        email,
		"phone":        phone,
		"errorMsg":     data.ErrorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderVerifyOTPPage(ctx *fiber.Ctx, pageData VerifyOTPPageData) error {
	email := pageData.Email
	phone := formatPhone(pageData.Phone)
	if pageData.IsMasked {
		email = maskEmail(email)
		phone = maskPhone(phone)
	}

	emailOrPhone := email
	if email == "" {
		emailOrPhone = phone
	}
	body, err := RenderHTML("verify-otp", fiber.Map{
		"siteName":     globalVars["siteName"],
		"emailOrPhone": emailOrPhone,
		"errorMsg":     pageData.ErrorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderRegisterVerifyEmailPage(ctx *fiber.Ctx, email string) error {
	body, err := RenderHTML("verify-email", fiber.Map{
		"siteName": globalVars["siteName"],
		"email":    email,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderEmailVerificationSuccessPage(ctx *fiber.Ctx, email string) error {
	body, err := RenderHTML("verify-email-result", fiber.Map{
		"siteName": globalVars["siteName"],
		"success":  true,
		"email":    email,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderEmailVerificationFailurePage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("verify-email-result", fiber.Map{
		"siteName": globalVars["siteName"],
		"success":  false,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderAuthorizeServiceAccessPage(ctx *fiber.Ctx, data AuthorizeServicePageData) error {
	body, err := RenderHTML("authorize-service", fiber.Map{
		"siteName":    globalVars["siteName"],
		"email":       data.Email,
		"serviceName": data.ServiceName,
		"serviceURL":  data.ServiceURL,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderForgotPasswordPage(ctx *fiber.Ctx, pageData ForgotPasswordPageData) error {
	body, err := RenderHTML("forgot-password", fiber.Map{
		"siteName":         globalVars["siteName"],
		"turnstileSiteKey": globalVars["turnstileSiteKey"],
		"email":            pageData.Email,
		"emailSent":        pageData.EmailSent,
		"errorMsg":         pageData.ErrorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderSetNewPasswordPage(ctx *fiber.Ctx, errorMsg string) error {
	body, err := RenderHTML("set-new-password", fiber.Map{
		"siteName":         globalVars["siteName"],
		"turnstileSiteKey": globalVars["turnstileSiteKey"],
		"errorMsg":         errorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderPasswordUpdatedPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("password-updated", fiber.Map{
		"siteName": globalVars["siteName"],
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderChangePasswordPage(ctx *fiber.Ctx, errorMsg string) error {
	body, err := RenderHTML("change-password", fiber.Map{
		"siteName":         globalVars["siteName"],
		"turnstileSiteKey": globalVars["turnstileSiteKey"],
		"errorMsg":         errorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderTOTPEnrollmentPage(ctx *fiber.Ctx, data TOTPEnrollmentPageData) error {
	body, err := RenderHTML("totp-enrollment", fiber.Map{
		"siteName":      globalVars["siteName"],
		"secretKey":     data.SecretKey,
		"enrollmentURL": data.EnrollmentURL,
		"errorMsg":      data.ErrorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderTOTPEnrollSuccessPage(ctx *fiber.Ctx) error {
	body, err := RenderHTML("totp-enroll-success", fiber.Map{
		"siteName": globalVars["siteName"],
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func Render2FASettingsPage(ctx *fiber.Ctx, data TwoFASettingsPageData) error {
	body, err := RenderHTML("twofactor-settings", fiber.Map{
		"siteName":     globalVars["siteName"],
		"email":        data.Email,
		"emailEnabled": data.EmailEnabled,
		"totpEnabled":  data.TOTPEnabled,
		"errorMsg":     data.ErrorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}

func RenderVerifyTOTPPage(ctx *fiber.Ctx, errorMsg string) error {
	body, err := RenderHTML("verify-totp", fiber.Map{
		"siteName": globalVars["siteName"],
		"errorMsg": errorMsg,
	})
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).SendString(body)
}
