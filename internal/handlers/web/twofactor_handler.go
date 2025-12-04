package web

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/mail"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/khanghh/kauth/internal/users"
	"github.com/khanghh/kauth/model"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
)

const (
	totpEnrollSecretSessionKey = "_totp_enroll_secret"
)

type TwoFactorHandler struct {
	twoFactorService TwoFactorService
	userService      UserService
	mailSender       mail.MailSender
}

func (h *TwoFactorHandler) renderVerifyOTP(ctx *fiber.Ctx, email string, errorMsg string) error {
	pageData := render.VerifyOTPPageData{
		Email:    email,
		IsMasked: true,
		ErrorMsg: errorMsg,
	}
	return render.RenderVerifyOTPPage(ctx, pageData)
}

func mapTwoFactorError(err error) (string, bool) {
	if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
		return MsgTooManyFailedAttempts, true
	}
	if errors.Is(err, twofactor.ErrOTPRequestLimitReached) {
		return MsgTooManyOTPRequested, true
	}
	if errors.Is(err, twofactor.ErrOTPRequestRateLimited) {
		return MsgOTPRequestRateLimited, true
	}
	var verifyErr *twofactor.AttemptFailError
	if errors.As(err, &verifyErr) {
		return fmt.Sprintf(MsgInvalidOTP, verifyErr.AttemptsLeft), true
	}
	return "", false
}

func getChallengeSubject(ctx *fiber.Ctx, session *sessions.Session) twofactor.Subject {
	return twofactor.Subject{
		UserID:    session.UserID,
		SessionID: session.ID(),
		IPAddress: ctx.IP(),
		UserAgent: ctx.Get("User-Agent"),
	}
}

func (h *TwoFactorHandler) GetChallenge(ctx *fiber.Ctx) error {
	encryptedState := ctx.Query("state")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	if encryptedState == "" {
		return render.RenderNotFoundErrorPage(ctx)
	}
	var state TwoFactorState
	if err := decryptState(ctx, encryptedState, &state); err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}
	if time.Since(time.UnixMilli(state.Timestamp)) > 5*time.Minute {
		// TODO: if this is 2fa login, logout user when it's expired
		return render.RenderNotFoundErrorPage(ctx)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	authFactors, err := h.userService.GetAuthFactors(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	pageData := render.VerificationRequiredPageData{
		Email:        user.Email,
		EmailEnabled: isFactorEnabled(authFactors, string(users.AuthFactorEmail)),
		TOTPEnabled:  isFactorEnabled(authFactors, string(users.AuthFactorTOTP)),
		IsMasked:     true,
	}
	return render.RenderVerificationRequiredPage(ctx, pageData)
}

func (h *TwoFactorHandler) generateAndSendEmailOTP(ctx *fiber.Ctx, ch *twofactor.Challenge, sub twofactor.Subject, email string) error {
	otpCode, err := h.twoFactorService.OTP().Generate(ctx.Context(), ch, sub)
	if err != nil {
		return err
	}
	return mail.SendOTP(h.mailSender, email, otpCode)
}

func (h *TwoFactorHandler) handleChallengeEmailOTP(ctx *fiber.Ctx, pageData render.VerificationRequiredPageData, sub twofactor.Subject, callbackURL string, createCallback func(ch *twofactor.Challenge) error) error {
	otpCode, ch, err := h.twoFactorService.OTP().Create(ctx.Context(), sub, callbackURL, 5*time.Minute)
	if err != nil {
		if errMsg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = errMsg
			return render.RenderVerificationRequiredPage(ctx, pageData)
		}
		return err
	}
	if err := mail.SendOTP(h.mailSender, pageData.Email, otpCode); err != nil {
		pageData.ErrorMsg = "Failed to send email"
		return render.RenderVerificationRequiredPage(ctx, pageData)
	}
	if err := createCallback(ch); err != nil {
		return err
	}
	return redirect(ctx, "/2fa/otp/verify", "cid", ch.ID)
}

func (h *TwoFactorHandler) handleChallengeTOTP(ctx *fiber.Ctx, pageData render.VerificationRequiredPageData, sub twofactor.Subject, callbackURL string, createCallback func(ch *twofactor.Challenge) error) error {
	ch, err := h.twoFactorService.TOTP().Create(ctx.Context(), sub, callbackURL, 5*time.Minute)
	if err != nil {
		if errMsg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = errMsg
			return render.RenderVerificationRequiredPage(ctx, pageData)
		}
		return err
	}
	if err := createCallback(ch); err != nil {
		return err
	}
	return redirect(ctx, "/2fa/totp/verify", "cid", ch.ID)
}

func (h *TwoFactorHandler) handleChallengeSuccess(ctx *fiber.Ctx, session *sessions.Session, ch *twofactor.Challenge, sub twofactor.Subject) error {
	if session.TwoFARequired && session.TwoFAChallengeID == ch.ID {
		session.TwoFARequired = false
		session.TwoFASuccessAt = time.Now().UnixMilli()
	}
	return redirect(ctx, ch.CallbackURL, "cid", ch.ID)
}

func (h *TwoFactorHandler) PostChallenge(ctx *fiber.Ctx) error {
	encryptedState := ctx.Query("state")
	method := ctx.FormValue("method")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	if encryptedState == "" {
		return render.RenderNotFoundErrorPage(ctx)
	}
	var state TwoFactorState
	if err := decryptState(ctx, encryptedState, &state); err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}
	if time.Since(time.UnixMilli(state.Timestamp)) > 5*time.Minute {
		// TODO: if this is 2fa login, logout user when it's expired
		return render.RenderNotFoundErrorPage(ctx)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	pageData := render.VerificationRequiredPageData{
		EmailEnabled: true,
		Email:        user.Email,
		IsMasked:     true,
	}

	postCreateFunc := func(ch *twofactor.Challenge) error {
		if state.Action == "login" && session.TwoFARequired {
			session.TwoFAChallengeID = ch.ID
		}
		return nil
	}

	sub := getChallengeSubject(ctx, session)
	switch method {
	case "email":
		return h.handleChallengeEmailOTP(ctx, pageData, sub, state.CallbackURL, postCreateFunc)
	case "totp":
		return h.handleChallengeTOTP(ctx, pageData, sub, state.CallbackURL, postCreateFunc)
	default:
		pageData.ErrorMsg = MsgInvalid2FAMethod
		return render.RenderVerificationRequiredPage(ctx, pageData)
	}
}

func (h *TwoFactorHandler) GetVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}

	sub := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, sub, twofactor.ChallengeTypeOTP); err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}

	return h.renderVerifyOTP(ctx, user.Email, "")
}

func (h *TwoFactorHandler) PostVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	code := ctx.FormValue("code")
	resend := ctx.FormValue("resend") != ""

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	if !resend && code == "" {
		return h.renderVerifyOTP(ctx, user.Email, MsgOTPCodeEmpty)
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject, twofactor.ChallengeTypeOTP); err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}

	handleTwoFactorError := func(ctx *fiber.Ctx, err error) error {
		if errors.Is(err, twofactor.ErrChallengeSubjectMismatch) {
			return render.RenderNotFoundErrorPage(ctx)
		}
		if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
			if !session.IsAuthenticated() {
				return forceLogout(ctx, "tfa_failed")
			}
			return ctx.Redirect("/")
		}
		if msg, ok := mapTwoFactorError(err); ok {
			return h.renderVerifyOTP(ctx, user.Email, msg)
		}
		return err
	}

	if resend {
		err = h.generateAndSendEmailOTP(ctx, ch, subject, user.Email)
		if err != nil {
			return handleTwoFactorError(ctx, err)
		}
		return redirect(ctx, "/2fa/verify-otp", "cid", ch.ID)
	}

	if err := h.twoFactorService.OTP().Verify(ctx.Context(), ch, subject, code); err != nil {
		return handleTwoFactorError(ctx, err)
	}

	return h.handleChallengeSuccess(ctx, session, ch, subject)
}

func (h *TwoFactorHandler) generateTOTPEnrollmentURL(issuer string, username string, secret string) (string, error) {
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

func (h *TwoFactorHandler) GetTOTPEnroll(ctx *fiber.Ctx) error {
	renew := ctx.Query("renew")
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	var secret string
	err = session.GetAttr(ctx.Context(), totpEnrollSecretSessionKey, &secret)
	if err != nil || renew == "true" {
		secret = h.twoFactorService.TOTP().GenerateSecret()
		err := session.SetAttr(ctx.Context(), totpEnrollSecretSessionKey, secret)
		if err != nil {
			return err
		}
	}

	issuer := ctx.Locals("siteName").(string)
	enrollmentURL, err := h.generateTOTPEnrollmentURL(issuer, user.Username, secret)
	if err != nil {
		return err
	}

	pageData := render.TOTPEnrollmentPageData{
		SecretKey:     secret,
		EnrollmentURL: enrollmentURL,
	}
	return render.RenderTOTPEnrollmentPage(ctx, pageData)
}

func (h *TwoFactorHandler) PostTOTPEnroll(ctx *fiber.Ctx) error {
	code := ctx.FormValue("verificationCode")

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	var secret string
	err = session.GetAttr(context.Background(), totpEnrollSecretSessionKey, &secret)
	if err != nil || secret == "" {
		return ctx.Redirect(ctx.OriginalURL(), fiber.StatusFound)
	}

	err = h.twoFactorService.TOTP().Enroll(ctx.Context(), session.UserID, secret, code)
	if err != nil {
		if errors.Is(err, twofactor.ErrTOTPVerifyFailed) {
			errMsg := MsgTOTPEnrollFailed
			issuer := ctx.Locals("siteName").(string)
			enrollmentURL, err := h.generateTOTPEnrollmentURL(issuer, user.Username, secret)
			if err != nil {
				return err
			}
			pageData := render.TOTPEnrollmentPageData{
				SecretKey:     secret,
				EnrollmentURL: enrollmentURL,
				ErrorMsg:      errMsg,
			}
			return render.RenderTOTPEnrollmentPage(ctx, pageData)
		}
		return err
	}

	session.SetAttr(ctx.Context(), totpEnrollSecretSessionKey, "")
	return render.RenderTOTPEnrollSuccessPage(ctx)
}

func (h *TwoFactorHandler) GetTOTVerify(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}

	sub := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, sub, twofactor.ChallengeTypeTOTP); err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}

	return render.RenderVerifyTOTPPage(ctx, "")
}

func (h *TwoFactorHandler) PostTOTPVerify(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	code := ctx.FormValue("code")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	if code == "" {
		return render.RenderVerifyTOTPPage(ctx, MsgOTPCodeEmpty)
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject, twofactor.ChallengeTypeTOTP); err != nil {
		return render.RenderNotFoundErrorPage(ctx)
	}

	handleTwoFactorError := func(ctx *fiber.Ctx, err error) error {
		if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
			if !session.IsAuthenticated() {
				return forceLogout(ctx, "tfa_failed")
			}
		}
		if msg, ok := mapTwoFactorError(err); ok {
			return render.RenderVerifyTOTPPage(ctx, msg)
		}
		return err
	}

	if err := h.twoFactorService.TOTP().Verify(ctx.Context(), ch, subject, code); err != nil {
		return handleTwoFactorError(ctx, err)
	}

	return h.handleChallengeSuccess(ctx, session, ch, subject)
}

func isFactorEnabled(authFactors []*model.UserFactor, factorType string) bool {
	for _, factor := range authFactors {
		if factor.Type == factorType && factor.Enabled {
			return true
		}
	}
	return false
}

func (h *TwoFactorHandler) GetTwoFASettings(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
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

	pageData := render.TwoFASettingsPageData{
		Email:        user.Email,
		EmailEnabled: isFactorEnabled(authFactors, "email"),
		TOTPEnabled:  isFactorEnabled(authFactors, "totp"),
	}
	return render.Render2FASettingsPage(ctx, pageData)
}

func (h *TwoFactorHandler) PostTwoFASettings(ctx *fiber.Ctx) error {
	emailEnabled := ctx.FormValue("emailEnabled") == "true"
	totpEnabled := ctx.FormValue("totpEnabled") == "true"

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	err = h.userService.SetAuthFactorEnabled(ctx.Context(), session.UserID, users.AuthFactorEmail, emailEnabled)
	if err != nil {
		return err
	}

	err = h.userService.SetAuthFactorEnabled(ctx.Context(), session.UserID, users.AuthFactorTOTP, totpEnabled)
	if totpEnabled && errors.Is(err, users.ErrAuthFactorNotSetup) {
		return ctx.Redirect("/2fa/totp/enroll", fiber.StatusFound)
	}

	return ctx.Redirect(ctx.OriginalURL(), fiber.StatusFound)
}

func NewTwoFactorHandler(twoFactorService TwoFactorService, userService UserService, mailSender mail.MailSender) *TwoFactorHandler {
	return &TwoFactorHandler{
		twoFactorService: twoFactorService,
		userService:      userService,
		mailSender:       mailSender,
	}
}
