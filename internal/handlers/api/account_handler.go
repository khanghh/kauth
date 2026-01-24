package api

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/khanghh/kauth/internal/users"
	"github.com/khanghh/kauth/internal/validation"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	totpEnrollSecretSessionKey = "_totp_enroll_secret"
)

type AccountHandler struct {
	userService      UserService
	twofactorService TwoFactorService
}

func NewAccountHandler(userService UserService, twofactorService TwoFactorService) *AccountHandler {
	return &AccountHandler{
		userService:      userService,
		twofactorService: twofactorService,
	}
}

// GetAccountInfo handles GET /api/account
// Returns basic account information of the authenticated user.
func (h *AccountHandler) GetAccountInfo(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		if err == users.ErrUserNotFound {
			return ErrUnauthorized
		}
		return ErrInternalServer
	}

	return ctx.JSON(
		NewDataResponse(userInfoResponse{
			ID:       fmt.Sprint(user.ID),
			Username: user.Username,
			FullName: user.FullName,
			Email:    user.Email,
			Picture:  user.Picture,
		}),
	)
}

// GetPersonalInfo handles GET /api/account/profile
// Returns detailed profile information of the authenticated user.
func (h *AccountHandler) GetPersonalInfo(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		if err == users.ErrUserNotFound {
			return ErrUnauthorized
		}
	}

	birthdayUnix := int64(0)
	if user.Birthday != nil {
		birthdayUnix = user.Birthday.Unix()
	}
	return ctx.JSON(
		NewDataResponse(userProfileResponse{
			ID:          fmt.Sprint(user.ID),
			Username:    user.Username,
			FullName:    user.FullName,
			Email:       user.Email,
			Picture:     user.Picture,
			Birthday:    birthdayUnix,
			PhoneNumber: user.PhoneNumber,
			Country:     user.Country,
		}),
	)
}

type updatePersonalInfoRequest struct {
	FullName    *string `json:"fullName"`
	Birthday    *int64  `json:"birthday"` // unix timestamp in seconds
	Gender      *string `json:"gender"`
	PhoneNumber *string `json:"phoneNumber"`
	Country     *string `json:"country"`
}

func validatePersonalInfoUpdates(req updatePersonalInfoRequest) (users.PersonalInfoUpdate, error) {
	empty := users.PersonalInfoUpdate{}
	updates := users.PersonalInfoUpdate{}
	if req.FullName != nil {
		if err := validation.ValidateFullName(*req.FullName); err != nil {
			return empty, err
		}
		updates.FullName = req.FullName
	}

	if req.Birthday != nil {
		if err := validation.ValidateBirthday(*req.Birthday); err != nil {
			return empty, err
		}
		birthday := time.Unix(*req.Birthday, 0)
		updates.Birthday = &birthday
	}

	if req.Gender != nil {
		gender := *req.Gender
		if gender != string(users.GenderMale) &&
			gender != string(users.GenderFemale) &&
			gender != string(users.GenderUnspecified) {
			return empty, fmt.Errorf("Invalid gender value.")
		}
		updates.Gender = (*users.Gender)(req.Gender)
	}

	if req.PhoneNumber != nil {
		if err := validation.ValidatePhoneNumber(*req.PhoneNumber); err != nil {
			return empty, err
		}
		updates.PhoneNumber = req.PhoneNumber
	}

	if req.Country != nil {
		if err := validation.ValidateCountryCode(*req.Country); err != nil {
			return empty, err
		}
		updates.Country = req.Country
	}

	return updates, nil
}

// PostPersonalInfo handles PATCH /api/account/personal-info
// Updates the personal info of the authenticated user.
func (h *AccountHandler) PatchPersonalInfo(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}
	var req updatePersonalInfoRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ErrMissingParameters
	}

	updates, err := validatePersonalInfoUpdates(req)
	if err != nil {
		return NewAPIError(fiber.StatusBadRequest, err.Error())
	}

	err = h.userService.UpdatePersonalInfo(ctx.Context(), session.UserID, updates)
	if err != nil {
		if err == users.ErrUserNotFound {
			return ErrUnauthorized
		}
		return ErrInternalServer
	}

	return ctx.SendStatus(fiber.StatusOK)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (h *AccountHandler) PostChangePassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}

	var req changePasswordRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ErrMissingParameters
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		return ErrMissingParameters
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		if err == users.ErrUserNotFound {
			return ErrUnauthorized
		}
		return ErrInternalServer
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword))
	if err != nil {
		return ErrIncorrectPassword
	}

	err = h.userService.UpdatePassword(ctx.Context(), user.ID, req.NewPassword)
	if err != nil {
		return ErrInternalServer
	}
	return ctx.SendStatus(fiber.StatusOK)
}

func (h *AccountHandler) GetTwoFactorMethods(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		if err == users.ErrUserNotFound {
			return ErrUnauthorized
		}
		return ErrInternalServer
	}

	factors, err := h.twofactorService.GetAllAuthFactors(ctx.Context(), session.UserID)
	if err != nil {
		return ErrInternalServer
	}

	methods := make([]twoFactorMethodResponse, 0, len(factors))
	for _, factor := range factors {
		method := twoFactorMethodResponse{
			Type:    factor.Type,
			Enabled: factor.Enabled,
		}
		if factor.Type == "email" {
			method.Email = user.Email
		} else if factor.Type == "sms" {
			method.Phone = user.PhoneNumber
		}
		methods = append(methods, method)
	}

	return ctx.JSON(NewDataResponse(methods))
}

func (h *AccountHandler) PatchTwoFactorMethod(ctx *fiber.Ctx) error {
	method := ctx.Params("method")

	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return ErrUnauthorized
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := ctx.BodyParser(&req); err != nil {
		return ErrMissingParameters
	}

	err = h.twofactorService.SetAuthFactorEnabled(ctx.Context(), session.UserID, method, req.Enabled)
	if err != nil {
		switch err {
		case twofactor.ErrTOTPNotEnrolled:
			return Err2FATOTPNotEnrolled
		case twofactor.ErrAuthMethodNotSupported:
			return Err2FAInvalidChallengeMethod
		}
		return err
	}

	return ctx.SendStatus(fiber.StatusOK)
}

// GenerateBase32TOTPSecret generates a RFC-compatible TOTP secret.
// - 20 bytes raw (160 bits)
// - 32 Base32 characters
// - No padding (Authenticator-friendly)
func generateTOTPSecret() string {
	raw := make([]byte, 20) // 160-bit secret (RFC 4226 / 6238)
	rand.Read(raw)

	secret := base32.StdEncoding.
		WithPadding(base32.NoPadding).
		EncodeToString(raw)

	return secret
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

type enrollTOTPResponse struct {
	EnrollmentURL string `json:"enrollmentUrl"`
	Secret        string `json:"secret"`
}

func (h *AccountHandler) GetTwoFactorTOTPEnroll(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return ErrUnauthorized
	}

	secret := generateTOTPSecret()
	err = session.SetField(ctx.Context(), totpEnrollSecretSessionKey, secret, 15*time.Minute)
	if err != nil {
		return err
	}

	issuer, _ := render.GetValue("siteName").(string)
	enrollmentURL, err := h.generateTOTPEnrollmentURL(issuer, user.Username, secret)
	if err != nil {
		return err
	}

	return ctx.JSON(NewDataResponse(enrollTOTPResponse{
		EnrollmentURL: enrollmentURL,
		Secret:        secret,
	}))
}

func (h *AccountHandler) PostTwoFactorTOTPEnroll(ctx *fiber.Ctx) error {
	var req struct {
		Code string `json:"code"`
	}

	if err := ctx.BodyParser(&req); err != nil || req.Code == "" {
		return ErrMissingParameters
	}

	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnauthorized
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return ErrUnauthorized
	}

	var secret string
	err = session.GetField(context.Background(), totpEnrollSecretSessionKey, &secret)
	if err != nil || secret == "" {
		return ErrUnauthorized
	}

	err = h.twofactorService.TOTP().Enroll(ctx.Context(), session.UserID, secret, req.Code)
	if err != nil {
		if err == twofactor.ErrTOTPVerifyFailed {
			return Err2FATOTPVerifyFailed
		}
		return err
	}

	session.DeleteField(ctx.Context(), totpEnrollSecretSessionKey)
	return ctx.SendStatus(fiber.StatusOK)
}
