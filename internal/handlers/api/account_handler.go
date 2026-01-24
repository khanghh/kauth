package api

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/khanghh/kauth/internal/users"
	"github.com/khanghh/kauth/internal/validation"
	"golang.org/x/crypto/bcrypt"
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

func (h *AccountHandler) PostTwoFactorMethods(ctx *fiber.Ctx) error {
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
