package api

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/users"
	"golang.org/x/crypto/bcrypt"
)

type AccountHandler struct {
	userService      UserService
	twofactorService TwoFactorService
}

// GetAccountInfo handles GET /api/account
// Returns basic account information of the authenticated user.
func (h *AccountHandler) GetAccountInfo(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnAuthorized
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		if err == users.ErrUserNotFound {
			return ErrUnAuthorized
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

// GetProfile handles GET /api/account/profile
// Returns detailed profile information of the authenticated user.
func (h *AccountHandler) GetProfile(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnAuthorized
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		if err == users.ErrUserNotFound {
			return ErrUnAuthorized
		}
	}
	return ctx.JSON(
		NewDataResponse(userProfileResponse{
			ID:          fmt.Sprint(user.ID),
			Username:    user.Username,
			FullName:    user.FullName,
			Email:       user.Email,
			Picture:     user.Picture,
			BirthDay:    user.BirthDay.UnixMilli(),
			PhoneNumber: user.PhoneNumber,
			Country:     user.Country,
		}),
	)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (h *AccountHandler) PostChangePassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session == nil || !session.IsAuthenticated() {
		return ErrUnAuthorized
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
			return ErrUnAuthorized
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

func NewAccountHandler(userService UserService, twofactorService TwoFactorService) *AccountHandler {
	return &AccountHandler{
		userService:      userService,
		twofactorService: twofactorService,
	}
}
