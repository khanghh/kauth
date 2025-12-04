package api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/urlutil"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

func (h *AuthHandler) GetServiceValidate(ctx *fiber.Ctx) error {
	ticketID := ctx.Query("ticket")
	serviceURL := urlutil.SanitizeURL(ctx.Query("service"))
	signature := string(ctx.Request().Header.Peek("X-Signature"))
	timestamp := string(ctx.Request().Header.Peek("X-Timestamp"))

	if ticketID == "" || serviceURL == "" || signature == "" || timestamp == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(APIResponse{
			Error: &APIErrorInfo{
				Code:    fiber.StatusBadRequest,
				Message: "missing required parameter",
			},
		})
	}

	ticket, err := h.authorizeService.ValidateServiceTicket(ctx.Context(), serviceURL, ticketID, timestamp, signature)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(APIResponse{
			Error: &APIErrorInfo{
				Code:    fiber.StatusUnauthorized,
				Message: err.Error(),
			},
		})
	}

	user, err := h.userService.GetUserByID(ctx.Context(), ticket.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(APIResponse{
			Error: &APIErrorInfo{
				Code:    fiber.StatusUnauthorized,
				Message: err.Error(),
			},
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(APIResponse{
		Data: UserInfoResponse{
			UserID:   user.ID,
			Username: user.Username,
			FullName: user.FullName,
			Email:    user.Email,
			Picture:  user.Picture,
		},
	})
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
