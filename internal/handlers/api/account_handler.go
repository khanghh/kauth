package api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/users"
)

type AccountHandler struct {
	userService *users.UserService
}

func (h *AccountHandler) Get(ctx *fiber.Ctx) error {
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

	return ctx.JSON(NewDataResponse(user))
}

func NewAccountHandler(userService *users.UserService) *AccountHandler {
	return &AccountHandler{
		userService: userService,
	}
}
