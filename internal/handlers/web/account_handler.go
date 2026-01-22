package web

import (
	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/render"
)

type AccountHandler struct {
	userService      UserService
	twoFactorService TwoFactorService
}

func (h *AccountHandler) GetHomePage(ctx *fiber.Ctx) error {
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

func NewAccountHandler(userService UserService, twoFactorService TwoFactorService) *AccountHandler {
	return &AccountHandler{
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
