package middlewares

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/render"
)

func ErrorHandler(ctx *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	switch code {
	case fiber.StatusBadRequest:
		return render.RenderBadRequestErrorPage(ctx)
	case fiber.StatusForbidden:
		return render.RenderForbiddenErrorPage(ctx)
	case fiber.StatusNotFound, fiber.StatusMethodNotAllowed:
		return render.RenderNotFoundErrorPage(ctx)
	default:
		slog.Error("unhandled error", "path", ctx.Path(), "code", code, "error", err)
		return render.RenderInternalServerErrorPage(ctx)
	}
}
