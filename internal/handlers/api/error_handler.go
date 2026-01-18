package api

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

func ErrorHandler(ctx *fiber.Ctx, err error) error {
	if apiErr, ok := err.(*APIError); ok {
		return ctx.Status(apiErr.Code).
			JSON(NewErrorResponse(apiErr))
	}

	if e, ok := err.(*fiber.Error); ok {
		return ctx.Status(e.Code).JSON(
			NewErrorResponse(&APIError{
				Code:    e.Code,
				Message: e.Message,
			}),
		)
	}

	slog.Error(
		"Unhandled error",
		"error", err,
		"method", ctx.Method(),
		"path", ctx.OriginalURL(),
		"ip", ctx.IP(),
	)
	return ctx.Status(fiber.StatusInternalServerError).JSON(
		NewErrorResponse(ErrInternalServer),
	)
}
