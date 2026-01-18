package api

import "github.com/gofiber/fiber/v2"

var (
	ErrInternalServer = &APIError{
		Code:    fiber.StatusInternalServerError,
		Message: "Internal server error",
	}
	ErrMissingParameters = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Missing required parameters",
	}
	ErrUnAuthorized = &APIError{
		Code:    fiber.StatusUnauthorized,
		Message: "Unauthorized",
	}
	ErrIncorrectPassword = &APIError{
		Code:    fiber.StatusUnauthorized,
		Message: "Invalid username or password",
	}
	ErrCaptchaVerificationFailed = &APIError{
		Code:    fiber.StatusUnauthorized,
		Message: "Captcha verification failed",
	}
)
