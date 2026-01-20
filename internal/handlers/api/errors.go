package api

import (
	"github.com/gofiber/fiber/v2"
)

// General API errors
var (
	ErrInternalServer = &APIError{
		Code:    fiber.StatusInternalServerError,
		Message: "Internal server error",
	}
	ErrMissingParameters = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Missing required parameters",
	}
	ErrCaptchaVerificationFailed = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Captcha verification failed",
	}
)

// Authentication errors
var (
	ErrUnauthorized = &APIError{
		Code:    fiber.StatusUnauthorized,
		Message: "Unauthorized",
	}
	ErrAlreadyLoggedIn = &APIError{
		Code:    fiber.StatusConflict,
		Message: "Already logged in",
	}
	ErrIncorrectPassword = &APIError{
		Code:    fiber.StatusUnauthorized,
		Message: "Invalid username or password",
	}
)
