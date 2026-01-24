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
	ErrBadRequest = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Bad request",
	}
	ErrUnauthorized = &APIError{
		Code:    fiber.StatusUnauthorized,
		Message: "Unauthorized",
	}
	ErrCaptchaVerificationFailed = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Captcha verification failed",
	}
)

var (
	ErrIncorrectPassword = &APIError{
		Code:    fiber.StatusUnauthorized,
		Message: "Incorrect username or password",
	}
)

// Two-factor authentication errors
var (
	Err2FAInvalidChallengeRequest = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "The request is invalid or has expired.",
	}
	Err2FAInvalidChallengeMethod = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Invalid two-factor challenge method",
	}
	Err2FATooManyFailedAttempts = &APIError{
		Code:    fiber.StatusTooManyRequests,
		Message: "Too many failed attempts",
	}
	Err2FAOTPRequestLimitReached = &APIError{
		Code:    fiber.StatusTooManyRequests,
		Message: "OTP request limit reached",
	}

	Err2FAChallengeNotFound = &APIError{
		Code:    fiber.StatusNotFound,
		Message: "Challenge not found",
	}
	Err2FAChallengeExpired = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Challenge expired",
	}
	Err2FAChallengeAttemptsExceeded = &APIError{
		Code:    fiber.StatusTooManyRequests,
		Message: "Max challenge attempts exceeded",
	}
	Err2FAChallengeAlreadyVerified = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Challenge already verified",
	}
	Err2FAChallengeNotVerified = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Challenge not verified",
	}
	Err2FAChallengeSubjectMismatch = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Challenge subject mismatch",
	}
	Err2FAChallengeTypeMismatch = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Challenge type mismatch",
	}
	Err2FAInvalidFinalizeToken = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Invalid finalize token",
	}
	Err2FAUserChallengeRateLimited = &APIError{
		Code:    fiber.StatusTooManyRequests,
		Message: "Request rate limited",
	}
	Err2FATokenInvalid = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Invalid token",
	}
	Err2FATokenExpired = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "Token is expired",
	}
	Err2FAOTPCodeExpired = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "OTP code is expired",
	}
	Err2FAOTPRequestRateLimited = &APIError{
		Code:    fiber.StatusTooManyRequests,
		Message: "OTP request rate limited",
	}
	Err2FATOTPNotEnrolled = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "TOTP not enrolled",
	}
	Err2FATOTPVerifyFailed = &APIError{
		Code:    fiber.StatusBadRequest,
		Message: "TOTP verification failed",
	}
)
