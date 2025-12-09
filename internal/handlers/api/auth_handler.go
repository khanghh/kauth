package api

import (
	"log"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/auth"
	"github.com/khanghh/kauth/internal/urlutil"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

type userInfoResponse struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Picture  string `json:"picture,omitempty"`
}

type authenticationSuccess struct {
	User         userInfoResponse `json:"user"`
	AccessToken  string           `json:"accessToken,omitempty"`
	RefreshToken string           `json:"refreshToken,omitempty"`
}

type authenticationFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type casValidateResponse struct {
	Success *authenticationSuccess `json:"authenticationSuccess,omitempty"`
	Failure *authenticationFailure `json:"authenticationFailure,omitempty"`
}

func (h *AuthHandler) PostServiceValidate(ctx *fiber.Ctx) error {
	ticketID := ctx.FormValue("ticket")
	serviceURL := urlutil.RemoveQuery(ctx.FormValue("service"))
	clientID := ctx.FormValue("client_id")
	clientSecret := ctx.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		return ctx.SendStatus(fiber.StatusUnauthorized)
	}

	service, err := h.authorizeService.GetServiceByClientID(ctx.Context(), clientID)
	if err != nil || service.ClientSecret != clientSecret {
		return ctx.SendStatus(fiber.StatusUnauthorized)
	}

	if ticketID == "" || serviceURL == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(
			NewErrorResponse(fiber.StatusBadRequest, "Missing required parameters"),
		)
	}

	ticket, err := h.authorizeService.ValidateServiceTicket(ctx.Context(), serviceURL, ticketID)
	if err != nil {
		var failure *authenticationFailure
		switch err {
		case auth.ErrTicketNotFound:
			failure = &authenticationFailure{
				Code:    "TICKET_NOT_FOUND",
				Message: "Ticket not found.",
			}
		case auth.ErrTicketExpired:
			failure = &authenticationFailure{
				Code:    "TICKET_EXPIRED",
				Message: "Ticket expired.",
			}
		case auth.ErrServiceMismatch:
			failure = &authenticationFailure{
				Code:    "SERVICE_MISMATCH",
				Message: "Service URL mismatch.",
			}
		default:
			log.Println("Validate service ticket error:", err)
			return ctx.Status(fiber.StatusInternalServerError).JSON(
				NewErrorResponse(fiber.StatusInternalServerError, "Internal server error"),
			)
		}

		return ctx.Status(fiber.StatusOK).JSON(
			NewDataResponse(casValidateResponse{Failure: failure}),
		)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), ticket.UserID)
	if err != nil {
		log.Printf("Failed to get user %d: %v", ticket.UserID, err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(
			NewErrorResponse(fiber.StatusInternalServerError, "Internal server error"),
		)
	}

	userInfo := userInfoResponse{
		UserID:   strconv.FormatUint(uint64(user.ID), 10),
		Username: user.Username,
		FullName: user.FullName,
		Email:    user.Email,
		Picture:  user.Picture,
	}

	return ctx.Status(fiber.StatusOK).JSON(
		NewDataResponse(casValidateResponse{
			Success: &authenticationSuccess{
				User: userInfo,
			},
		}),
	)
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
