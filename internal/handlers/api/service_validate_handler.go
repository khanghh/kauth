package api

import (
	"log"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/auth"
	"github.com/khanghh/kauth/internal/urlutil"
)

type ServiceValidateHandler struct {
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

type serviceValidateRequest struct {
	Service      string `json:"service" form:"service"`
	State        string `json:"state" form:"state"`
	Ticket       string `json:"ticket" form:"ticket"`
	ClientID     string `json:"clientId" form:"client_id"`
	ClientSecret string `json:"clientSecret" form:"client_secret"`
}

func (h *ServiceValidateHandler) PostServiceValidate(ctx *fiber.Ctx) error {
	var req serviceValidateRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(
			NewErrorResponse(fiber.StatusBadRequest, "Missing required parameters"),
		)
	}
	if req.ClientID == "" || req.ClientSecret == "" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(
			NewErrorResponse(fiber.StatusUnauthorized, "Unauthorized"),
		)
	}

	service, err := h.authorizeService.GetServiceByClientID(ctx.Context(), req.ClientID)
	if err != nil || service.ClientSecret != req.ClientSecret {
		return ctx.Status(fiber.StatusUnauthorized).JSON(
			NewErrorResponse(fiber.StatusUnauthorized, "Unauthorized"),
		)
	}

	if req.Ticket == "" || req.Service == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(
			NewErrorResponse(fiber.StatusBadRequest, "Missing required parameters"),
		)
	}

	callbackURL := urlutil.AppendQuery(req.Service, "state", req.State)
	ticket, err := h.authorizeService.ValidateServiceTicket(ctx.Context(), callbackURL, req.Ticket)
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

func NewServiceValidateHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService) *ServiceValidateHandler {
	return &ServiceValidateHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
