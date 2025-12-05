package auth

import "errors"

var (
	ErrTicketExpired            = errors.New("ticket expired")
	ErrTicketNotFound           = errors.New("ticket not found")
	ErrServiceMismatch          = errors.New("service url mismatch")
	ErrServiceNotFound          = errors.New("service not found")
	ErrServiceAlreadyRegistered = errors.New("service already registered")
	ErrServiceCredentials       = errors.New("invalid service credentials")
	ErrServiceNameEmpty         = errors.New("service name cannot be empty")
	ErrServiceCallbackEmpty     = errors.New("service callback cannot be empty")
)
