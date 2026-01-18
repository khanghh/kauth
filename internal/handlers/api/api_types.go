package api

type APIResponse struct {
	APIVersion string    `json:"apiVersion"`
	Data       any       `json:"data,omitempty"`
	Error      *APIError `json:"error,omitempty"`
}

type APIError struct {
	Code    int              `json:"code"`
	Message string           `json:"message"`
	Errors  []APIErrorDetail `json:"errors,omitempty"`
}

func (e *APIError) Error() string {
	return e.Message
}

func NewAPIError(code int, message string, details ...APIErrorDetail) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Errors:  details,
	}
}

type APIErrorDetail struct {
	Domain  string `json:"domain"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func NewDataResponse(data any) APIResponse {
	return APIResponse{
		APIVersion: "1.0",
		Data:       data,
	}
}

func NewErrorResponse(err error) APIResponse {
	apiErr, ok := err.(*APIError)
	if !ok {
		apiErr = ErrInternalServer
	}
	return APIResponse{
		APIVersion: "1.0",
		Error:      apiErr,
	}
}

func NewErrorDetail(domain, reason, message string) APIErrorDetail {
	return APIErrorDetail{
		Domain:  domain,
		Reason:  reason,
		Message: message,
	}
}
