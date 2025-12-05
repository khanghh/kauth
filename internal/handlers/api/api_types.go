package api

type APIResponse struct {
	APIVersion string        `json:"apiVersion"`
	Data       any           `json:"data,omitempty"`
	Error      *APIErrorInfo `json:"error,omitempty"`
}

type APIErrorInfo struct {
	Code    int              `json:"code"`
	Message string           `json:"message"`
	Errors  []APIErrorDetail `json:"errors,omitempty"`
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

func NewErrorResponse(code int, message string, details ...APIErrorDetail) APIResponse {
	return APIResponse{
		APIVersion: "1.0",
		Error: &APIErrorInfo{
			Code:    code,
			Message: message,
			Errors:  details,
		},
	}
}

func NewErrorDetail(domain, reason, message string) APIErrorDetail {
	return APIErrorDetail{
		Domain:  domain,
		Reason:  reason,
		Message: message,
	}
}
