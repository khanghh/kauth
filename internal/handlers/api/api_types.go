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

type UserInfoResponse struct {
	UserID   uint   `json:"userId"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Picture  string `json:"picture,omitempty"`
}
