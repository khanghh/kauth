package api

type userInfoResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Picture  string `json:"picture,omitempty"`
}

type userProfileResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	FullName    string `json:"fullName"`
	Email       string `json:"email"`
	Picture     string `json:"picture,omitempty"`
	Birthday    int64  `json:"birthday,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Country     string `json:"country,omitempty"`
	TimeZone    string `json:"timeZone,omitempty"`
}

type twoFactorMethodResponse struct {
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	Email   string `json:"email,omitempty"`
	Phone   string `json:"phone,omitempty"`
}
