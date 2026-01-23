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
	BirthDate   int64  `json:"birthDate,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Country     string `json:"country,omitempty"`
	TimeZone    string `json:"timeZone,omitempty"`
}
