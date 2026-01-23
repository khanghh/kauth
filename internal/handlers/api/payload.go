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
	BirthDay    int64  `json:"birthDay,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Country     string `json:"country,omitempty"`
	TimeZone    string `json:"timeZone,omitempty"`
}
