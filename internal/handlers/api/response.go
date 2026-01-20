package api

type userInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Picture  string `json:"picture,omitempty"`
}

type twoFactorMethod struct {
	Type   string `json:"type"`
	Target string `json:"target,omitempty"`
}

type loginResponse struct {
	User          userInfo          `json:"user"`
	TwoFARequired bool              `json:"twoFaRequired"`
	TwoFAMethods  []twoFactorMethod `json:"twoFaMethods,omitempty"`
}
