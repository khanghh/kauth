package api

import (
	"strconv"

	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/model"
)

var ()

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

type loginRequest struct {
	Username     string `json:"username" form:"username"`
	Password     string `json:"password" form:"password"`
	ClientID     string `json:"clientId" form:"client_id"`
	ClientSecret string `json:"clientSecret" form:"client_secret"`
}

func get2FAMethods(user *model.User, factors []*model.UserFactor) []twoFactorMethod {
	methods := make([]twoFactorMethod, 0, len(factors))
	for _, factor := range factors {
		var target string
		if factor.Type == "email" {
			target = render.MaskEmail(user.Email)
		}
		methods = append(methods, twoFactorMethod{
			Type:   factor.Type,
			Target: target,
		})
	}
	return methods
}

func toLoginUserInfo(user *model.User) userInfo {
	return userInfo{
		ID:       strconv.FormatUint(uint64(user.ID), 10),
		Username: user.Username,
		FullName: user.FullName,
		Email:    user.Email,
		Picture:  user.Picture,
	}
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
