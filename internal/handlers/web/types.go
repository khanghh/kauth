package web

import (
	"context"
	"time"

	"github.com/khanghh/kauth/internal/auth"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/khanghh/kauth/internal/users"
	"github.com/khanghh/kauth/model"
)

type AuthorizeService interface {
	RegisterService(ctx context.Context, service *model.Service) error
	GetServiceByNameOrURL(ctx context.Context, nameOrURL string) (*model.Service, error)
	GetServiceByClientID(ctx context.Context, clientID string) (*model.Service, error)
	DeleteService(ctx context.Context, serviceID uint) error
	GenerateServiceTicket(ctx context.Context, userID uint, callbackURL string) (*auth.ServiceTicket, error)
	ValidateServiceTicket(ctx context.Context, serviceURL string, ticketId string) (*auth.ServiceTicket, error)
}

type TwoFactorService interface {
	GetChallenge(ctx context.Context, cid string) (*twofactor.Challenge, error)
	CreateChallenge(ctx context.Context, sub twofactor.Subject, callbackURL string, expiresIn time.Duration) (*twofactor.Challenge, error)
	ValidateChallenge(ctx context.Context, ch *twofactor.Challenge, sub twofactor.Subject, chType string) error
	FinalizeChallenge(ctx context.Context, cid string, sub twofactor.Subject, callbackURL string) error
	IsTwoFAEnabled(ctx context.Context, uid uint) (bool, error)
	CalculateHash(inputs ...interface{}) string
	OTP() *twofactor.OTPChallenger
	TOTP() *twofactor.TOTPChallenger
	JWT() *twofactor.JWTChallenger
	Token() *twofactor.TokenChallenger
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
	CreateUser(ctx context.Context, opts users.CreateUserOptions) (*model.User, error)
	RegisterUser(ctx context.Context, opts users.CreateUserOptions) (*model.PendingUser, error)
	ApprovePendingUser(ctx context.Context, email string, token string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error)
	GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error)
	GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
	UpdatePassword(ctx context.Context, email string, newPassword string) error
	GetAuthFactors(ctx context.Context, userID uint) ([]*model.UserFactor, error)
	SetAuthFactorEnabled(ctx context.Context, userID uint, factorType users.AuthFactor, enabled bool) error
}
