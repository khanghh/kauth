package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/khanghh/kauth/internal/store"
	"github.com/khanghh/kauth/internal/urlutil"
	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
	"github.com/khanghh/kauth/params"
	"gorm.io/gen"
	"gorm.io/gorm"
)

type ServiceRepository interface {
	WithTx(tx *query.Query) ServiceRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.Service, error)
	Create(ctx context.Context, service *model.Service) error
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
	Delete(ctx context.Context, conds ...gen.Condition) error
}

type ServiceTicket struct {
	TicketID    string    `json:"ticketID"    redis:"ticket_id"`
	UserID      uint      `json:"userID"      redis:"user_id"`
	ServiceName string    `json:"serviceName" redis:"service_name"`
	CallbackURL string    `json:"callbackURL" redis:"callback_url"`
	CreateTime  time.Time `json:"createTime"  redis:"create_time"`
	ExpiresAt   time.Time `json:"expiresAt"   redis:"expires_at"`
}

type AuthorizeService struct {
	masterKey   string
	serviceRepo ServiceRepository
	ticketStore store.Store[ServiceTicket]
}

func generateSecret(n int) (string, error) {
	// each 3 bytes → 4 Base64 chars
	rawSize := (n*3 + 3) / 4
	raw := make([]byte, rawSize)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	return secret[:n], nil
}

func (s *AuthorizeService) ValidateServiceTicket(ctx context.Context, serviceCallbackURL string, ticketID string) (*ServiceTicket, error) {
	ticket, err := s.ticketStore.Get(ctx, ticketID)
	if err != nil {
		return nil, ErrTicketNotFound
	}

	if time.Now().After(ticket.ExpiresAt) {
		return &ticket, ErrTicketExpired
	}

	if ticket.CallbackURL != serviceCallbackURL {
		return &ticket, ErrServiceMismatch
	}

	// Attempt to remove the ticket. If it doesn't exist, it has either expired or been used.
	if err := s.ticketStore.Delete(ctx, ticketID); err != nil {
		return &ticket, ErrTicketExpired
	}

	return &ticket, nil
}

func (s *AuthorizeService) GenerateServiceTicket(ctx context.Context, userId uint, serviceCallbackURL string) (*ServiceTicket, error) {
	cleanServiceURL := urlutil.RemoveQuery(serviceCallbackURL)
	svc, err := s.GetServiceByCallbackURL(ctx, cleanServiceURL)
	if err != nil {
		return nil, err
	}

	st := ServiceTicket{
		TicketID:    uuid.NewString(),
		UserID:      userId,
		ServiceName: svc.Name,
		CallbackURL: serviceCallbackURL,
		CreateTime:  time.Now(),
		ExpiresAt:   time.Now().Add(params.ServiceTicketExpiration),
	}

	err = s.ticketStore.Set(ctx, st.TicketID, st, params.ServiceTicketExpiration)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *AuthorizeService) RegisterService(ctx context.Context, service *model.Service) error {
	if service.Name == "" {
		return ErrServiceNameEmpty
	} else if service.CallbackURL == "" {
		return ErrServiceCallbackEmpty
	}

	service.ClientID = uuid.NewString()
	service.ClientSecret, _ = generateSecret(params.ServiceClientSecretLength)
	var mysqlErr *mysql.MySQLError
	if err := s.serviceRepo.Create(ctx, service); errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return ErrServiceAlreadyRegistered
	}
	return nil
}

func (s *AuthorizeService) GetServiceByID(ctx context.Context, serviceID uint) (*model.Service, error) {
	service, err := s.serviceRepo.First(ctx, query.Service.ID.Eq(serviceID))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrServiceNotFound
	}
	return service, err
}

func (s *AuthorizeService) GetServiceByCallbackURL(ctx context.Context, callbackURL string) (*model.Service, error) {
	service, err := s.serviceRepo.First(ctx, query.Service.CallbackURL.Eq(callbackURL))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrServiceNotFound
	}
	return service, nil
}

func (s *AuthorizeService) GetServiceByClientID(ctx context.Context, clientID string) (*model.Service, error) {
	service, err := s.serviceRepo.First(ctx, query.Service.ClientID.Eq(clientID))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrServiceNotFound
	}
	return service, err
}

func (s *AuthorizeService) DeleteService(ctx context.Context, serviceID uint) error {
	return s.serviceRepo.Delete(ctx, query.Service.ID.Eq(serviceID))
}

func NewAuthorizeService(masterKey string, storage store.Storage, serviceRepo ServiceRepository) *AuthorizeService {
	return &AuthorizeService{
		masterKey:   masterKey,
		serviceRepo: serviceRepo,
		ticketStore: store.New[ServiceTicket](storage, params.TicketKeyPrefix),
	}
}
