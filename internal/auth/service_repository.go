package auth

import (
	"context"

	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
	"gorm.io/gen"
)

type serviceRepository struct {
	query *query.Query
}

func (r *serviceRepository) WithTx(tx *query.Query) ServiceRepository {
	return NewServiceRepository(tx)
}

func (r *serviceRepository) First(ctx context.Context, conds ...gen.Condition) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(conds...).First()
}

func (r *serviceRepository) Create(ctx context.Context, service *model.Service) error {
	return r.query.Service.WithContext(ctx).Create(service)
}

func (r *serviceRepository) Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.Service.WithContext(ctx).Where(conds...).Updates(columns)
}

func (r *serviceRepository) Delete(ctx context.Context, conds ...gen.Condition) error {
	_, err := r.query.Service.WithContext(ctx).Where(conds...).Delete()
	return err
}

func (r *serviceRepository) GetServiceByCallbackURL(ctx context.Context, callbackURL string) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(r.query.Service.LoginURL.Eq(callbackURL)).First()
}

func (r *serviceRepository) GetServiceByClientID(ctx context.Context, clientID string) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(r.query.Service.ClientID.Eq(clientID)).First()
}

func NewServiceRepository(query *query.Query) ServiceRepository {
	return &serviceRepository{
		query: query,
	}
}
