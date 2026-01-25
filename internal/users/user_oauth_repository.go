package users

import (
	"context"

	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
	"gorm.io/gen"
	"gorm.io/gorm/clause"
)

type UserOAuthRepository interface {
	WithTx(tx *query.Query) UserOAuthRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error)
	Take(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error)
	Upsert(ctx context.Context, userOAuth *model.UserOAuth) error
	Updates(ctx context.Context, updates map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
	Find(ctx context.Context, conds ...gen.Condition) ([]*model.UserOAuth, error)
	Delete(ctx context.Context, conds ...gen.Condition) (bool, error)
	CreateIfNotExists(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}

type userOAuthRepository struct {
	query *query.Query
}

func (r *userOAuthRepository) First(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error) {
	return r.query.UserOAuth.WithContext(ctx).Where(conds...).First()
}

func (r *userOAuthRepository) Take(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error) {
	return r.query.UserOAuth.WithContext(ctx).Where(conds...).Take()
}

func (r *userOAuthRepository) WithTx(tx *query.Query) UserOAuthRepository {
	return NewUserOAuthRepository(tx)
}

func (r *userOAuthRepository) Upsert(ctx context.Context, userOAuth *model.UserOAuth) error {
	return r.query.UserOAuth.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Returning(&userOAuth).
		Create(userOAuth)
}

func (r *userOAuthRepository) Updates(ctx context.Context, updates map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.UserOAuth.WithContext(ctx).Where(conds...).Updates(updates)
}

func (r *userOAuthRepository) CreateIfNotExists(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error) {
	err := r.query.UserOAuth.WithContext(ctx).
		Clauses(clause.OnConflict{
			DoUpdates: clause.Assignments(map[string]interface{}{
				query.ColUserOAuthDisplayName: userOAuth.DisplayName,
				query.ColUserOAuthEmail:       userOAuth.Email,
				query.ColUserOAuthPicture:     userOAuth.Picture,
				query.ColUserOAuthDeletedAt:   nil,
			}),
		}).
		Create(userOAuth)
	if err != nil {
		return nil, err
	}

	return r.Take(ctx, r.query.UserOAuth.AccountID.Eq(userOAuth.AccountID))
}

func (r *userOAuthRepository) Find(ctx context.Context, conds ...gen.Condition) ([]*model.UserOAuth, error) {
	return r.query.UserOAuth.WithContext(ctx).Where(conds...).Find()
}

func (r *userOAuthRepository) Delete(ctx context.Context, conds ...gen.Condition) (bool, error) {
	ret, err := r.query.UserOAuth.WithContext(ctx).Where(conds...).Delete()
	if err != nil {
		return false, err
	}
	if ret.RowsAffected == 0 {
		return false, nil
	}
	return true, nil
}

func NewUserOAuthRepository(query *query.Query) UserOAuthRepository {
	return &userOAuthRepository{query}
}
