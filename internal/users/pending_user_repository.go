package users

import (
	"context"
	"errors"
	"time"

	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
	"github.com/khanghh/kauth/params"
	"gorm.io/gen"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type PendingUserRepository interface {
	WithTx(tx *query.Query) PendingUserRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.PendingUser, error)
	Create(ctx context.Context, user *model.PendingUser) error
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
	Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error)
	CreateIfNotExists(ctx context.Context, user *model.PendingUser) (*model.PendingUser, error)
}

type pendingUserRepository struct {
	query *query.Query
}

func (r *pendingUserRepository) WithTx(tx *query.Query) PendingUserRepository {
	return NewPendingUserRepository(tx)
}

func (r *pendingUserRepository) First(ctx context.Context, conds ...gen.Condition) (*model.PendingUser, error) {
	return r.query.PendingUser.WithContext(ctx).Where(conds...).First()
}

func (r *pendingUserRepository) Create(ctx context.Context, user *model.PendingUser) error {
	return r.query.PendingUser.WithContext(ctx).Create(user)
}

func (r *pendingUserRepository) Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.PendingUser.WithContext(ctx).Where(conds...).Updates(columns)
}

func (r *pendingUserRepository) Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.PendingUser.WithContext(ctx).Where(conds...).Delete()
}

// CreateIfNotExists creates a pending user if there is no existing pending user, else returns the existing one with error.
func (r *pendingUserRepository) CreateIfNotExists(ctx context.Context, user *model.PendingUser) (*model.PendingUser, error) {
	var existing *model.PendingUser
	txErr := r.query.Transaction(func(tx *query.Query) error {
		var err error
		existing, err = tx.PendingUser.WithContext(ctx).Where(
			query.PendingUser.Where(query.PendingUser.Email.Eq(user.Email)).Or(query.PendingUser.Username.Eq(user.Username)),
			query.PendingUser.CreatedAt.Gt(time.Now().Add(-params.PendingUserExpiration)),
		).Take()
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if existing != nil {
			return ErrPendingUserExists
		}
		return tx.PendingUser.WithContext(ctx).
			Clauses(clause.OnConflict{
				UpdateAll: true,
				DoUpdates: clause.Assignments(map[string]interface{}{
					query.ColPendingUserCreatedAt: time.Now(),
					query.ColPendingUserUpdatedAt: time.Now(),
				}),
			}).
			Create(user)
	})
	return existing, txErr
}

func NewPendingUserRepository(query *query.Query) PendingUserRepository {
	return &pendingUserRepository{query}
}
