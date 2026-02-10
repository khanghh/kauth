package users

import (
	"fmt"
	"testing"

	"github.com/khanghh/kauth/internal/testutils"
	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
)

func TestCreatePendingUser(t *testing.T) {
	db := testutils.MustInitDatabase()
	query.SetDefault(db)
	repo := NewPendingUserRepository(query.Q)
	pendingUser := &model.PendingUser{
		Email:       "bshieldios@gmail.com",
		Username:    "md_5",
		FullName:    "bbbbbb",
		Password:    "securepassword",
		ActiveToken: "activation",
	}
	_, err := repo.CreateIfNotExists(t.Context(), pendingUser)
	if err != nil {
		t.Fatalf("failed to create pending user: %v", err)
	}
	fmt.Println(pendingUser.ID)
}
