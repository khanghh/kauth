package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"

	"github.com/khanghh/kauth/internal/common"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/params"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)

func validateUsername(username string) error {
	if username == "" {
		return errors.New("Username is required.")
	}
	if len(username) < 4 {
		return errors.New("Username must be at least 4 characters.")
	}
	if len(username) > 32 {
		return errors.New("Username must be less than 32 characters.")
	}
	if first := username[0]; !(('A' <= first && first <= 'Z') || ('a' <= first && first <= 'z')) {
		return errors.New("Username must start with a letter.")
	}
	if !usernameRegex.MatchString(username) {
		return errors.New("Username can only contain letters, numbers, and underscores.")
	}
	return nil
}

func validateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("Invalid email address.")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 6 {
		return errors.New("Password must be at least 6 characters.")
	}
	return nil
}

func randomNonce(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func createNonce(ctx context.Context, session *sessions.Session, data string) (string, error) {
	nonce := randomNonce(16)
	nonceHash := common.CalculateHash(session.SecretKey, data, nonce)
	field := fmt.Sprintf("nonce:%s", nonce)
	err := session.SetField(ctx, field, nonceHash, params.NonceExpiration)
	if err != nil {
		return "", err
	}
	return nonce, err
}

func checkNonce(ctx context.Context, session *sessions.Session, data string, nonce string) (bool, error) {
	hash := common.CalculateHash(session.SecretKey, data, nonce)
	field := fmt.Sprintf("nonce:%s", nonce)
	var expectedHash string
	err := session.GetField(ctx, field, &expectedHash)
	return expectedHash == hash, err
}

func deleteNonce(ctx context.Context, session *sessions.Session, nonce string) error {
	field := fmt.Sprintf("nonce:%s", nonce)
	return session.DeleteField(ctx, field)
}
