package common

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/params"
)

func randomNonce(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func CreateNonce(ctx context.Context, session *sessions.Session, data string) (string, error) {
	nonce := randomNonce(16)
	nonceHash := CalculateHash(session.SecretKey, data, nonce)
	field := fmt.Sprintf("nonce:%s", nonce)
	err := session.SetField(ctx, field, nonceHash, params.NonceExpiration)
	if err != nil {
		return "", err
	}
	return nonce, err
}

func CheckNonce(ctx context.Context, session *sessions.Session, data string, nonce string) (bool, error) {
	hash := CalculateHash(session.SecretKey, data, nonce)
	field := fmt.Sprintf("nonce:%s", nonce)
	var expectedHash string
	err := session.GetField(ctx, field, &expectedHash)
	return expectedHash == hash, err
}

func DeleteNonce(ctx context.Context, session *sessions.Session, nonce string) error {
	field := fmt.Sprintf("nonce:%s", nonce)
	return session.DeleteField(ctx, field)
}
