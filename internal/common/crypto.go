package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func CalculateHash(key string, inputs ...interface{}) string {
	if len(inputs) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, []byte(key))
	for _, val := range inputs {
		switch v := val.(type) {
		case []byte:
			h.Write(v)
		default:
			h.Write([]byte(fmt.Sprintf("%v", v)))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateSecret(n int) (string, error) {
	// each 3 bytes → 4 Base64 chars
	rawSize := (n*3 + 3) / 4
	raw := make([]byte, rawSize)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	return secret[:n], nil
}
