package common

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
)

type State struct {
	Action      string
	RedirectURL string
	Service     string
	State       string
}

type OAuthLoginState struct {
	Service string
	State   string
}

func init() {
	gob.Register(State{})
}

func getStateEncryptionKey(ctx *fiber.Ctx) string {
	session := sessions.Get(ctx)
	if session.SecretKey == "" {
		session.SecretKey, _ = GenerateSecret(32)
	}
	return session.SecretKey
}

func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func EncryptState(ctx *fiber.Ctx, state any) string {
	key := getStateEncryptionKey(ctx)
	blob, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	cipherBytes := xorBytes(blob, []byte(key))
	return base64.RawURLEncoding.EncodeToString([]byte(cipherBytes))
}

func DecryptState(ctx *fiber.Ctx, encryted string, state any) error {
	key := getStateEncryptionKey(ctx)
	cipherBytes, err := base64.RawURLEncoding.DecodeString(encryted)
	if err != nil {
		return err
	}
	blob := xorBytes(cipherBytes, []byte(key))
	return json.Unmarshal(blob, state)
}

func MarshalBase64(state any) (string, error) {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(state)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func UnmarshalBase64(data string, state any) error {
	blob, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(blob)
	return gob.NewDecoder(buf).Decode(state)
}
