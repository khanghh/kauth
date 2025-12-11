package web

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/common"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
)

type State struct {
	Action      string
	RedirectURL string
	Service     string
	State       string
}

func init() {
	gob.Register(State{})
}

func getStateEncryptionKey(ctx *fiber.Ctx) string {
	session := sessions.Get(ctx)
	if session.SecretKey == "" {
		session.SecretKey, _ = common.GenerateSecret(32)
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

func encryptState(ctx *fiber.Ctx, state any) string {
	key := getStateEncryptionKey(ctx)
	blob, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	cipherBytes := xorBytes(blob, []byte(key))
	return base64.URLEncoding.EncodeToString([]byte(cipherBytes))
}

func decryptState(ctx *fiber.Ctx, encryted string, state any) error {
	key := getStateEncryptionKey(ctx)
	cipherBytes, err := base64.URLEncoding.DecodeString(encryted)
	if err != nil {
		return err
	}
	blob := xorBytes(cipherBytes, []byte(key))
	return json.Unmarshal(blob, state)
}

func marshalBase64(state any) (string, error) {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(state)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}

func unmarshalBase64(data string, state any) error {
	blob, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(blob)
	return gob.NewDecoder(buf).Decode(state)
}
