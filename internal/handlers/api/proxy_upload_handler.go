package api

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

type ProxyUploadHandler struct {
	targetURL string
	token     string
}

// PostUpload forwards the incoming upload request to an external upload service
// and returns the service response body (for example, an uploaded file URL).
func (h *ProxyUploadHandler) PostUpload(ctx *fiber.Ctx) error {
	body := ctx.Body()

	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodPost, h.targetURL, bytes.NewReader(body))
	if err != nil {
		return ErrUploadServiceUnavailable
	}

	if ct := ctx.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}

	req.Header.Set("Authorization", "Bearer "+h.token)
	// Perform the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ErrUploadServiceUnavailable
	}
	defer resp.Body.Close()

	// Copy response status and headers
	ctx.Status(resp.StatusCode)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		ctx.Set("Content-Type", ct)
	}

	// Stream response body back to client
	if _, err := io.Copy(ctx.Response().BodyWriter(), resp.Body); err != nil {
		return ErrUploadServiceUnavailable
	}

	return nil
}

func NewProxyUploadHandler(targetURL string, token string) *ProxyUploadHandler {
	return &ProxyUploadHandler{
		targetURL: targetURL,
		token:     token,
	}
}
