package upload

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

var (
	ErrUploadServerUnavailable = fmt.Errorf("upload server unavailable")
)

type Uploader interface {
	Upload(ctx context.Context, filename string, reader io.Reader) (string, error)
}

type ProxyUploader struct {
	uploadURL string
	token     string
	client    *http.Client
}

func (u *ProxyUploader) Upload(ctx context.Context, fileName string, stream io.Reader) (string, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	// writer goroutine: write the multipart content and stream the file
	go func() {
		defer func() {
			mw.Close()
			pw.Close()
		}()
		part, err := mw.CreateFormFile("file", fileName)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, stream); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	proxiedReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.uploadURL, pr)
	if err != nil {
		return "", ErrUploadServerUnavailable
	}

	proxiedReq.Header.Del("Host")
	proxiedReq.Header.Set("Authorization", "Bearer "+u.token)
	proxiedReq.Header.Set("Content-Type", contentType)

	resp, err := u.client.Do(proxiedReq)
	if err != nil {
		return "", ErrUploadServerUnavailable
	}
	defer resp.Body.Close()

	var ret struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ErrUploadServerUnavailable
	}

	if err := json.Unmarshal(respBody, &ret); err != nil {
		return "", ErrUploadServerUnavailable
	}

	if resp.StatusCode != http.StatusCreated {
		if ret.Error.Message != "" {
			return "", fmt.Errorf("upload error: %s", ret.Error.Message)
		}
		return "", ErrUploadServerUnavailable
	}

	return ret.Data.URL, nil
}

func NewProxyUploader(uploadURL string, token string) *ProxyUploader {
	return &ProxyUploader{
		uploadURL: uploadURL,
		token:     token,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}
