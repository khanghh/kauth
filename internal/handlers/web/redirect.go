package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
)

func redirect(ctx *fiber.Ctx, location string, values ...any) error {
	url, err := url.Parse(location)
	if err != nil {
		return err
	}

	query := url.Query()
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			slog.Error("invalid query parameter", "key", i)
			continue
		}
		if v := values[i+1]; v != nil {
			if s, ok := v.(string); ok && s == "" {
				continue
			}
			query.Set(key, fmt.Sprint(values[i+1]))
		}
	}

	url.RawQuery = query.Encode()
	return ctx.Redirect(url.String())
}

func redirectInternal(ctx *fiber.Ctx, location string) error {
	ctx.Path(location)
	ctx.Method(http.MethodGet)
	return ctx.RestartRouting()
}

func forceLogout(ctx *fiber.Ctx, errCode string) error {
	sessions.Destroy(ctx)
	if errCode != "" {
		return redirect(ctx, "/login", "error", errCode)
	}
	return redirect(ctx, "/login")
}
