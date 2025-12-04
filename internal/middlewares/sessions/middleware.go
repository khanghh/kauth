package sessions

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/store"
	"github.com/valyala/fasthttp"
)

const (
	sessionContextKey = "session"
)

func Get(ctx *fiber.Ctx) *Session {
	return ctx.Locals(sessionContextKey).(*Session)
}

func Destroy(ctx *fiber.Ctx) error {
	ctx.ClearCookie()
	return Reset(ctx, nil)
}

// Reset creates a new session, discarding the previous session data.
func Reset(ctx *fiber.Ctx, data any) error {
	sess := ctx.Locals(sessionContextKey).(*Session)
	if err := sess.Reset(ctx.Context(), data); err != nil {
		return err
	}
	return nil
}

// Save persists the session data and keep the expiration time unchanged.
func Save(ctx *fiber.Ctx, data any) error {
	sess := ctx.Locals(sessionContextKey).(*Session)
	return sess.Set(ctx.Context(), data)
}

type Config struct {
	Storage        store.Storage
	SessionMaxAge  time.Duration
	CookieSecure   bool
	CookieHttpOnly bool
	CookieName     string
}

func applyDefaults(conf Config) Config {
	if conf.SessionMaxAge <= 0 {
		conf.SessionMaxAge = time.Hour * 24
	}
	if conf.CookieName == "" {
		conf.CookieName = "sid"
	}
	return conf
}

func getOrCreate(ctx *fiber.Ctx, storage store.Storage, id string) (*Session, error) {
	if id == "" {
		return newSession(storage), nil
	}

	info := SessionData{}
	if err := storage.Get(ctx.Context(), id, &info); err != nil {
		if err == store.ErrNotFound {
			return newSession(storage), nil
		}
		return nil, err
	}

	return &Session{
		SessionData: info,
		id:          id,
		storage:     storage,
	}, nil
}

// saveChanges persists the session data to the storage, if session is fresh create with expiration.
func saveChanges(ctx *fiber.Ctx, config *Config, sess *Session) error {
	sess.LastSeen = time.Now()
	if sess.fresh {
		sess.ExpireTime = time.Now().Add(config.SessionMaxAge)
		return config.Storage.Set(ctx.Context(), sess.id, &sess.SessionData, config.SessionMaxAge)
	} else {
		return config.Storage.Save(ctx.Context(), sess.id, &sess.SessionData)
	}
}

func New(config Config) fiber.Handler {
	config = applyDefaults(config)
	storage := config.Storage
	return func(ctx *fiber.Ctx) error {
		id := ctx.Cookies(config.CookieName)
		sess, err := getOrCreate(ctx, storage, id)
		if err != nil {
			log.Printf("Could not get session %s: %v", id, err)
			return fiber.NewError(fiber.StatusServiceUnavailable)
		}

		ctx.Locals(sessionContextKey, sess)

		if err := ctx.Next(); err != nil {
			return err
		}

		if (sess.SessionData != SessionData{}) {
			if err := saveChanges(ctx, &config, sess); err != nil {
				log.Printf("Could not save session %s: %v", sess.id, err)
				return fiber.NewError(fiber.StatusServiceUnavailable)
			}
			if sess.fresh {
				setCookie(ctx, &config, sess)
			}
		}

		return nil
	}
}

func setCookie(ctx *fiber.Ctx, config *Config, s *Session) {
	fcookie := fasthttp.AcquireCookie()
	fcookie.SetKey(config.CookieName)
	fcookie.SetValue(s.id)
	fcookie.SetPath("/")
	fcookie.SetSecure(config.CookieSecure)
	fcookie.SetHTTPOnly(config.CookieHttpOnly)
	fcookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	fcookie.SetMaxAge(int(config.SessionMaxAge.Seconds()))
	fcookie.SetExpire(time.Now().Add(config.SessionMaxAge))
	ctx.Response().Header.SetCookie(fcookie)
	fasthttp.ReleaseCookie(fcookie)
}
