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

var sessStore *Store

// getOrCreate retrieves existing session or create a temporary new one.
func getOrCreate(ctx *fiber.Ctx) (*Session, error) {
	sess, ok := ctx.Locals(sessionContextKey).(*Session)
	if ok {
		return sess, nil
	}

	if id := ctx.Cookies(sessStore.CookieName); id != "" {
		sess, err := sessStore.Get(ctx.Context(), id)
		if err == nil {
			ctx.Locals(sessionContextKey, sess)
			return sess, nil
		} else if err != store.ErrNotFound {
			log.Printf("Could not load session %s: %v", id, err)
			return nil, err
		}
	}

	sess = newSession(sessStore.Storage)
	ctx.Locals(sessionContextKey, sess)
	return sess, nil
}

// Get retrieves the current session or create a temporary new one.
// The session will be saved automatically at the end of request if it is modified.
func Get(ctx *fiber.Ctx) *Session {
	sess, _ := getOrCreate(ctx)
	return sess
}

// Destroy immediately deletes the current session and clear the cookie.
func Destroy(ctx *fiber.Ctx) error {
	ctx.ClearCookie(sessStore.CookieName)
	_, err := Reset(ctx, SessionData{})
	return err
}

// Reset immediately deletes the current session and create tempory new one with given data.
func Reset(ctx *fiber.Ctx, data SessionData) (*Session, error) {
	if id := ctx.Cookies(sessStore.CookieName); id != "" {
		err := sessStore.Delete(ctx.Context(), id)
		if err != nil && err != store.ErrNotFound {
			return nil, err
		}
	}

	sess := newSession(sessStore.Storage)
	sess.SessionData = data
	ctx.Locals(sessionContextKey, sess)
	return sess, nil
}

// Save immediately persists the current session data to the storage.
func Save(ctx *fiber.Ctx, data SessionData) error {
	sess, err := getOrCreate(ctx)
	if err != nil {
		return err
	}
	sess.SessionData = data
	return sessStore.Save(ctx.Context(), sess)
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

func Initialize(config Config) fiber.Handler {
	sessStore = &Store{
		Config: applyDefaults(config),
	}
	return func(ctx *fiber.Ctx) error {
		if err := ctx.Next(); err != nil {
			return err
		}

		sess, ok := ctx.Locals(sessionContextKey).(*Session)
		if ok && (sess.SessionData != SessionData{}) {
			if err := sessStore.Save(ctx.Context(), sess); err != nil {
				log.Printf("Could not save session %s: %v", sess.id, err)
				return err
			}
			if sess.fresh {
				setCookie(ctx, &sessStore.Config, sess)
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
