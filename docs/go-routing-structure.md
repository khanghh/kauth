# Clean Fiber Routing Structure (Web, API v1/v2)

This guide proposes a clean, extensible structure for registering web and API routes with go-fiber while avoiding long parameter lists. It uses:
- A single `Deps` (dependencies) struct instead of >8 function parameters
- Fiber’s `fiber.Router` groups for `web`, `api/v1`, and `api/v2`
- A small `Server` composition that wires everything together

All examples use native Fiber types: `*fiber.App`, `fiber.Router`, and `*fiber.Ctx`.

---

## High-Level Design

- `Deps` holds all shared services/modules/config needed by handlers.
- Each module exposes a `Register(r fiber.Router, deps *Deps)` to attach routes.
- `Server.RegisterRoutes()` composes groups for `web`, `api/v1`, `api/v2`.
- Versioning is additive: v2 lives alongside v1 without breaking signatures.

Benefits:
- Eliminate long parameter lists; add/remove services via `Deps`.
- Clear route ownership by package (`web`, `api/v1`, `api/v2`).
- Easy to test by constructing `Deps` with fakes and using Fiber’s `app.Test`.

---

## Suggested Package Layout

```
cmd/
  kauth/
    main.go
internal/
  app/
    deps.go              # Deps container + builders
    server.go            # NewServer, RegisterRoutes
  http/
    middleware/
      ...
    web/
      register.go        # Register(r fiber.Router, deps *Deps)
      handlers.go
    api/
      v1/
        register.go      # Register(r fiber.Router, deps *Deps)
        handlers.go
      v2/
        register.go
        handlers.go
pkg/
  (optional public libs)
```

---

## Deps Container (replace long parameter lists)

```go
// internal/app/deps.go
package app

type Deps struct {
  // Router & static
  StaticDir string

  // Sessions
  Session SessionConfig

  // Core services (examples)
  AuthorizeService  AuthorizeService
  UserService       UserService
  TwoFactorService  TwoFactorService
  OAuthProviders    OAuthProviders
  MailSender        MailSender
}

type SessionConfig struct {
  Storage        any   // e.g. *session.Store or custom
  SessionMaxAge  string
  CookieSecure   bool
  CookieHttpOnly bool
  CookieName     string
}
```

---

## Module Registration (Fiber groups)

```go
// internal/http/web/register.go
package web

import (
  "github.com/gofiber/fiber/v2"
  "github.com/yourorg/yourapp/internal/app"
)

func Register(r fiber.Router, deps *app.Deps) {
  if deps.StaticDir != "" {
    r.Static("/static", deps.StaticDir)
  }

  r.Get("/", func(c *fiber.Ctx) error { return c.Redirect("/login") })
  r.Get("/login", loginHandler{deps}.Get)
  r.Post("/logout", logoutHandler{deps}.Post)
  r.Get("/profile", profileHandler{deps}.Get)
}

type loginHandler struct{ deps *app.Deps }
func (h loginHandler) Get(c *fiber.Ctx) error { /* ... */ return nil }

type logoutHandler struct{ deps *app.Deps }
func (h logoutHandler) Post(c *fiber.Ctx) error { /* ... */ return nil }

type profileHandler struct{ deps *app.Deps }
func (h profileHandler) Get(c *fiber.Ctx) error { /* ... */ return nil }
```

```go
// internal/http/api/v1/register.go
package v1

import (
  "github.com/gofiber/fiber/v2"
  "github.com/yourorg/yourapp/internal/app"
)

func Register(r fiber.Router, deps *app.Deps) {
  r.Get("/health", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
  r.Post("/token", tokenHandler{deps}.Post)
  r.Get("/userinfo", userinfoHandler{deps}.Get)
}

type tokenHandler struct{ deps *app.Deps }
func (h tokenHandler) Post(c *fiber.Ctx) error { /* ... */ return nil }

type userinfoHandler struct{ deps *app.Deps }
func (h userinfoHandler) Get(c *fiber.Ctx) error { /* ... */ return nil }
```

```go
// internal/http/api/v2/register.go
package v2

import (
  "github.com/gofiber/fiber/v2"
  "github.com/yourorg/yourapp/internal/app"
)

func Register(r fiber.Router, deps *app.Deps) {
  // V2 endpoints; keep v1 intact
  r.Get("/health", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok", "v": 2}) })
  r.Post("/token", tokenHandler{deps}.PostV2)
}

type tokenHandler struct{ deps *app.Deps }
func (h tokenHandler) PostV2(c *fiber.Ctx) error { /* ... */ return nil }
```

---

## Server Composition (groups + middleware)

```go
// internal/app/server.go
package app

import (
  "github.com/gofiber/fiber/v2"
  v1 "github.com/yourorg/yourapp/internal/http/api/v1"
  v2 "github.com/yourorg/yourapp/internal/http/api/v2"
  "github.com/yourorg/yourapp/internal/http/web"
)

type Server struct {
  app  *fiber.App
  deps *Deps
}

type Option func(*Server)

func WithStaticDir(dir string) Option { return func(s *Server) { s.deps.StaticDir = dir } }

func New(app *fiber.App, deps *Deps, opts ...Option) *Server {
  s := &Server{app: app, deps: deps}
  for _, opt := range opts { opt(s) }
  return s
}

func (s *Server) RegisterRoutes() {
  // Global middlewares (examples)
  // s.app.Use(logger.New())
  // s.app.Use(cors.New())

  // Web (root) routes
  web.Register(s.app, s.deps)

  // API root group
  api := s.app.Group("/api")

  // Versioned groups
  v1.Register(api.Group("/v1"), s.deps)
  // When ready, add v2 alongside v1
  v2.Register(api.Group("/v2"), s.deps)
}
```

`fiber.Router` is implemented by both `*fiber.App` and `*fiber.Group`, so the same `Register` signature works for root and sub-groups.

---

## Replacing Long Calls (Before → After)

Before (too many params):
```go
setupWebRoutes(
  router,
  config.StaticDir,
  sessions.Config{
    Storage:        redisStorage,
    SessionMaxAge:  config.Session.SessionMaxAge,
    CookieSecure:   config.Session.CookieSecure,
    CookieHttpOnly: config.Session.CookieHttpOnly,
    CookieName:     config.Session.CookieName,
  },
  authorizeService,
  userService,
  twoFactorService,
  oauthProviders,
  mailSender,
)
```

After (single `Deps` into a Fiber-aware server):
```go
deps := &app.Deps{
  StaticDir: config.StaticDir,
  Session: app.SessionConfig{
    Storage:        redisStorage,
    SessionMaxAge:  config.Session.SessionMaxAge,
    CookieSecure:   config.Session.CookieSecure,
    CookieHttpOnly: config.Session.CookieHttpOnly,
    CookieName:     config.Session.CookieName,
  },
  AuthorizeService: authorizeService,
  UserService:      userService,
  TwoFactorService: twoFactorService,
  OAuthProviders:   oauthProviders,
  MailSender:       mailSender,
}

app := fiber.New()
srv := appserver.New(app, deps) // alias: appserver == internal/app
srv.RegisterRoutes()
app.Listen(":3000")
```

When you introduce v2, no signatures change—just add `v2.Register(api.Group("/v2"), deps)`.

---

## Options and Per-Group Middleware

- Put cross-cutting middleware (logger, CORS, CSRF) on `*fiber.App`.
- Attach auth/guard middleware per API version:

```go
api := app.Group("/api")
v1g := api.Group("/v1") // v1-specific middleware
// v1g.Use(jwtware.New(jwtware.Config{ /* ... */ }))
v1.Register(v1g, deps)

v2g := api.Group("/v2") // different policies possible
// v2g.Use(jwtware.New(...))
v2.Register(v2g, deps)
```

---

## Testing Tips (Fiber)

- Use `app.Test(req, timeout)` to exercise handlers without running a server.
- Build `Deps` with fakes/mocks and pass into `New(app, deps)`.
- Keep handlers as small structs calling services from `Deps` for easy isolation.

---

## Migration Checklist

- Create `Deps` and move all function params into it.
- Split registration: `web.Register(app, deps)`, `v1.Register(app.Group("/api/v1"), deps)`, `v2.Register(app.Group("/api/v2"), deps)`.
- Replace `setupWebRoutes`/`setupAPIRoutes` with `Server.RegisterRoutes()`.
- Gradually move handlers into `internal/http/web` and `internal/http/api/v1`.

This Fiber-centric structure removes unwieldy parameter lists, simplifies versioning, and keeps routing clean, testable, and ready for future growth.
