package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/khanghh/kauth/internal/audit"
	"github.com/khanghh/kauth/internal/auth"
	"github.com/khanghh/kauth/internal/config"
	"github.com/khanghh/kauth/internal/handlers"
	"github.com/khanghh/kauth/internal/handlers/api"
	"github.com/khanghh/kauth/internal/handlers/web"
	"github.com/khanghh/kauth/internal/mail"
	"github.com/khanghh/kauth/internal/middlewares/captcha"
	"github.com/khanghh/kauth/internal/middlewares/sessions"
	"github.com/khanghh/kauth/internal/oauth"
	"github.com/khanghh/kauth/internal/render"
	"github.com/khanghh/kauth/internal/store"
	"github.com/khanghh/kauth/internal/twofactor"
	"github.com/khanghh/kauth/internal/users"
	"github.com/khanghh/kauth/model"
	"github.com/khanghh/kauth/model/query"
	"github.com/khanghh/kauth/params"
	"github.com/redis/go-redis/v9"
	"github.com/urfave/cli/v2"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"gorm.io/gorm/schema"
)

var (
	app       *cli.App
	gitCommit string
	gitDate   string
	gitTag    string
)

var (
	configFileFlag = &cli.StringFlag{
		Name:  "config",
		Usage: "YAML config file",
		Value: "config.yaml",
	}
	debugFlag = &cli.BoolFlag{
		Name:  "debug",
		Usage: "Enable debug logging",
	}
)

func init() {
	app = cli.NewApp()
	app.EnableBashCompletion = true
	app.Usage = "kauth - A simple and secure authentication server"
	app.Flags = []cli.Flag{
		configFileFlag,
		debugFlag,
	}
	app.Commands = []*cli.Command{
		{
			Name: "version",
			Action: func(ctx *cli.Context) error {
				fmt.Println(params.VersionWithCommit(gitCommit, gitDate))
				return nil
			},
		},
	}
	app.Action = run
}

func mustInitLogger(debug bool) {
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))
}

func mustInitDatabase(dbConfig config.MySQLConfig) *gorm.DB {
	db, err := gorm.Open(mysql.Open(dbConfig.Dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   dbConfig.TablePrefix,
			SingularTable: true,
		},
	})
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	if err := db.AutoMigrate(model.Models...); err != nil {
		slog.Error("Database migration failed", "error", err)
		os.Exit(1)
	}

	return db
}

func mustInitOAuthProviders(config *config.Config) []oauth.OAuthProvider {
	var providers []oauth.OAuthProvider
	for providerName, providerCfg := range config.AuthProviders.OAuth {
		callbackURL, _ := url.JoinPath(config.BaseURL, "oauth", providerName, "callback")
		switch providerName {
		case "google":
			provider := oauth.NewGoogleOAuthProvider(callbackURL, providerCfg.ClientID, providerCfg.ClientSecret)
			providers = append(providers, provider)
		default:
			slog.Error("Unsupported OAuth provider", "provider", providerName)
			os.Exit(1)
		}
	}
	return providers
}

func mustInitMailSender(mailCfg config.MailConfig) mail.MailSender {
	if mailCfg.From == "" {
		log.Fatal("Mail from address is required")
	}
	mail.SetDefaultFromAddress(mailCfg.From)
	if mailCfg.Backend == "smtp" {
		smtpCfg := mail.SMTPConfig{
			Host:     mailCfg.SMTP.Host,
			Port:     mailCfg.SMTP.Port,
			Username: mailCfg.SMTP.Username,
			Password: mailCfg.SMTP.Password,
			TLS:      mailCfg.SMTP.TLS,
			CertFile: mailCfg.SMTP.CertFile,
			KeyFile:  mailCfg.SMTP.KeyFile,
			CAFile:   mailCfg.SMTP.CAFile,
		}
		mailSender, err := mail.NewSMTPMailSender(smtpCfg)
		if err != nil {
			log.Fatalf("Failed to initialize SMTP mail sender: %v", err)
		}
		return mailSender
	}
	log.Fatal("Invalid mail sender backend")
	return nil
}

func mustInitCaptchaVerifier(capchaCfg config.CaptchaConfig) {
	var verifier captcha.CaptchaVerifier
	if capchaCfg.Provider == "turnstile" {
		verifier = captcha.NewTurnstileVerifier(capchaCfg.Turnstile.SecretKey)
	} else {
		verifier = captcha.NewNullVerifier()
	}
	captcha.SetVerifier(verifier)
}

func mustInitRedisClient(redisCfg config.RedisConfig) redis.UniversalClient {
	opts, err := redis.ParseURL(redisCfg.URL)
	if err != nil {
		log.Fatalf("Failed to parse redis url: %v", err)
	}
	uniOpts := &redis.UniversalOptions{
		Addrs:         []string{opts.Addr},
		DB:            opts.DB,
		Username:      opts.Username,
		Password:      opts.Password,
		PoolSize:      redisCfg.PoolSize,
		IsClusterMode: redisCfg.ClusterMode,
	}
	db := redis.NewUniversalClient(uniOpts)
	if err := db.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to redis: %v", err)
	}
	return db
}

func mustInitRenderTemplate(templateDir string, config *config.Config) {
	globalVars := fiber.Map{
		"siteName":           config.SiteName,
		"baseURL":            config.BaseURL,
		"turnstileSiteKey":   config.Captcha.Turnstile.SiteKey,
		"turnstileSecretKey": config.Captcha.Turnstile.SecretKey,
	}
	if err := render.Initialize(globalVars, templateDir); err != nil {
		log.Fatalf("Failed to initialize render templates: %v", err)
	}
}

type apiDependencies struct {
	authorizeService *auth.AuthorizeService
	userService      *users.UserService
	twoFactorService *twofactor.TwoFactorService
}

func setupAPIRoutes(router fiber.Router, deps *apiDependencies) {
	authHandler := api.NewAuthHandler(deps.authorizeService, deps.userService, deps.twoFactorService)
	router.Post("/p3/serviceValidate", authHandler.PostServiceValidate)
}

type webDependencies struct {
	statisDir        string
	captchaConfig    config.CaptchaConfig
	mailSender       mail.MailSender
	authorizeService *auth.AuthorizeService
	userService      *users.UserService
	twoFactorService *twofactor.TwoFactorService
	oauthProviders   []oauth.OAuthProvider
}

func setupWebRoutes(router fiber.Router, deps *webDependencies) {
	// handlers
	var (
		authHandler            = web.NewAuthHandler(deps.authorizeService, deps.userService, deps.twoFactorService, deps.oauthProviders)
		registerHandler        = web.NewRegisterHandler(deps.userService, deps.mailSender)
		oauthHandler           = web.NewOAuthHandler(deps.userService, deps.oauthProviders)
		twofactorHandler       = web.NewTwoFactorHandler(deps.twoFactorService, deps.userService, deps.mailSender)
		resetPasswordHandler   = web.NewResetPasswordHandler(deps.userService, deps.twoFactorService, deps.mailSender)
		accountSettingsHandler = web.NewAccountSettingsHandler(deps.userService, deps.twoFactorService, deps.mailSender)
	)

	// middlewares
	mustInitCaptchaVerifier(deps.captchaConfig)

	// routes
	router.Static("/static", deps.statisDir)
	router.Get("/", authHandler.GetHome)
	router.Get("/login", authHandler.GetLogin)
	router.Post("/login", authHandler.PostLogin)
	router.Post("/logout", authHandler.PostLogout)
	router.Get("/authorize", authHandler.GetAuthorize)
	router.Post("/authorize", authHandler.PostAuthorize)
	router.Get("/profile", authHandler.GetProfile)
	router.Get("/register", registerHandler.GetRegister)
	router.Post("/register", registerHandler.PostRegister)
	router.Get("/register/verify", registerHandler.GetRegisterVerify)
	router.Get("/register/oauth", registerHandler.GetRegisterWithOAuth)
	router.Post("/register/oauth", registerHandler.PostRegisterWithOAuth)
	router.Get("/reset-password", resetPasswordHandler.GetResetPassword)
	router.Post("/reset-password", resetPasswordHandler.PostResetPassword)
	router.Get("/forgot-password", resetPasswordHandler.GetForogtPassword)
	router.Post("/forgot-password", resetPasswordHandler.PostForgotPassword)
	router.Get("/2fa/challenge", twofactorHandler.GetChallenge)
	router.Post("/2fa/challenge", twofactorHandler.PostChallenge)
	router.Get("/2fa/otp/verify", twofactorHandler.GetVerifyOTP)
	router.Post("/2fa/otp/verify", twofactorHandler.PostVerifyOTP)
	router.Get("/2fa/totp/enroll", twofactorHandler.GetTOTPEnroll)
	router.Post("/2fa/totp/enroll", twofactorHandler.PostTOTPEnroll)
	router.Get("/2fa/totp/verify", twofactorHandler.GetVerifyTOTP)
	router.Post("/2fa/totp/verify", twofactorHandler.PostVerifyTOTP)
	router.Get("/2fa/settings", twofactorHandler.GetTwoFASettings)
	router.Post("/2fa/settings", twofactorHandler.PostTwoFASettings)
	router.Get("/account/change-password", accountSettingsHandler.GetChangePassword)
	router.Post("/account/change-password", accountSettingsHandler.PostChangePassword)
	router.Get("/oauth/:provider/callback", oauthHandler.GetOAuthCallback)
}

func run(ctx *cli.Context) error {
	config, err := config.LoadConfig(ctx.String(configFileFlag.Name))
	if err != nil {
		slog.Error("Could not load config file.", "error", err)
		return err
	}

	mustInitLogger(config.Debug || ctx.IsSet(debugFlag.Name))

	mustInitRenderTemplate(config.TemplateDir, config)
	mailSender := mustInitMailSender(config.Mail)
	database := mustInitDatabase(config.MySQL)
	redisConn := mustInitRedisClient(config.Redis)
	storage := store.NewRedisStorage(redisConn)

	// repositories
	query.SetDefault(database)
	var (
		userRepo        = users.NewUserRepository(query.Q)
		pendingUserRepo = users.NewPendingUserRepository(query.Q)
		userOAuthRepo   = users.NewUserOAuthRepository(query.Q)
		userFactorRepo  = users.NewUserFactorRepository(query.Q)
		serviceRepo     = auth.NewServiceRepository(query.Q)
		auditRepo       = audit.NewAuditLogRepository(query.Q)
	)

	// services
	var (
		userService      = users.NewUserService(userRepo, userOAuthRepo, userFactorRepo, pendingUserRepo)
		authorizeService = auth.NewAuthorizeService(config.MasterKey, storage, serviceRepo)
		twoFactorService = twofactor.NewTwoFactorService(config.MasterKey, storage, userFactorRepo)
		oauthProviders   = mustInitOAuthProviders(config)
	)

	audit.Initialize(auditRepo)

	router := fiber.New(fiber.Config{
		Prefork:       false,
		CaseSensitive: true,
		BodyLimit:     params.ServerBodyLimit,
		IdleTimeout:   params.ServerIdleTimeout,
		ReadTimeout:   params.ServerReadTimeout,
		WriteTimeout:  params.ServerWriteTimeout,
		ErrorHandler:  handlers.ErrorHandler,
	})

	router.Use(recover.New())
	router.Use(logger.New())
	router.Use(cors.New(cors.Config{
		AllowOrigins: strings.Join(config.AllowOrigins, ", "),
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))
	router.Use(sessions.Initialize(sessions.Config{
		Storage:        store.StorageWithPrefix(storage, params.SessionKeyPrefix),
		SessionMaxAge:  config.Session.SessionMaxAge,
		CookieSecure:   config.Session.CookieSecure,
		CookieHttpOnly: config.Session.CookieHttpOnly,
		CookieName:     config.Session.CookieName,
	}))

	setupAPIRoutes(router, &apiDependencies{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	})

	setupWebRoutes(router, &webDependencies{
		statisDir:        config.StaticDir,
		captchaConfig:    config.Captcha,
		mailSender:       mailSender,
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
		oauthProviders:   oauthProviders,
	})

	go startHealthCheckServer(params.HealthCheckServerAddr, redisConn, database)
	return router.Listen(config.ListenAddr)
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
