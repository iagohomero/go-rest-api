package server

import (
	"context"
	"fmt"
	"time"

	"go-rest-api/internal/auth"
	"go-rest-api/internal/common/httputil"
	"go-rest-api/internal/common/logger"
	"go-rest-api/internal/common/validation"
	"go-rest-api/internal/config"
	"go-rest-api/internal/email"
	"go-rest-api/internal/healthcheck"
	"go-rest-api/internal/middleware"
	"go-rest-api/internal/routes"
	"go-rest-api/internal/user"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/swagger"
	"gorm.io/gorm"
)

// Server represents the HTTP server with its dependencies.
type Server struct {
	app *fiber.App
	cfg *config.Config
	db  *gorm.DB
}

// New creates a new server instance with configured middlewares.
func New(cfg *config.Config, db *gorm.DB) *Server {
	app := fiber.New(config.NewFiberConfig(cfg))

	app.Use(middleware.LoggerConfig())
	app.Use(helmet.New())
	app.Use(compress.New())
	app.Use(cors.New())
	app.Use(middleware.RecoverConfig())

	return &Server{
		app: app,
		cfg: cfg,
		db:  db,
	}
}

// SetupRoutes initializes all application routes and handlers.
func (s *Server) SetupRoutes() {
	validate := validation.New()

	healthcheckService := healthcheck.NewService(s.db)
	emailService := email.NewService(s.cfg)
	userRepository := user.NewRepository(s.db)
	userService := user.NewService(userRepository, validate)
	authRepository := auth.NewRepository(s.db)
	authService := auth.NewService(authRepository, validate, userService, s.cfg)

	healthcheckHandler := healthcheck.NewHandler(healthcheckService)
	authHandler := auth.NewHandler(authService, userService, emailService, s.cfg)
	userHandler := user.NewHandler(userService)

	v1 := s.app.Group("/v1")
	v1.Use("/auth", middleware.LimiterConfig())

	authMiddlewareFunc := func(permissions ...string) fiber.Handler {
		return middleware.Auth(userService, s.cfg, permissions...)
	}

	routes.Setup(v1, &routes.Handlers{
		Auth:        authHandler,
		User:        userHandler,
		HealthCheck: healthcheckHandler,
	}, authMiddlewareFunc)

	if !s.cfg.App.IsProd() {
		v1.Get("/docs/*", swagger.HandlerDefault)
	}

	s.app.Use(httputil.NotFoundHandler)
}

// Start starts the HTTP server listening on the configured address.
func (s *Server) Start() error {
	address := s.cfg.App.Address()
	logger.New().Infof("Starting server on %s", address)

	if err := s.app.Listen(address); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server with timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	logger.New().Info("Shutting down server...")

	const shutdownTimeout = 10 * time.Second
	shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()

	if err := s.app.ShutdownWithContext(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	logger.New().Info("Server stopped successfully")
	return nil
}

// App returns the underlying Fiber app instance for testing.
func (s *Server) App() *fiber.App {
	return s.app
}
