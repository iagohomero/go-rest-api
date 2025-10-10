package routes

import (
	"go-rest-api/internal/auth"
	"go-rest-api/internal/healthcheck"
	"go-rest-api/internal/rbac"
	"go-rest-api/internal/user"

	"github.com/gofiber/fiber/v2"
)

// Handlers groups all HTTP handlers.
type Handlers struct {
	Auth        *auth.Handler
	User        *user.Handler
	HealthCheck *healthcheck.Handler
}

// AuthMiddleware is a function that creates authentication middleware with permissions.
type AuthMiddleware func(permissions ...string) fiber.Handler

// Setup configures all application routes.
func Setup(v1 fiber.Router, handlers *Handlers, authMiddleware AuthMiddleware) {
	health := v1.Group("/health")
	health.Get("/", handlers.HealthCheck.Check)

	authGroup := v1.Group("/auth")
	authGroup.Post("/register", handlers.Auth.Register)
	authGroup.Post("/login", handlers.Auth.Login)
	authGroup.Post("/logout", handlers.Auth.Logout)
	authGroup.Post("/refresh-tokens", handlers.Auth.RefreshTokens)
	authGroup.Post("/forgot-password", handlers.Auth.ForgotPassword)
	authGroup.Post("/reset-password", handlers.Auth.ResetPassword)
	authGroup.Post("/send-verification-email", authMiddleware(), handlers.Auth.SendVerificationEmail)
	authGroup.Post("/verify-email", handlers.Auth.VerifyEmail)
	authGroup.Get("/google", handlers.Auth.GoogleLogin)
	authGroup.Get("/google-callback", handlers.Auth.GoogleCallback)

	users := v1.Group("/users")
	users.Get("/", authMiddleware(rbac.PermissionGetUsers), handlers.User.GetUsers)
	users.Post("/", authMiddleware(rbac.PermissionManageUsers), handlers.User.CreateUser)
	users.Get("/:userId", authMiddleware(rbac.PermissionGetUsers), handlers.User.GetUserByID)
	users.Patch("/:userId", authMiddleware(rbac.PermissionManageUsers), handlers.User.UpdateUser)
	users.Delete("/:userId", authMiddleware(rbac.PermissionManageUsers), handlers.User.DeleteUser)
}
