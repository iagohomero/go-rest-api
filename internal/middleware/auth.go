package middleware

import (
	"context"
	"strings"

	pkgErrors "go-rest-api/internal/common/errors"
	"go-rest-api/internal/common/jwt"
	"go-rest-api/internal/config"
	"go-rest-api/internal/rbac"
	"go-rest-api/internal/user"

	"github.com/gofiber/fiber/v2"
)

// UserService defines the interface for user operations in middleware.
type UserService interface {
	GetUserByID(ctx context.Context, id string) (*user.User, error)
}

// Auth creates an authentication and authorization middleware.
// If requiredPermissions are provided, user must have all permissions or be accessing their own resource.
func Auth(userService UserService, cfg *config.Config, requiredPermissions ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

		if token == "" {
			return pkgErrors.HandleHTTPError(c, pkgErrors.ErrUnauthorized)
		}

		userID, err := jwt.VerifyToken(token, cfg.JWT.Secret, "access")
		if err != nil {
			return pkgErrors.HandleHTTPError(c, pkgErrors.ErrUnauthorized)
		}

		user, err := userService.GetUserByID(c.Context(), userID)
		if err != nil || user == nil {
			return pkgErrors.HandleHTTPError(c, pkgErrors.ErrUnauthorized)
		}

		c.Locals("user", user)

		if len(requiredPermissions) > 0 {
			role, exists := rbac.GetRole(user.Role)
			if !exists {
				return pkgErrors.HandleHTTPError(c, pkgErrors.ErrForbidden)
			}

			hasPermissions := role.HasAllPermissions(requiredPermissions)
			isOwnResource := c.Params("userId") == userID

			if !hasPermissions && !isOwnResource {
				return pkgErrors.HandleHTTPError(c, pkgErrors.ErrForbidden)
			}
		}

		return c.Next()
	}
}
