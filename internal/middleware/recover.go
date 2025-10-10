package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// RecoverConfig returns a configured panic recovery middleware.
func RecoverConfig() fiber.Handler {
	return recover.New(recover.Config{
		EnableStackTrace: true,
	})
}
