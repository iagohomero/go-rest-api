package middleware

import (
	"time"

	"go-rest-api/internal/common/httputil"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

const (
	// MaxRequests is the maximum number of requests per time window.
	MaxRequests = 20
	// ExpirationMin is the time window in minutes for rate limiting.
	ExpirationMin = 15
)

// LimiterConfig returns a configured rate limiter middleware (20 requests per 15 minutes).
func LimiterConfig() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        MaxRequests,
		Expiration: ExpirationMin * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).
				JSON(httputil.Common{
					Code:    fiber.StatusTooManyRequests,
					Status:  "error",
					Message: "Too many requests, please try again later",
				})
		},
		SkipSuccessfulRequests: true,
	})
}
