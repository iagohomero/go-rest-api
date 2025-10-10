package config

import (
	pkgErrors "go-rest-api/internal/common/errors"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
)

// NewFiberConfig returns a Fiber configuration with custom error handler and JSON encoder.
func NewFiberConfig(cfg *Config) fiber.Config {
	return fiber.Config{
		AppName:      cfg.App.Name,
		ErrorHandler: pkgErrors.HandleHTTPError,
		JSONEncoder:  sonic.Marshal,
		JSONDecoder:  sonic.Unmarshal,
	}
}
