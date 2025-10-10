package httputil

import (
	"errors"

	"go-rest-api/internal/common/validation"

	"github.com/gofiber/fiber/v2"
)

// ErrorHandler is the global error handler for Fiber.
func ErrorHandler(c *fiber.Ctx, err error) error {
	if errorsMap := validation.CustomErrorMessages(err); len(errorsMap) > 0 {
		return Error(c, fiber.StatusBadRequest, "Bad Request", errorsMap)
	}

	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return Error(c, fiberErr.Code, fiberErr.Message, nil)
	}

	return Error(c, fiber.StatusInternalServerError, "Internal Server Error", nil)
}

// NotFoundHandler handles 404 not found errors.
func NotFoundHandler(c *fiber.Ctx) error {
	return Error(c, fiber.StatusNotFound, "Endpoint Not Found", nil)
}
