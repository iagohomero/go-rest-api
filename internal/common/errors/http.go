package errors

import (
	"errors"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

// ErrorResponse represents a standardized error response.
type ErrorResponse struct {
	Error   string      `json:"error"`
	Message string      `json:"message,omitempty"`
	Details interface{} `json:"details,omitempty"`
}

// HandleHTTPError converts application errors to appropriate HTTP responses.
func HandleHTTPError(c *fiber.Ctx, err error) error {
	if err == nil {
		return nil
	}

	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "validation_error",
			Message: "validation failed",
			Details: formatValidationErrors(validationErrs),
		})
	}

	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return c.Status(fiberErr.Code).JSON(ErrorResponse{
			Error:   "error",
			Message: fiberErr.Message,
		})
	}

	switch {
	case errors.Is(err, ErrNotFound):
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error:   "not_found",
			Message: err.Error(),
		})

	case errors.Is(err, ErrUnauthorized):
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "unauthorized",
			Message: err.Error(),
		})

	case errors.Is(err, ErrForbidden):
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error:   "forbidden",
			Message: "insufficient permissions",
		})

	case errors.Is(err, ErrConflict):
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error:   "conflict",
			Message: err.Error(),
		})

	case errors.Is(err, ErrBadRequest), errors.Is(err, ErrInvalidInput):
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "bad_request",
			Message: err.Error(),
		})

	case errors.Is(err, ErrInternal):
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "internal_error",
			Message: err.Error(),
		})

	default:
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "internal_error",
			Message: "an unexpected error occurred",
		})
	}
}

func formatValidationErrors(errs validator.ValidationErrors) map[string]string {
	errors := make(map[string]string)
	for _, err := range errs {
		field := err.Field()
		switch err.Tag() {
		case "required":
			errors[field] = field + " is required"
		case "email":
			errors[field] = field + " must be a valid email"
		case "min":
			errors[field] = field + " must be at least " + err.Param() + " characters"
		case "max":
			errors[field] = field + " must be at most " + err.Param() + " characters"
		default:
			errors[field] = field + " is invalid"
		}
	}
	return errors
}
