package httputil

import "github.com/gofiber/fiber/v2"

// Common represents a standard HTTP response.
type Common struct {
	Code    int    `json:"code" example:"200"`
	Status  string `json:"status" example:"success"`
	Message string `json:"message" example:"Operation completed successfully"`
}

// SuccessWithPaginate represents a paginated success response.
type SuccessWithPaginate[T any] struct {
	Code         int    `json:"code"`
	Status       string `json:"status"`
	Message      string `json:"message"`
	Results      []T    `json:"results"`
	Page         int    `json:"page"`
	Limit        int    `json:"limit"`
	TotalPages   int64  `json:"total_pages"`
	TotalResults int64  `json:"total_results"`
}

// ErrorDetails represents an error response with details.
type ErrorDetails struct {
	Code    int         `json:"code"`
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Errors  interface{} `json:"errors"`
}

// Success sends a success response.
func Success(c *fiber.Ctx, code int, message string, data interface{}) error {
	return c.Status(code).JSON(fiber.Map{
		"code":    code,
		"status":  "success",
		"message": message,
		"data":    data,
	})
}

// Error sends an error response.
func Error(c *fiber.Ctx, code int, message string, errors interface{}) error {
	response := ErrorDetails{
		Code:    code,
		Status:  "error",
		Message: message,
		Errors:  errors,
	}
	return c.Status(code).JSON(response)
}

// Paginated sends a paginated response.
func Paginated[T any](c *fiber.Ctx, code int, message string, results []T, page, limit int, totalResults int64) error {
	totalPages := (totalResults + int64(limit) - 1) / int64(limit)

	response := SuccessWithPaginate[T]{
		Code:         code,
		Status:       "success",
		Message:      message,
		Results:      results,
		Page:         page,
		Limit:        limit,
		TotalPages:   totalPages,
		TotalResults: totalResults,
	}

	return c.Status(code).JSON(response)
}
