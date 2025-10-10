package healthcheck

import (
	"github.com/gofiber/fiber/v2"
)

// Handler handles health check HTTP requests.
type Handler struct {
	service Service
}

// NewHandler creates a new health check handler.
func NewHandler(service Service) *Handler {
	return &Handler{
		service: service,
	}
}

// Check performs health checks on database and memory.
// @Tags Health
// @Summary Health Check
// @Description Check the status of services and database connections
// @Accept json
// @Produce json
// @Success 200 {object} Response
// @Failure 500 {object} Response
// @Router /health [get].
func (h *Handler) Check(c *fiber.Ctx) error {
	isHealthy := true
	var checks []CheckResult

	if err := h.service.DatabaseCheck(); err != nil {
		isHealthy = false
		errMsg := err.Error()
		checks = append(checks, CheckResult{
			Name:    "database",
			Status:  "down",
			IsUp:    false,
			Message: &errMsg,
		})
	} else {
		checks = append(checks, CheckResult{
			Name:   "database",
			Status: "up",
			IsUp:   true,
		})
	}

	if err := h.service.MemoryCheck(); err != nil {
		isHealthy = false
		errMsg := err.Error()
		checks = append(checks, CheckResult{
			Name:    "memory",
			Status:  "down",
			IsUp:    false,
			Message: &errMsg,
		})
	} else {
		checks = append(checks, CheckResult{
			Name:   "memory",
			Status: "up",
			IsUp:   true,
		})
	}

	statusCode := fiber.StatusOK
	status := "success"

	if !isHealthy {
		statusCode = fiber.StatusServiceUnavailable
		status = "error"
	}

	return c.Status(statusCode).JSON(Response{
		Status:    status,
		Message:   "Health check completed",
		Code:      statusCode,
		IsHealthy: isHealthy,
		Checks:    checks,
	})
}
