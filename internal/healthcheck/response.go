package healthcheck

// CheckResult represents the result of a single health check.
type CheckResult struct {
	Name    string  `json:"name" example:"database"`
	Status  string  `json:"status" example:"up"`
	IsUp    bool    `json:"is_up" example:"true"`
	Message *string `json:"message,omitempty" example:"connection refused"`
}

// HealthCheckResponse represents the health check response.
type HealthCheckResponse struct {
	Status    string        `json:"status" example:"success"`
	Message   string        `json:"message" example:"Health check completed"`
	Code      int           `json:"code" example:"200"`
	IsHealthy bool          `json:"is_healthy" example:"true"`
	Checks    []CheckResult `json:"checks"`
}
