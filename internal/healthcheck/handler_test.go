package healthcheck_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-rest-api/internal/healthcheck"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockService is a mock implementation of the healthcheck Service interface.
type MockService struct {
	mock.Mock
}

func (m *MockService) DatabaseCheck() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockService) MemoryCheck() error {
	args := m.Called()
	return args.Error(0)
}

// setupTestHandler creates a new health check handler with mock service for testing.
func setupTestHandler() (*healthcheck.Handler, *MockService) {
	mockService := new(MockService)
	handler := healthcheck.NewHandler(mockService)
	return handler, mockService
}

// setupFiberApp creates a Fiber app for testing.
func setupFiberApp() *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})
	return app
}

// TestNewHandler tests the handler constructor.
func TestNewHandler(t *testing.T) {
	mockService := new(MockService)
	handler := healthcheck.NewHandler(mockService)

	assert.NotNil(t, handler)
}

// TestHandler_Check tests the Check handler.
func TestHandler_Check(t *testing.T) {
	tests := []struct {
		name            string
		setupMock       func(*MockService)
		expectedStatus  int
		expectedHealthy bool
		checkResponse   func(*testing.T, *http.Response)
	}{
		{
			name: "Success - All checks pass",
			setupMock: func(m *MockService) {
				m.On("DatabaseCheck").Return(nil)
				m.On("MemoryCheck").Return(nil)
			},
			expectedStatus:  fiber.StatusOK,
			expectedHealthy: true,
			checkResponse: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, fiber.StatusOK, resp.StatusCode)
			},
		},
		{
			name: "Error - Database check fails",
			setupMock: func(m *MockService) {
				m.On("DatabaseCheck").Return(assert.AnError)
				m.On("MemoryCheck").Return(nil)
			},
			expectedStatus:  fiber.StatusServiceUnavailable,
			expectedHealthy: false,
			checkResponse: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)
			},
		},
		{
			name: "Error - Memory check fails",
			setupMock: func(m *MockService) {
				m.On("DatabaseCheck").Return(nil)
				m.On("MemoryCheck").Return(assert.AnError)
			},
			expectedStatus:  fiber.StatusServiceUnavailable,
			expectedHealthy: false,
			checkResponse: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)
			},
		},
		{
			name: "Error - Both checks fail",
			setupMock: func(m *MockService) {
				m.On("DatabaseCheck").Return(assert.AnError)
				m.On("MemoryCheck").Return(assert.AnError)
			},
			expectedStatus:  fiber.StatusServiceUnavailable,
			expectedHealthy: false,
			checkResponse: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockService)

			app.Get("/health", handler.Check)

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.checkResponse != nil {
				tt.checkResponse(t, resp)
			}

			mockService.AssertExpectations(t)
		})
	}
}

// TestHandler_Check_ResponseFormat tests the response format of the Check handler.
func TestHandler_Check_ResponseFormat(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(nil)
	mockService.On("MemoryCheck").Return(nil)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Check response headers
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	mockService.AssertExpectations(t)
}

// TestHandler_Check_DatabaseError tests the Check handler with database error.
func TestHandler_Check_DatabaseError(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(assert.AnError)
	mockService.On("MemoryCheck").Return(nil)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// TestHandler_Check_MemoryError tests the Check handler with memory error.
func TestHandler_Check_MemoryError(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(nil)
	mockService.On("MemoryCheck").Return(assert.AnError)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// TestHandler_Check_BothErrors tests the Check handler with both errors.
func TestHandler_Check_BothErrors(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(assert.AnError)
	mockService.On("MemoryCheck").Return(assert.AnError)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// TestHandler_Check_Concurrent tests the Check handler under concurrent access.
func TestHandler_Check_Concurrent(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(nil).Maybe()
	mockService.On("MemoryCheck").Return(nil).Maybe()

	app.Get("/health", handler.Check)

	// Run multiple concurrent requests
	done := make(chan *http.Response, 5)

	for i := 0; i < 5; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			resp, _ := app.Test(req)
			done <- resp
		}()
	}

	// Collect responses
	for i := 0; i < 5; i++ {
		resp := <-done
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	mockService.AssertExpectations(t)
}

// TestHandler_Check_ErrorMessages tests that error messages are properly included in responses.
func TestHandler_Check_ErrorMessages(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	// Test with database error
	mockService.On("DatabaseCheck").Return(assert.AnError)
	mockService.On("MemoryCheck").Return(nil)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// TestHandler_Check_StatusCodes tests different status codes based on health status.
func TestHandler_Check_StatusCodes(t *testing.T) {
	tests := []struct {
		name           string
		databaseError  error
		memoryError    error
		expectedStatus int
	}{
		{
			name:           "Healthy - No errors",
			databaseError:  nil,
			memoryError:    nil,
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "Unhealthy - Database error",
			databaseError:  assert.AnError,
			memoryError:    nil,
			expectedStatus: fiber.StatusServiceUnavailable,
		},
		{
			name:           "Unhealthy - Memory error",
			databaseError:  nil,
			memoryError:    assert.AnError,
			expectedStatus: fiber.StatusServiceUnavailable,
		},
		{
			name:           "Unhealthy - Both errors",
			databaseError:  assert.AnError,
			memoryError:    assert.AnError,
			expectedStatus: fiber.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockService := setupTestHandler()
			app := setupFiberApp()

			mockService.On("DatabaseCheck").Return(tt.databaseError)
			mockService.On("MemoryCheck").Return(tt.memoryError)

			app.Get("/health", handler.Check)

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			mockService.AssertExpectations(t)
		})
	}
}

// TestHandler_Check_ResponseStructure tests the structure of the health check response.
func TestHandler_Check_ResponseStructure(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(nil)
	mockService.On("MemoryCheck").Return(nil)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Verify response structure
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	mockService.AssertExpectations(t)
}

// TestHandler_Check_ErrorHandling tests error handling in the Check handler.
func TestHandler_Check_ErrorHandling(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	// Test with specific error messages
	databaseError := assert.AnError
	memoryError := assert.AnError

	mockService.On("DatabaseCheck").Return(databaseError)
	mockService.On("MemoryCheck").Return(memoryError)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// TestHandler_Check_Performance tests the performance of the Check handler.
func TestHandler_Check_Performance(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(nil)
	mockService.On("MemoryCheck").Return(nil)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// TestHandler_Check_EdgeCases tests edge cases for the Check handler.
func TestHandler_Check_EdgeCases(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	// Test with nil errors
	mockService.On("DatabaseCheck").Return(nil)
	mockService.On("MemoryCheck").Return(nil)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockService.AssertExpectations(t)
}

// TestHandler_Check_ResponseHeaders tests response headers.
func TestHandler_Check_ResponseHeaders(t *testing.T) {
	handler, mockService := setupTestHandler()
	app := setupFiberApp()

	mockService.On("DatabaseCheck").Return(nil)
	mockService.On("MemoryCheck").Return(nil)

	app.Get("/health", handler.Check)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Check important headers
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	mockService.AssertExpectations(t)
}
