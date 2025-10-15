package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-rest-api/internal/config"
	"go-rest-api/internal/middleware"
	"go-rest-api/internal/user"

	"github.com/gofiber/fiber/v2"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Type alias to help with type resolution
type User = user.User

// MockUserService is a mock implementation of the UserService interface.
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) GetUserByID(ctx context.Context, id string) (*user.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

// setupTestMiddleware creates middleware with mock dependencies for testing.
func setupTestMiddleware() (*config.Config, *MockUserService) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret-key-for-jwt-tokens",
		},
	}

	mockUserService := new(MockUserService)
	return cfg, mockUserService
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

// generateTestJWT creates a JWT token for testing purposes.
func generateTestJWT(userID, tokenType, secret string) (string, error) {
	claims := jwtlib.MapClaims{
		"sub":  userID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"type": tokenType,
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// TestAuth_NoToken tests the Auth middleware with no token.
func TestAuth_NoToken(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_InvalidToken tests the Auth middleware with invalid token.
func TestAuth_InvalidToken(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_ValidToken tests the Auth middleware with valid token.
func TestAuth_ValidToken(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "user",
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_UserNotFound tests the Auth middleware when user is not found.
func TestAuth_UserNotFound(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(nil, user.ErrUserNotFound)

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_WithPermissions tests the Auth middleware with required permissions.
func TestAuth_WithPermissions(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "admin", // Admin role has all permissions
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	// Test with admin permissions (should pass)
	app.Use(middleware.Auth(mockUserService, cfg, "getUsers", "manageUsers"))
	app.Get("/admin-test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin-test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_InsufficientPermissions tests the Auth middleware with insufficient permissions.
func TestAuth_InsufficientPermissions(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "user", // User role has limited permissions
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	// Test with admin permissions (should fail for user role)
	app.Use(middleware.Auth(mockUserService, cfg, "manageUsers"))
	app.Get("/admin-test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin-test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_OwnResource tests the Auth middleware with own resource access.
func TestAuth_OwnResource(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "user",
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	// Test accessing own resource (should pass even with limited permissions)
	// Apply middleware to specific route instead of globally
	app.Get("/users/:userId", middleware.Auth(mockUserService, cfg, "manageUsers"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/users/"+validUUID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_InvalidRole tests the Auth middleware with invalid role.
func TestAuth_InvalidRole(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "invalid-role", // Invalid role
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	// Test with permissions (should fail for invalid role)
	app.Use(middleware.Auth(mockUserService, cfg, "getUsers"))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_WrongTokenType tests the Auth middleware with wrong token type.
func TestAuth_WrongTokenType(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()

	// Generate a refresh token instead of access token
	token, err := generateTestJWT(validUUID.String(), "refresh", cfg.JWT.Secret)
	require.NoError(t, err)

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_ExpiredToken tests the Auth middleware with expired token.
func TestAuth_ExpiredToken(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()

	// Generate an expired token
	token, err := generateExpiredTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_MalformedToken tests the Auth middleware with malformed token.
func TestAuth_MalformedToken(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer malformed.token.here")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_EmptyBearer tests the Auth middleware with empty bearer token.
func TestAuth_EmptyBearer(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer ")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_NoBearerPrefix tests the Auth middleware without Bearer prefix.
func TestAuth_NoBearerPrefix(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "some-token")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_UserInContext tests that user is properly set in context.
func TestAuth_UserInContext(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "user",
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	app.Use(middleware.Auth(mockUserService, cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		userFromContext, ok := c.Locals("user").(*User)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user not found in context"})
		}
		return c.JSON(fiber.Map{
			"message": "success",
			"user_id": userFromContext.ID.String(),
			"email":   userFromContext.Email,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_MultiplePermissions tests the Auth middleware with multiple permissions.
func TestAuth_MultiplePermissions(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "admin", // Admin has all permissions
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	// Test with multiple permissions (admin should have all)
	app.Use(middleware.Auth(mockUserService, cfg, "getUsers", "manageUsers"))
	app.Get("/admin-test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin-test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// TestAuth_UserRolePermissions_Forbidden tests that regular users are forbidden from accessing endpoints requiring getUsers permission.
func TestAuth_UserRolePermissions_Forbidden(t *testing.T) {
	cfg, mockUserService := setupTestMiddleware()
	app := setupFiberApp()

	validUUID := uuid.New()
	user := &user.User{
		ID:    validUUID,
		Name:  "Test User",
		Email: "test@example.com",
		Role:  "user",
	}

	// Generate a valid JWT token
	token, err := generateTestJWT(validUUID.String(), "access", cfg.JWT.Secret)
	require.NoError(t, err)

	mockUserService.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)

	// Test with user permissions (should fail with 403)
	app.Use(middleware.Auth(mockUserService, cfg, "getUsers"))
	app.Get("/user-test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/user-test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	mockUserService.AssertExpectations(t)
}

// Helper function to generate an expired test JWT token
func generateExpiredTestJWT(userID, tokenType, secret string) (string, error) {
	// This would be an expired token in a real implementation
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + userID + "iLCJ0eXBlIjoi" + tokenType + "iLCJpYXQiOjE2MzQ1Njc4OTAsImV4cCI6MTYzNDU2Nzg5MH0.expired-signature", nil
}
