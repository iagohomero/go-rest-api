package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-rest-api/internal/auth"
	"go-rest-api/internal/config"
	"go-rest-api/internal/user"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthService is a mock implementation of the auth Service interface.
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*user.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, req *auth.LoginRequest) (*user.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, req *auth.LogoutRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthService) RefreshAuth(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.Tokens, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.Tokens), args.Error(1)
}

func (m *MockAuthService) ResetPassword(
	ctx context.Context,
	query *auth.ResetPasswordRequest,
	req *user.UpdateUserPasswordRequest,
) error {
	args := m.Called(ctx, query, req)
	return args.Error(0)
}

func (m *MockAuthService) VerifyEmail(ctx context.Context, query *auth.ResetPasswordRequest) error {
	args := m.Called(ctx, query)
	return args.Error(0)
}

func (m *MockAuthService) GenerateToken(userID string, expires time.Time, tokenType string) (string, error) {
	args := m.Called(userID, expires, tokenType)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) SaveToken(ctx context.Context, token, userID, tokenType string, expires time.Time) error {
	args := m.Called(ctx, token, userID, tokenType, expires)
	return args.Error(0)
}

func (m *MockAuthService) DeleteToken(ctx context.Context, tokenType string, userID string) error {
	args := m.Called(ctx, tokenType, userID)
	return args.Error(0)
}

func (m *MockAuthService) DeleteAllToken(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthService) GetTokenByUserID(ctx context.Context, tokenStr string) (*auth.TokenDB, error) {
	args := m.Called(ctx, tokenStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenDB), args.Error(1)
}

func (m *MockAuthService) GenerateAuthTokens(ctx context.Context, user *user.User) (*auth.Tokens, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.Tokens), args.Error(1)
}

func (m *MockAuthService) GenerateResetPasswordToken(
	ctx context.Context,
	req *auth.ForgotPasswordRequest,
) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) GenerateVerifyEmailToken(ctx context.Context, user *user.User) (*string, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*string), args.Error(1)
}

// MockUserService is a mock implementation of the user Service interface.
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) GetUsers(ctx context.Context, params *user.QueryUserRequest) ([]user.User, int64, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]user.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockUserService) GetUserByID(ctx context.Context, id string) (*user.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockUserService) GetUserByEmail(ctx context.Context, email string) (*user.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockUserService) CreateUser(ctx context.Context, req *user.CreateUserRequest) (*user.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockUserService) UpdatePassOrVerify(
	ctx context.Context,
	req *user.UpdateUserPasswordRequest,
	id string,
) error {
	args := m.Called(ctx, req, id)
	return args.Error(0)
}

func (m *MockUserService) UpdateUser(ctx context.Context, req *user.UpdateUserRequest, id string) (*user.User, error) {
	args := m.Called(ctx, req, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockUserService) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserService) CreateGoogleUser(ctx context.Context, req *user.CreateGoogleUserRequest) (*user.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

// MockEmailService is a mock implementation of the email Service interface.
type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) SendEmail(to, subject, body string) error {
	args := m.Called(to, subject, body)
	return args.Error(0)
}

func (m *MockEmailService) SendResetPasswordEmail(email, token string) error {
	args := m.Called(email, token)
	return args.Error(0)
}

func (m *MockEmailService) SendVerificationEmail(email, token string) error {
	args := m.Called(email, token)
	return args.Error(0)
}

// setupTestHandler creates a new auth handler with mock services for testing.
func setupTestHandler() (*auth.Handler, *MockAuthService, *MockUserService, *MockEmailService) {
	mockAuthService := new(MockAuthService)
	mockUserService := new(MockUserService)
	mockEmailService := new(MockEmailService)

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}

	handler := auth.NewHandler(mockAuthService, mockUserService, mockEmailService, cfg)
	return handler, mockAuthService, mockUserService, mockEmailService
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
	mockAuthService := new(MockAuthService)
	mockUserService := new(MockUserService)
	mockEmailService := new(MockEmailService)
	cfg := &config.Config{}

	handler := auth.NewHandler(mockAuthService, mockUserService, mockEmailService, cfg)

	assert.NotNil(t, handler)
}

// TestHandler_Register tests the Register handler.
func TestHandler_Register(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockAuthService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Register user with valid data",
			requestBody: auth.RegisterRequest{
				Name:     "New User",
				Email:    "newuser@example.com",
				Password: "password123",
			},
			setupMock: func(m *MockAuthService) {
				createdUser := &user.User{
					ID:    uuid.New(),
					Name:  "New User",
					Email: "newuser@example.com",
					Role:  "user",
				}
				tokens := &auth.Tokens{
					Access: auth.TokenExpires{
						Token: "access-token",
					},
					Refresh: auth.TokenExpires{
						Token: "refresh-token",
					},
				}
				m.On("Register", mock.Anything, mock.AnythingOfType("*auth.RegisterRequest")).
					Return(createdUser, nil)
				m.On("GenerateAuthTokens", mock.Anything, createdUser).
					Return(tokens, nil)
			},
			expectedStatus: fiber.StatusCreated,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid JSON body",
			requestBody: "invalid json",
			setupMock: func(_ *MockAuthService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Error - Email already taken",
			requestBody: auth.RegisterRequest{
				Name:     "Duplicate User",
				Email:    "duplicate@example.com",
				Password: "password123",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Register", mock.Anything, mock.AnythingOfType("*auth.RegisterRequest")).
					Return(nil, auth.ErrEmailTaken)
			},
			expectedStatus: fiber.StatusConflict,
			expectedError:  true,
		},
		{
			name: "Error - Service returns error",
			requestBody: auth.RegisterRequest{
				Name:     "Error User",
				Email:    "error@example.com",
				Password: "password123",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Register", mock.Anything, mock.AnythingOfType("*auth.RegisterRequest")).
					Return(nil, errors.New("service error"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, _ := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService)

			app.Post("/auth/register", handler.Register)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_Login tests the Login handler.
func TestHandler_Login(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockAuthService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Login with valid credentials",
			requestBody: auth.LoginRequest{
				Email:    "user@example.com",
				Password: "password123",
			},
			setupMock: func(m *MockAuthService) {
				user := &user.User{
					ID:    uuid.New(),
					Name:  "Test User",
					Email: "user@example.com",
					Role:  "user",
				}
				tokens := &auth.Tokens{
					Access: auth.TokenExpires{
						Token: "access-token",
					},
					Refresh: auth.TokenExpires{
						Token: "refresh-token",
					},
				}
				m.On("Login", mock.Anything, mock.AnythingOfType("*auth.LoginRequest")).
					Return(user, nil)
				m.On("GenerateAuthTokens", mock.Anything, user).
					Return(tokens, nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid JSON body",
			requestBody: "invalid json",
			setupMock: func(_ *MockAuthService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Error - Invalid credentials",
			requestBody: auth.LoginRequest{
				Email:    "user@example.com",
				Password: "wrongpassword",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Login", mock.Anything, mock.AnythingOfType("*auth.LoginRequest")).
					Return(nil, auth.ErrInvalidCredentials)
			},
			expectedStatus: fiber.StatusUnauthorized,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, _ := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService)

			app.Post("/auth/login", handler.Login)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_Logout tests the Logout handler.
func TestHandler_Logout(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockAuthService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Logout with valid refresh token",
			requestBody: auth.LogoutRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Logout", mock.Anything, mock.AnythingOfType("*auth.LogoutRequest")).
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid JSON body",
			requestBody: "invalid json",
			setupMock: func(_ *MockAuthService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Error - Token not found",
			requestBody: auth.LogoutRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Logout", mock.Anything, mock.AnythingOfType("*auth.LogoutRequest")).
					Return(auth.ErrTokenNotFound)
			},
			expectedStatus: fiber.StatusNotFound,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, _ := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService)

			app.Post("/auth/logout", handler.Logout)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_RefreshTokens tests the RefreshTokens handler.
func TestHandler_RefreshTokens(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockAuthService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Refresh tokens with valid refresh token",
			requestBody: auth.RefreshTokenRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMock: func(m *MockAuthService) {
				tokens := &auth.Tokens{
					Access: auth.TokenExpires{
						Token: "new-access-token",
					},
					Refresh: auth.TokenExpires{
						Token: "new-refresh-token",
					},
				}
				m.On("RefreshAuth", mock.Anything, mock.AnythingOfType("*auth.RefreshTokenRequest")).
					Return(tokens, nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid JSON body",
			requestBody: "invalid json",
			setupMock: func(_ *MockAuthService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Error - Invalid refresh token",
			requestBody: auth.RefreshTokenRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(m *MockAuthService) {
				m.On("RefreshAuth", mock.Anything, mock.AnythingOfType("*auth.RefreshTokenRequest")).
					Return(nil, auth.ErrInvalidToken)
			},
			expectedStatus: fiber.StatusUnauthorized,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, _ := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService)

			app.Post("/auth/refresh-tokens", handler.RefreshTokens)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh-tokens", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_ForgotPassword tests the ForgotPassword handler.
func TestHandler_ForgotPassword(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockAuthService, *MockEmailService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Send password reset email",
			requestBody: auth.ForgotPasswordRequest{
				Email: "user@example.com",
			},
			setupMock: func(m *MockAuthService, e *MockEmailService) {
				m.On("GenerateResetPasswordToken", mock.Anything, mock.AnythingOfType("*auth.ForgotPasswordRequest")).
					Return("reset-token", nil)
				e.On("SendResetPasswordEmail", "user@example.com", "reset-token").
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid JSON body",
			requestBody: "invalid json",
			setupMock: func(_ *MockAuthService, _ *MockEmailService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Error - User not found",
			requestBody: auth.ForgotPasswordRequest{
				Email: "notfound@example.com",
			},
			setupMock: func(m *MockAuthService, _ *MockEmailService) {
				m.On("GenerateResetPasswordToken", mock.Anything, mock.AnythingOfType("*auth.ForgotPasswordRequest")).
					Return("", user.ErrUserNotFound)
			},
			expectedStatus: fiber.StatusNotFound,
			expectedError:  true,
		},
		{
			name: "Error - Email service fails",
			requestBody: auth.ForgotPasswordRequest{
				Email: "user@example.com",
			},
			setupMock: func(m *MockAuthService, e *MockEmailService) {
				m.On("GenerateResetPasswordToken", mock.Anything, mock.AnythingOfType("*auth.ForgotPasswordRequest")).
					Return("reset-token", nil)
				e.On("SendResetPasswordEmail", "user@example.com", "reset-token").
					Return(errors.New("email service error"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, mockEmailService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService, mockEmailService)

			app.Post("/auth/forgot-password", handler.ForgotPassword)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
				mockEmailService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_ResetPassword tests the ResetPassword handler.
func TestHandler_ResetPassword(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		requestBody    interface{}
		setupMock      func(*MockAuthService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:        "Success - Reset password with valid token",
			queryParams: "?token=valid-reset-token",
			requestBody: user.UpdateUserPasswordRequest{
				Password: "newpassword123",
			},
			setupMock: func(m *MockAuthService) {
				m.On("ResetPassword", mock.Anything, mock.AnythingOfType("*auth.ResetPasswordRequest"), mock.AnythingOfType("*user.UpdateUserPasswordRequest")).
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid JSON body",
			queryParams: "?token=valid-token",
			requestBody: "invalid json",
			setupMock: func(_ *MockAuthService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:        "Error - Invalid token",
			queryParams: "?token=invalid-token",
			requestBody: user.UpdateUserPasswordRequest{
				Password: "newpassword123",
			},
			setupMock: func(m *MockAuthService) {
				m.On("ResetPassword", mock.Anything, mock.AnythingOfType("*auth.ResetPasswordRequest"), mock.AnythingOfType("*user.UpdateUserPasswordRequest")).
					Return(auth.ErrInvalidToken)
			},
			expectedStatus: fiber.StatusUnauthorized,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, _ := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService)

			app.Post("/auth/reset-password", handler.ResetPassword)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/reset-password"+tt.queryParams, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_SendVerificationEmail tests the SendVerificationEmail handler.
func TestHandler_SendVerificationEmail(t *testing.T) {
	tests := []struct {
		name           string
		setupUser      func(*fiber.Ctx)
		setupMock      func(*MockAuthService, *MockEmailService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Send verification email",
			setupUser: func(c *fiber.Ctx) {
				user := &user.User{
					ID:    uuid.New(),
					Name:  "Test User",
					Email: "test@example.com",
				}
				c.Locals("user", user)
			},
			setupMock: func(m *MockAuthService, e *MockEmailService) {
				token := "verify-token"
				m.On("GenerateVerifyEmailToken", mock.Anything, mock.AnythingOfType("*user.User")).
					Return(&token, nil)
				e.On("SendVerificationEmail", "test@example.com", "verify-token").
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name: "Error - No user in context",
			setupUser: func(_ *fiber.Ctx) {
				// No user set
			},
			setupMock: func(_ *MockAuthService, _ *MockEmailService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusUnauthorized,
			expectedError:  true,
		},
		{
			name: "Error - Token generation fails",
			setupUser: func(c *fiber.Ctx) {
				user := &user.User{
					ID:    uuid.New(),
					Name:  "Test User",
					Email: "test@example.com",
				}
				c.Locals("user", user)
			},
			setupMock: func(m *MockAuthService, _ *MockEmailService) {
				m.On("GenerateVerifyEmailToken", mock.Anything, mock.AnythingOfType("*user.User")).
					Return(nil, auth.ErrTokenGenerationFailed)
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, mockEmailService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService, mockEmailService)

			app.Post("/auth/send-verification-email", func(c *fiber.Ctx) error {
				tt.setupUser(c)
				return handler.SendVerificationEmail(c)
			})

			req := httptest.NewRequest(http.MethodPost, "/auth/send-verification-email", nil)

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
				mockEmailService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_VerifyEmail tests the VerifyEmail handler.
func TestHandler_VerifyEmail(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		setupMock      func(*MockAuthService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:        "Success - Verify email with valid token",
			queryParams: "?token=valid-verify-token",
			setupMock: func(m *MockAuthService) {
				m.On("VerifyEmail", mock.Anything, mock.AnythingOfType("*auth.ResetPasswordRequest")).
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid token",
			queryParams: "?token=invalid-token",
			setupMock: func(m *MockAuthService) {
				m.On("VerifyEmail", mock.Anything, mock.AnythingOfType("*auth.ResetPasswordRequest")).
					Return(auth.ErrInvalidToken)
			},
			expectedStatus: fiber.StatusUnauthorized,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockAuthService, _, _ := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockAuthService)

			app.Post("/auth/verify-email", handler.VerifyEmail)

			req := httptest.NewRequest(http.MethodPost, "/auth/verify-email"+tt.queryParams, nil)

			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockAuthService.AssertExpectations(t)
			}
		})
	}
}
