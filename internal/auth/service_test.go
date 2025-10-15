package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-rest-api/internal/auth"
	"go-rest-api/internal/common/crypto"
	"go-rest-api/internal/common/validation"
	"go-rest-api/internal/config"
	"go-rest-api/internal/user"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockRepository is a mock implementation of the Repository interface.
type MockRepository struct {
	mock.Mock
}

// generateTestToken creates a valid JWT token for testing
func generateTestToken(userID, tokenType string, cfg *config.Config) (string, error) {
	expires := time.Now().Add(time.Hour)

	// Create a minimal service struct to access GenerateToken
	mockRepo := new(MockRepository)
	mockUserService := new(MockUserService)
	validate := validation.New()

	testService := auth.NewService(mockRepo, validate, mockUserService, cfg)

	return testService.GenerateToken(userID, expires, tokenType)
}

func (m *MockRepository) CreateUser(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) CreateToken(ctx context.Context, token *auth.TokenDB) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRepository) DeleteToken(ctx context.Context, tokenType string, userID string) error {
	args := m.Called(ctx, tokenType, userID)
	return args.Error(0)
}

func (m *MockRepository) DeleteAllTokens(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRepository) FindTokenByTokenAndUserID(ctx context.Context, tokenStr string, userID string) (*auth.TokenDB, error) {
	args := m.Called(ctx, tokenStr, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenDB), args.Error(1)
}

// setupTestService creates a new service with mock dependencies for testing.
func setupTestService() (auth.Service, *MockRepository, *MockUserService) {
	mockRepo := new(MockRepository)
	mockUserService := new(MockUserService)
	validate := validation.New()

	// Create a minimal config for testing
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:              "test-secret",
			AccessExpMinutes:    60,
			RefreshExpDays:      7,
			ResetPasswordExpMin: 15,
			VerifyEmailExpMin:   15,
		},
		SMTP: config.SMTPConfig{
			Host:     "localhost",
			Port:     587,
			Username: "test",
			Password: "test",
			From:     "test@example.com",
		},
	}

	service := auth.NewService(mockRepo, validate, mockUserService, cfg)
	return service, mockRepo, mockUserService
}

// TestNewService tests the service constructor.
func TestNewService(t *testing.T) {
	mockRepo := new(MockRepository)
	mockUserService := new(MockUserService)
	validate := validation.New()

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:              "test-secret",
			AccessExpMinutes:    60,
			RefreshExpDays:      7,
			ResetPasswordExpMin: 15,
			VerifyEmailExpMin:   15,
		},
		SMTP: config.SMTPConfig{
			Host:     "localhost",
			Port:     587,
			Username: "test",
			Password: "test",
			From:     "test@example.com",
		},
	}

	service := auth.NewService(mockRepo, validate, mockUserService, cfg)

	assert.NotNil(t, service)
}

// TestService_Register tests the Register service method.
func TestService_Register(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *auth.RegisterRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
		checkError    func(*testing.T, error)
	}{
		{
			name: "Success - Register user",
			request: &auth.RegisterRequest{
				Name:     "New User",
				Email:    "newuser@example.com",
				Password: "Password123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*user.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Validation fails (empty name)",
			request: &auth.RegisterRequest{
				Name:     "",
				Email:    "test@example.com",
				Password: "Password123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - validation fails first
			},
			checkError: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "Error - Email already taken",
			request: &auth.RegisterRequest{
				Name:     "Test User",
				Email:    "duplicate@example.com",
				Password: "Password123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*user.User")).
					Return(auth.ErrEmailTaken)
			},
			expectedError: auth.ErrEmailTaken,
		},
		{
			name: "Error - Repository error",
			request: &auth.RegisterRequest{
				Name:     "Test User",
				Email:    "test@example.com",
				Password: "Password123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*user.User")).
					Return(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			user, err := service.Register(ctx, tt.request)

			switch {
			case tt.checkError != nil:
				tt.checkError(t, err)
			case tt.expectedError != nil:
				require.Error(t, err)
				assert.Nil(t, user)
			default:
				require.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.request.Name, user.Name)
				assert.Equal(t, tt.request.Email, user.Email)
				assert.NotEqual(t, tt.request.Password, user.Password) // Password should be hashed
			}

			if tt.checkError == nil && tt.expectedError == nil {
				mockRepo.AssertExpectations(t)
			}
		})
	}
}

// TestService_Login tests the Login service method.
func TestService_Login(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *auth.LoginRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Login with valid credentials",
			request: &auth.LoginRequest{
				Email:    "user@example.com",
				Password: "Password123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// Generate a proper bcrypt hash for the test password
				hashedPassword, _ := crypto.HashPassword("Password123!")
				user := &user.User{
					ID:       uuid.New(),
					Name:     "Test User",
					Email:    "user@example.com",
					Password: hashedPassword,
					Role:     "user",
				}
				mockUser.On("GetUserByEmail", ctx, "user@example.com").Return(user, nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - User not found",
			request: &auth.LoginRequest{
				Email:    "notfound@example.com",
				Password: "Password123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockUser.On("GetUserByEmail", ctx, "notfound@example.com").
					Return(nil, user.ErrUserNotFound)
			},
			expectedError: auth.ErrInvalidCredentials,
		},
		{
			name: "Error - Wrong password",
			request: &auth.LoginRequest{
				Email:    "user@example.com",
				Password: "WrongPassword123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				user := &user.User{
					ID:       uuid.New(),
					Name:     "Test User",
					Email:    "user@example.com",
					Password: "$2a$10$hashedpassword", // Different hashed password
					Role:     "user",
				}
				mockUser.On("GetUserByEmail", ctx, "user@example.com").Return(user, nil)
			},
			expectedError: auth.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			user, err := service.Login(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
			}

			mockRepo.AssertExpectations(t)
			mockUserService.AssertExpectations(t)
		})
	}
}

// TestService_Logout tests the Logout service method.
func TestService_Logout(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *auth.LogoutRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Logout with valid refresh token",
			request: &auth.LogoutRequest{
				RefreshToken: "", // Will be set in test execution
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: nil,
		},
		{
			name: "Error - Validation fails (empty refresh token)",
			request: &auth.LogoutRequest{
				RefreshToken: "",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
		},
		{
			name: "Error - Token not found",
			request: &auth.LogoutRequest{
				RefreshToken: "invalid-refresh-token",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - JWT verification fails first
			},
			expectedError: auth.ErrTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			// For the success case, we need to replace the token with a real one
			if tt.name == "Success - Logout with valid refresh token" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeRefresh, cfg)
				tt.request.RefreshToken = validToken

				// Set up the mocks with the actual token
				token := &auth.TokenDB{
					ID:      uuid.New(),
					Token:   validToken,
					UserID:  userID,
					Type:    auth.TokenTypeRefresh,
					Expires: time.Now().Add(time.Hour),
				}
				mockRepo.On("FindTokenByTokenAndUserID", ctx, validToken, userID.String()).
					Return(token, nil)
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeRefresh, userID.String()).
					Return(nil)
			}

			err := service.Logout(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_RefreshAuth tests the RefreshAuth service method.
func TestService_RefreshAuth(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *auth.RefreshTokenRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Refresh auth with valid token",
			request: &auth.RefreshTokenRequest{
				RefreshToken: "", // Will be set in test execution
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: nil,
		},
		{
			name: "Error - Invalid token",
			request: &auth.RefreshTokenRequest{
				RefreshToken: "invalid-refresh-token",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - JWT verification fails first
			},
			expectedError: auth.ErrInvalidToken,
		},
		{
			name: "Error - User not found",
			request: &auth.RefreshTokenRequest{
				RefreshToken: "valid-refresh-token", // Will be replaced with real token
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: auth.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			// For the success case, we need to replace the token with a real one
			if tt.name == "Success - Refresh auth with valid token" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeRefresh, cfg)
				tt.request.RefreshToken = validToken

				// Set up the mocks with the actual token
				token := &auth.TokenDB{
					ID:      uuid.New(),
					Token:   validToken,
					UserID:  userID,
					Type:    auth.TokenTypeRefresh,
					Expires: time.Now().Add(time.Hour),
				}
				user := &user.User{
					ID:    userID,
					Name:  "Test User",
					Email: "user@example.com",
					Role:  "user",
				}
				mockRepo.On("FindTokenByTokenAndUserID", ctx, validToken, userID.String()).
					Return(token, nil)
				mockUserService.On("GetUserByID", ctx, userID.String()).Return(user, nil)
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeRefresh, userID.String()).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			} else if tt.name == "Error - User not found" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeRefresh, cfg)
				tt.request.RefreshToken = validToken

				// Set up the mocks with the actual token
				token := &auth.TokenDB{
					ID:      uuid.New(),
					Token:   validToken,
					UserID:  userID,
					Type:    auth.TokenTypeRefresh,
					Expires: time.Now().Add(time.Hour),
				}
				mockRepo.On("FindTokenByTokenAndUserID", ctx, validToken, userID.String()).
					Return(token, nil)
				mockUserService.On("GetUserByID", ctx, userID.String()).
					Return(nil, user.ErrUserNotFound)
			}

			tokens, err := service.RefreshAuth(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, tokens)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokens)
			}

			mockRepo.AssertExpectations(t)
			mockUserService.AssertExpectations(t)
		})
	}
}

// TestService_ResetPassword tests the ResetPassword service method.
func TestService_ResetPassword(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		query         *auth.ResetPasswordRequest
		request       *user.UpdateUserPasswordRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Reset password with valid token",
			query: &auth.ResetPasswordRequest{
				Token: "", // Will be set in test execution
			},
			request: &user.UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: nil,
		},
		{
			name: "Error - Invalid token",
			query: &auth.ResetPasswordRequest{
				Token: "invalid-token",
			},
			request: &user.UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - JWT verification fails
			},
			expectedError: auth.ErrInvalidToken,
		},
		{
			name: "Error - User not found",
			query: &auth.ResetPasswordRequest{
				Token: "valid-reset-token", // Will be replaced with real token
			},
			request: &user.UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: auth.ErrPasswordResetFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			// For the success case, we need to replace the token with a real one
			if tt.name == "Success - Reset password with valid token" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeResetPassword, cfg)
				tt.query.Token = validToken

				// Set up the mocks with the actual token
				user := &user.User{
					ID:    userID,
					Name:  "Test User",
					Email: "user@example.com",
					Role:  "user",
				}
				mockUserService.On("GetUserByID", ctx, userID.String()).Return(user, nil)
				mockUserService.On("UpdatePassOrVerify", ctx, mock.AnythingOfType("*user.UpdateUserPasswordRequest"), userID.String()).
					Return(nil)
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeResetPassword, userID.String()).Return(nil)
			} else if tt.name == "Error - User not found" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeResetPassword, cfg)
				tt.query.Token = validToken

				// Set up the mocks with the actual token
				mockUserService.On("GetUserByID", ctx, userID.String()).
					Return(nil, user.ErrUserNotFound)
			}

			err := service.ResetPassword(ctx, tt.query, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.name != "Error - Invalid token" {
				mockRepo.AssertExpectations(t)
				mockUserService.AssertExpectations(t)
			}
		})
	}
}

// TestService_VerifyEmail tests the VerifyEmail service method.
func TestService_VerifyEmail(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		query         *auth.ResetPasswordRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Verify email with valid token",
			query: &auth.ResetPasswordRequest{
				Token: "", // Will be set in test execution
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: nil,
		},
		{
			name: "Error - Invalid token",
			query: &auth.ResetPasswordRequest{
				Token: "invalid-token",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - JWT verification fails
			},
			expectedError: auth.ErrInvalidToken,
		},
		{
			name: "Error - User not found",
			query: &auth.ResetPasswordRequest{
				Token: "valid-verify-token", // Will be replaced with real token
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: auth.ErrVerifyEmailFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			// For the success case, we need to replace the token with a real one
			if tt.name == "Success - Verify email with valid token" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeVerifyEmail, cfg)
				tt.query.Token = validToken

				// Set up the mocks with the actual token
				user := &user.User{
					ID:    userID,
					Name:  "Test User",
					Email: "user@example.com",
					Role:  "user",
				}
				mockUserService.On("GetUserByID", ctx, userID.String()).Return(user, nil)
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeVerifyEmail, userID.String()).Return(nil)
				mockUserService.On("UpdatePassOrVerify", ctx, mock.AnythingOfType("*user.UpdateUserPasswordRequest"), userID.String()).
					Return(nil)
			} else if tt.name == "Error - User not found" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeVerifyEmail, cfg)
				tt.query.Token = validToken

				// Set up the mocks with the actual token
				mockUserService.On("GetUserByID", ctx, userID.String()).
					Return(nil, user.ErrUserNotFound)
			}

			err := service.VerifyEmail(ctx, tt.query)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.name != "Error - Invalid token" {
				mockRepo.AssertExpectations(t)
				mockUserService.AssertExpectations(t)
			}
		})
	}
}

// TestService_GenerateToken tests the GenerateToken service method.
func TestService_GenerateToken(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		expires       time.Time
		tokenType     string
		expectedError error
	}{
		{
			name:          "Success - Generate access token",
			userID:        uuid.New().String(),
			expires:       time.Now().Add(time.Hour),
			tokenType:     auth.TokenTypeAccess,
			expectedError: nil,
		},
		{
			name:          "Success - Generate refresh token",
			userID:        uuid.New().String(),
			expires:       time.Now().Add(time.Hour * 24),
			tokenType:     auth.TokenTypeRefresh,
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, _ := setupTestService()

			token, err := service.GenerateToken(tt.userID, tt.expires, tt.tokenType)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		})
	}
}

// TestService_SaveToken tests the SaveToken service method.
func TestService_SaveToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		token         string
		userID        string
		tokenType     string
		expires       time.Time
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name:      "Success - Save token",
			token:     "test-token",
			userID:    uuid.New().String(),
			tokenType: auth.TokenTypeAccess,
			expires:   time.Now().Add(time.Hour),
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeAccess, mock.AnythingOfType("string")).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "Error - Repository error",
			token:     "test-token",
			userID:    uuid.New().String(),
			tokenType: auth.TokenTypeAccess,
			expires:   time.Now().Add(time.Hour),
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeAccess, mock.AnythingOfType("string")).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).
					Return(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			err := service.SaveToken(ctx, tt.token, tt.userID, tt.tokenType, tt.expires)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_DeleteToken tests the DeleteToken service method.
func TestService_DeleteToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		tokenType     string
		userID        string
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name:      "Success - Delete token",
			tokenType: auth.TokenTypeRefresh,
			userID:    uuid.New().String(),
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeRefresh, mock.AnythingOfType("string")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "Error - Repository error",
			tokenType: auth.TokenTypeRefresh,
			userID:    uuid.New().String(),
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeRefresh, mock.AnythingOfType("string")).
					Return(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			err := service.DeleteToken(ctx, tt.tokenType, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GetTokenByUserID tests the GetTokenByUserID service method.
func TestService_GetTokenByUserID(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		tokenStr      string
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name:     "Success - Get token by user ID",
			tokenStr: "", // Will be set in test execution
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: nil,
		},
		{
			name:     "Error - Invalid token",
			tokenStr: "invalid-token",
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - JWT verification fails
			},
			expectedError: auth.ErrInvalidToken,
		},
		{
			name:     "Error - Token not found",
			tokenStr: "valid-refresh-token", // Will be replaced with real token
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// This will be set up in the test execution with the actual token
			},
			expectedError: auth.ErrTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			// For the success case, we need to replace the token with a real one
			if tt.name == "Success - Get token by user ID" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeRefresh, cfg)
				tt.tokenStr = validToken

				// Set up the mocks with the actual token
				token := &auth.TokenDB{
					ID:      uuid.New(),
					Token:   validToken,
					UserID:  userID,
					Type:    auth.TokenTypeRefresh,
					Expires: time.Now().Add(time.Hour),
				}
				mockRepo.On("FindTokenByTokenAndUserID", ctx, validToken, userID.String()).
					Return(token, nil)
			} else if tt.name == "Error - Token not found" {
				userID := uuid.New()
				cfg := &config.Config{
					JWT: config.JWTConfig{
						Secret:              "test-secret",
						AccessExpMinutes:    60,
						RefreshExpDays:      7,
						ResetPasswordExpMin: 15,
						VerifyEmailExpMin:   15,
					},
				}
				validToken, _ := generateTestToken(userID.String(), auth.TokenTypeRefresh, cfg)
				tt.tokenStr = validToken

				// Set up the mocks with the actual token
				mockRepo.On("FindTokenByTokenAndUserID", ctx, validToken, userID.String()).
					Return(nil, auth.ErrTokenNotFound)
			}

			token, err := service.GetTokenByUserID(ctx, tt.tokenStr)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, token)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, token)
			}

			if tt.name != "Error - Invalid token" {
				mockRepo.AssertExpectations(t)
			}
		})
	}
}

// TestService_GenerateAuthTokens tests the GenerateAuthTokens service method.
func TestService_GenerateAuthTokens(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		user          *user.User
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Generate auth tokens",
			user: &user.User{
				ID:    uuid.New(),
				Name:  "Test User",
				Email: "user@example.com",
				Role:  "user",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeRefresh, mock.AnythingOfType("string")).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Save token fails",
			user: &user.User{
				ID:    uuid.New(),
				Name:  "Test User",
				Email: "user@example.com",
				Role:  "user",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeRefresh, mock.AnythingOfType("string")).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).
					Return(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			tokens, err := service.GenerateAuthTokens(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, tokens)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokens)
				assert.NotEmpty(t, tokens.Access.Token)
				assert.NotEmpty(t, tokens.Refresh.Token)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GenerateResetPasswordToken tests the GenerateResetPasswordToken service method.
func TestService_GenerateResetPasswordToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *auth.ForgotPasswordRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Generate reset password token",
			request: &auth.ForgotPasswordRequest{
				Email: "user@example.com",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				user := &user.User{
					ID:    uuid.New(),
					Name:  "Test User",
					Email: "user@example.com",
					Role:  "user",
				}
				mockUser.On("GetUserByEmail", ctx, "user@example.com").Return(user, nil)
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeResetPassword, mock.AnythingOfType("string")).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Validation fails (empty email)",
			request: &auth.ForgotPasswordRequest{
				Email: "",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
		},
		{
			name: "Error - User not found",
			request: &auth.ForgotPasswordRequest{
				Email: "notfound@example.com",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockUser.On("GetUserByEmail", ctx, "notfound@example.com").
					Return(nil, user.ErrUserNotFound)
			},
			expectedError: user.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			token, err := service.GenerateResetPasswordToken(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
			}

			if tt.expectedError == nil {
				mockRepo.AssertExpectations(t)
				mockUserService.AssertExpectations(t)
			}
		})
	}
}

// TestService_GenerateVerifyEmailToken tests the GenerateVerifyEmailToken service method.
func TestService_GenerateVerifyEmailToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		user          *user.User
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Generate verify email token",
			user: &user.User{
				ID:    uuid.New(),
				Name:  "Test User",
				Email: "user@example.com",
				Role:  "user",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeVerifyEmail, mock.AnythingOfType("string")).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Token generation fails",
			user: &user.User{
				ID:    uuid.New(),
				Name:  "Test User",
				Email: "user@example.com",
				Role:  "user",
			},
			setupMock: func(mockRepo *MockRepository, mockUser *MockUserService) {
				mockRepo.On("DeleteToken", ctx, auth.TokenTypeVerifyEmail, mock.AnythingOfType("string")).Return(nil)
				mockRepo.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).
					Return(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			token, err := service.GenerateVerifyEmailToken(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, token)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, token)
				assert.NotEmpty(t, *token)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
