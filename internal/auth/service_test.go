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

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockRepository is a mock implementation of the auth Repository interface.
type MockRepository struct {
	mock.Mock
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

func (m *MockRepository) FindTokenByTokenAndUserID(
	ctx context.Context,
	tokenStr string,
	userID string,
) (*auth.TokenDB, error) {
	args := m.Called(ctx, tokenStr, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenDB), args.Error(1)
}

// setupTestService creates a new auth service with mock dependencies for testing.
func setupTestService() (auth.Service, *MockRepository, *MockUserService) {
	mockRepo := new(MockRepository)
	mockUserService := new(MockUserService)
	validate := validation.New()

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret-key-for-jwt-tokens",
		},
	}

	service := auth.NewService(mockRepo, validate, mockUserService, cfg)
	return service, mockRepo, mockUserService
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

// TestNewService tests the service constructor.
func TestNewService(t *testing.T) {
	mockRepo := new(MockRepository)
	mockUserService := new(MockUserService)
	validate := validation.New()
	cfg := &config.Config{}

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
		checkResult   func(*testing.T, *user.User)
	}{
		{
			name: "Success - Register new user",
			request: &auth.RegisterRequest{
				Name:     "New User",
				Email:    "newuser@example.com",
				Password: "Password123!",
			},
			setupMock: func(m *MockRepository, _ *MockUserService) {
				m.On("CreateUser", ctx, mock.AnythingOfType("*user.User")).Return(nil)
			},
			expectedError: nil,
			checkResult: func(t *testing.T, user *user.User) {
				assert.NotNil(t, user)
				assert.Equal(t, "New User", user.Name)
				assert.Equal(t, "newuser@example.com", user.Email)
				assert.NotEqual(t, "Password123!", user.Password) // Password should be hashed
				assert.Equal(t, "user", user.Role)
			},
		},
		{
			name: "Error - Email already taken",
			request: &auth.RegisterRequest{
				Name:     "Duplicate User",
				Email:    "duplicate@example.com",
				Password: "Password123!",
			},
			setupMock: func(m *MockRepository, _ *MockUserService) {
				m.On("CreateUser", ctx, mock.AnythingOfType("*user.User")).Return(auth.ErrEmailTaken)
			},
			expectedError: auth.ErrEmailTaken,
		},
		{
			name: "Error - Validation fails (empty name)",
			request: &auth.RegisterRequest{
				Name:     "",
				Email:    "test@example.com",
				Password: "Password123!",
			},
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
		},
		{
			name: "Error - Repository error",
			request: &auth.RegisterRequest{
				Name:     "Test User",
				Email:    "test@example.com",
				Password: "Password123!",
			},
			setupMock: func(m *MockRepository, _ *MockUserService) {
				m.On("CreateUser", ctx, mock.AnythingOfType("*user.User")).
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

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, user)
			} else if tt.checkResult != nil {
				require.NoError(t, err)
				assert.NotNil(t, user)
				tt.checkResult(t, user)
			}

			if tt.name != "Error - Validation fails (empty name)" {
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
		setupMock     func(*MockUserService)
		expectedError error
		checkResult   func(*testing.T, *user.User)
	}{
		{
			name: "Success - Login with valid credentials",
			request: &auth.LoginRequest{
				Email:    "user@example.com",
				Password: "Password123!",
			},
			setupMock: func(u *MockUserService) {
				// Hash the password properly for testing
				hashedPassword, _ := crypto.HashPassword("Password123!")
				user := &user.User{
					ID:       uuid.New(),
					Name:     "Test User",
					Email:    "user@example.com",
					Password: hashedPassword,
					Role:     "user",
				}
				u.On("GetUserByEmail", ctx, "user@example.com").Return(user, nil)
			},
			expectedError: nil,
			checkResult: func(t *testing.T, user *user.User) {
				assert.NotNil(t, user)
				assert.Equal(t, "user@example.com", user.Email)
			},
		},
		{
			name: "Error - User not found",
			request: &auth.LoginRequest{
				Email:    "notfound@example.com",
				Password: "Password123!",
			},
			setupMock: func(u *MockUserService) {
				u.On("GetUserByEmail", ctx, "notfound@example.com").Return(nil, user.ErrUserNotFound)
			},
			expectedError: auth.ErrInvalidCredentials,
		},
		{
			name: "Error - Invalid password",
			request: &auth.LoginRequest{
				Email:    "user@example.com",
				Password: "WrongPass1!",
			},
			setupMock: func(u *MockUserService) {
				// Hash a different password for testing
				hashedPassword, _ := crypto.HashPassword("CorrectPass1!")
				user := &user.User{
					ID:       uuid.New(),
					Name:     "Test User",
					Email:    "user@example.com",
					Password: hashedPassword,
					Role:     "user",
				}
				u.On("GetUserByEmail", ctx, "user@example.com").Return(user, nil)
			},
			expectedError: auth.ErrInvalidCredentials,
		},
		{
			name: "Error - Validation fails (empty email)",
			request: &auth.LoginRequest{
				Email:    "",
				Password: "Password123!",
			},
			setupMock: func(_ *MockUserService) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockUserService := setupTestService()
			tt.setupMock(mockUserService)

			user, err := service.Login(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, user)
			} else if tt.checkResult != nil {
				require.NoError(t, err)
				assert.NotNil(t, user)
				tt.checkResult(t, user)
			}

			if tt.name != "Error - Validation fails (empty email)" {
				mockUserService.AssertExpectations(t)
			}
		})
	}
}

// TestService_Logout tests the Logout service method.
func TestService_Logout(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	// Generate a valid JWT token for the success test
	validToken, err := generateTestJWT(validUUID.String(), auth.TokenTypeRefresh, "test-secret-key-for-jwt-tokens")
	require.NoError(t, err)

	tests := []struct {
		name          string
		request       *auth.LogoutRequest
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name: "Success - Logout with valid refresh token",
			request: &auth.LogoutRequest{
				RefreshToken: validToken,
			},
			setupMock: func(m *MockRepository) {
				token := &auth.TokenDB{
					ID:     uuid.New(),
					UserID: validUUID,
					Type:   auth.TokenTypeRefresh,
				}
				m.On("FindTokenByTokenAndUserID", ctx, validToken, validUUID.String()).
					Return(token, nil)
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Token not found",
			request: &auth.LogoutRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(_ *MockRepository) {
				// JWT validation fails before repository is called, so no mock needed
			},
			expectedError: auth.ErrTokenNotFound,
		},
		{
			name: "Error - Validation fails (empty refresh token)",
			request: &auth.LogoutRequest{
				RefreshToken: "",
			},
			setupMock: func(_ *MockRepository) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, _ := setupTestService()
			tt.setupMock(mockRepo)

			logoutErr := service.Logout(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, logoutErr)
			} else {
				require.NoError(t, logoutErr)
			}

			if tt.name != "Error - Validation fails (empty refresh token)" {
				mockRepo.AssertExpectations(t)
			}
		})
	}
}

// TestService_RefreshAuth tests the RefreshAuth service method.
func TestService_RefreshAuth(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	// Generate a valid JWT token for the success test
	validToken, err := generateTestJWT(validUUID.String(), auth.TokenTypeRefresh, "test-secret-key-for-jwt-tokens")
	require.NoError(t, err)

	tests := []struct {
		name          string
		request       *auth.RefreshTokenRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
		checkResult   func(*testing.T, *auth.Tokens)
	}{
		{
			name: "Success - Refresh tokens with valid refresh token",
			request: &auth.RefreshTokenRequest{
				RefreshToken: validToken,
			},
			setupMock: func(m *MockRepository, u *MockUserService) {
				token := &auth.TokenDB{
					ID:     uuid.New(),
					UserID: validUUID,
					Type:   auth.TokenTypeRefresh,
				}
				user := &user.User{
					ID:    validUUID,
					Name:  "Test User",
					Email: "user@example.com",
				}
				m.On("FindTokenByTokenAndUserID", ctx, validToken, validUUID.String()).
					Return(token, nil)
				u.On("GetUserByID", ctx, validUUID.String()).Return(user, nil)
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
			checkResult: func(t *testing.T, tokens *auth.Tokens) {
				assert.NotNil(t, tokens)
				assert.NotEmpty(t, tokens.Access.Token)
				assert.NotEmpty(t, tokens.Refresh.Token)
			},
		},
		{
			name: "Error - Invalid refresh token",
			request: &auth.RefreshTokenRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// JWT validation fails before repository is called, so no mock needed
			},
			expectedError: auth.ErrInvalidToken,
		},
		{
			name: "Error - User not found",
			request: &auth.RefreshTokenRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// JWT validation fails before repository is called, so no mock needed
			},
			expectedError: auth.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			tokens, refreshErr := service.RefreshAuth(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, refreshErr)
				assert.Nil(t, tokens)
			} else if tt.checkResult != nil {
				require.NoError(t, refreshErr)
				assert.NotNil(t, tokens)
				tt.checkResult(t, tokens)
			}

			mockRepo.AssertExpectations(t)
			mockUserService.AssertExpectations(t)
		})
	}
}

// TestService_ResetPassword tests the ResetPassword service method.
func TestService_ResetPassword(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	// Generate a valid JWT token for the success test
	validToken, err := generateTestJWT(
		validUUID.String(),
		auth.TokenTypeResetPassword,
		"test-secret-key-for-jwt-tokens",
	)
	require.NoError(t, err)

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
				Token: validToken,
			},
			request: &user.UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(m *MockRepository, u *MockUserService) {
				user := &user.User{
					ID:    validUUID,
					Name:  "Test User",
					Email: "user@example.com",
				}
				u.On("GetUserByID", ctx, validUUID.String()).Return(user, nil)
				u.On("UpdatePassOrVerify", ctx, mock.AnythingOfType("*user.UpdateUserPasswordRequest"), validUUID.String()).
					Return(nil)
				m.On("DeleteToken", ctx, auth.TokenTypeResetPassword, validUUID.String()).Return(nil)
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
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// No mock needed - JWT verification fails first
			},
			expectedError: auth.ErrInvalidToken,
		},
		{
			name: "Error - User not found",
			query: &auth.ResetPasswordRequest{
				Token: "invalid-token",
			},
			request: &user.UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// JWT validation fails before user lookup, so no mock needed
			},
			expectedError: auth.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			resetErr := service.ResetPassword(ctx, tt.query, tt.request)

			if tt.expectedError != nil {
				require.Error(t, resetErr)
			} else {
				require.NoError(t, resetErr)
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
	validUUID := uuid.New()

	// Generate a valid JWT token for the success test
	validToken, err := generateTestJWT(validUUID.String(), auth.TokenTypeVerifyEmail, "test-secret-key-for-jwt-tokens")
	require.NoError(t, err)

	tests := []struct {
		name          string
		query         *auth.ResetPasswordRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
	}{
		{
			name: "Success - Verify email with valid token",
			query: &auth.ResetPasswordRequest{
				Token: validToken,
			},
			setupMock: func(m *MockRepository, u *MockUserService) {
				user := &user.User{
					ID:    validUUID,
					Name:  "Test User",
					Email: "user@example.com",
				}
				u.On("GetUserByID", ctx, validUUID.String()).Return(user, nil)
				m.On("DeleteToken", ctx, auth.TokenTypeVerifyEmail, validUUID.String()).Return(nil)
				u.On("UpdatePassOrVerify", ctx, mock.AnythingOfType("*user.UpdateUserPasswordRequest"), validUUID.String()).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Invalid token",
			query: &auth.ResetPasswordRequest{
				Token: "invalid-token",
			},
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// No mock needed - JWT verification fails first
			},
			expectedError: auth.ErrInvalidToken,
		},
		{
			name: "Error - User not found",
			query: &auth.ResetPasswordRequest{
				Token: "invalid-token",
			},
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// JWT validation fails before user lookup, so no mock needed
			},
			expectedError: auth.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, mockUserService := setupTestService()
			tt.setupMock(mockRepo, mockUserService)

			verifyErr := service.VerifyEmail(ctx, tt.query)

			if tt.expectedError != nil {
				require.Error(t, verifyErr)
			} else {
				require.NoError(t, verifyErr)
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
	service, _, _ := setupTestService()

	tests := []struct {
		name        string
		userID      string
		expires     time.Time
		tokenType   string
		expectError bool
	}{
		{
			name:        "Success - Generate access token",
			userID:      uuid.New().String(),
			expires:     time.Now().Add(time.Hour),
			tokenType:   auth.TokenTypeAccess,
			expectError: false,
		},
		{
			name:        "Success - Generate refresh token",
			userID:      uuid.New().String(),
			expires:     time.Now().Add(24 * time.Hour),
			tokenType:   auth.TokenTypeRefresh,
			expectError: false,
		},
		{
			name:        "Success - Generate reset password token",
			userID:      uuid.New().String(),
			expires:     time.Now().Add(time.Hour),
			tokenType:   auth.TokenTypeResetPassword,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := service.GenerateToken(tt.userID, tt.expires, tt.tokenType)

			if tt.expectError {
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
	validUUID := uuid.New()

	tests := []struct {
		name          string
		token         string
		userID        string
		tokenType     string
		expires       time.Time
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:      "Success - Save token",
			token:     "test-token",
			userID:    validUUID.String(),
			tokenType: auth.TokenTypeRefresh,
			expires:   time.Now().Add(time.Hour),
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "Error - Delete token fails",
			token:     "test-token",
			userID:    validUUID.String(),
			tokenType: auth.TokenTypeRefresh,
			expires:   time.Now().Add(time.Hour),
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(errors.New("delete error"))
			},
			expectedError: errors.New("delete error"),
		},
		{
			name:      "Error - Create token fails",
			token:     "test-token",
			userID:    validUUID.String(),
			tokenType: auth.TokenTypeRefresh,
			expires:   time.Now().Add(time.Hour),
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(errors.New("create error"))
			},
			expectedError: errors.New("create error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, _ := setupTestService()
			tt.setupMock(mockRepo)

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
	validUUID := uuid.New()

	tests := []struct {
		name          string
		tokenType     string
		userID        string
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:      "Success - Delete token",
			tokenType: auth.TokenTypeRefresh,
			userID:    validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "Error - Repository error",
			tokenType: auth.TokenTypeRefresh,
			userID:    validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(errors.New("delete error"))
			},
			expectedError: errors.New("delete error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, _ := setupTestService()
			tt.setupMock(mockRepo)

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

// TestService_DeleteAllToken tests the DeleteAllToken service method.
func TestService_DeleteAllToken(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:   "Success - Delete all tokens",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("DeleteAllTokens", ctx, validUUID.String()).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "Error - Repository error",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("DeleteAllTokens", ctx, validUUID.String()).Return(errors.New("delete error"))
			},
			expectedError: errors.New("delete error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, _ := setupTestService()
			tt.setupMock(mockRepo)

			err := service.DeleteAllToken(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GenerateAuthTokens tests the GenerateAuthTokens service method.
func TestService_GenerateAuthTokens(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		user          *user.User
		setupMock     func(*MockRepository)
		expectedError error
		checkResult   func(*testing.T, *auth.Tokens)
	}{
		{
			name: "Success - Generate auth tokens",
			user: &user.User{
				ID:    validUUID,
				Name:  "Test User",
				Email: "user@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
			checkResult: func(t *testing.T, tokens *auth.Tokens) {
				assert.NotNil(t, tokens)
				assert.NotEmpty(t, tokens.Access.Token)
				assert.NotEmpty(t, tokens.Refresh.Token)
				assert.True(t, tokens.Access.Expires.After(time.Now().Add(-time.Minute)))
				assert.True(t, tokens.Refresh.Expires.After(time.Now().Add(-time.Minute)))
			},
		},
		{
			name: "Error - Save token fails",
			user: &user.User{
				ID:    validUUID,
				Name:  "Test User",
				Email: "user@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeRefresh, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(errors.New("save error"))
			},
			expectedError: errors.New("save error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, _ := setupTestService()
			tt.setupMock(mockRepo)

			tokens, err := service.GenerateAuthTokens(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, tokens)
			} else if tt.checkResult != nil {
				require.NoError(t, err)
				assert.NotNil(t, tokens)
				tt.checkResult(t, tokens)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GenerateResetPasswordToken tests the GenerateResetPasswordToken service method.
func TestService_GenerateResetPasswordToken(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		request       *auth.ForgotPasswordRequest
		setupMock     func(*MockRepository, *MockUserService)
		expectedError error
		checkResult   func(*testing.T, string)
	}{
		{
			name: "Success - Generate reset password token",
			request: &auth.ForgotPasswordRequest{
				Email: "user@example.com",
			},
			setupMock: func(m *MockRepository, u *MockUserService) {
				user := &user.User{
					ID:    validUUID,
					Name:  "Test User",
					Email: "user@example.com",
				}
				u.On("GetUserByEmail", ctx, "user@example.com").Return(user, nil)
				m.On("DeleteToken", ctx, auth.TokenTypeResetPassword, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
			checkResult: func(t *testing.T, token string) {
				assert.NotEmpty(t, token)
			},
		},
		{
			name: "Error - User not found",
			request: &auth.ForgotPasswordRequest{
				Email: "notfound@example.com",
			},
			setupMock: func(_ *MockRepository, u *MockUserService) {
				u.On("GetUserByEmail", ctx, "notfound@example.com").Return(nil, user.ErrUserNotFound)
			},
			expectedError: user.ErrUserNotFound,
		},
		{
			name: "Error - Validation fails (empty email)",
			request: &auth.ForgotPasswordRequest{
				Email: "",
			},
			setupMock: func(_ *MockRepository, _ *MockUserService) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
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
			} else if tt.checkResult != nil {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
				tt.checkResult(t, token)
			}

			if tt.name != "Error - Validation fails (empty email)" {
				mockRepo.AssertExpectations(t)
				mockUserService.AssertExpectations(t)
			}
		})
	}
}

// TestService_GenerateVerifyEmailToken tests the GenerateVerifyEmailToken service method.
func TestService_GenerateVerifyEmailToken(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		user          *user.User
		setupMock     func(*MockRepository)
		expectedError error
		checkResult   func(*testing.T, *string)
	}{
		{
			name: "Success - Generate verify email token",
			user: &user.User{
				ID:    validUUID,
				Name:  "Test User",
				Email: "user@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeVerifyEmail, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(nil)
			},
			expectedError: nil,
			checkResult: func(t *testing.T, token *string) {
				assert.NotNil(t, token)
				assert.NotEmpty(t, *token)
			},
		},
		{
			name: "Error - Save token fails",
			user: &user.User{
				ID:    validUUID,
				Name:  "Test User",
				Email: "user@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("DeleteToken", ctx, auth.TokenTypeVerifyEmail, validUUID.String()).Return(nil)
				m.On("CreateToken", ctx, mock.AnythingOfType("*auth.TokenDB")).Return(errors.New("save error"))
			},
			expectedError: errors.New("save error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo, _ := setupTestService()
			tt.setupMock(mockRepo)

			token, err := service.GenerateVerifyEmailToken(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, token)
			} else if tt.checkResult != nil {
				require.NoError(t, err)
				assert.NotNil(t, token)
				tt.checkResult(t, token)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
