package user_test

import (
	"context"
	"errors"
	"testing"

	pkgErrors "go-rest-api/internal/common/errors"
	"go-rest-api/internal/common/validation"
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

func (m *MockRepository) FindAll(ctx context.Context, limit, offset int, search string) ([]user.User, error) {
	args := m.Called(ctx, limit, offset, search)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]user.User), args.Error(1)
}

func (m *MockRepository) Count(ctx context.Context, search string) (int64, error) {
	args := m.Called(ctx, search)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRepository) FindByID(ctx context.Context, id string) (*user.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockRepository) Create(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) Update(ctx context.Context, id string, user *user.User) (int64, error) {
	args := m.Called(ctx, id, user)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRepository) UpdateFields(ctx context.Context, id string, updates map[string]interface{}) (int64, error) {
	args := m.Called(ctx, id, updates)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRepository) Delete(ctx context.Context, id string) (int64, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRepository) Save(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// setupTestService creates a new service with a mock repository for testing.
func setupTestService() (user.Service, *MockRepository) {
	mockRepo := new(MockRepository)
	validate := validation.New()
	service := user.NewService(mockRepo, validate)
	return service, mockRepo
}

// TestNewService tests the service constructor.
func TestNewService(t *testing.T) {
	mockRepo := new(MockRepository)
	validate := validation.New()
	service := user.NewService(mockRepo, validate)

	assert.NotNil(t, service)
}

// TestService_GetUsers tests the GetUsers service method.
func TestService_GetUsers(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		params        *user.QueryUserRequest
		setupMock     func(*MockRepository)
		expectedUsers []user.User
		expectedCount int64
		expectedError error
	}{
		{
			name: "Success - Get users with default pagination",
			params: &user.QueryUserRequest{
				Page:   1,
				Limit:  10,
				Search: "",
			},
			setupMock: func(m *MockRepository) {
				users := []user.User{
					{ID: uuid.New(), Name: "User 1", Email: "user1@example.com", Role: "user"},
					{ID: uuid.New(), Name: "User 2", Email: "user2@example.com", Role: "admin"},
				}
				m.On("Count", ctx, "").Return(int64(2), nil)
				m.On("FindAll", ctx, 10, 0, "").Return(users, nil)
			},
			expectedCount: 2,
			expectedError: nil,
		},
		{
			name: "Success - Get users with search filter",
			params: &user.QueryUserRequest{
				Page:   1,
				Limit:  10,
				Search: "admin",
			},
			setupMock: func(m *MockRepository) {
				users := []user.User{
					{ID: uuid.New(), Name: "Admin User", Email: "admin@example.com", Role: "admin"},
				}
				m.On("Count", ctx, "admin").Return(int64(1), nil)
				m.On("FindAll", ctx, 10, 0, "admin").Return(users, nil)
			},
			expectedCount: 1,
			expectedError: nil,
		},
		{
			name: "Success - Get users with custom pagination",
			params: &user.QueryUserRequest{
				Page:   2,
				Limit:  5,
				Search: "",
			},
			setupMock: func(m *MockRepository) {
				users := []user.User{
					{ID: uuid.New(), Name: "User 6", Email: "user6@example.com", Role: "user"},
				}
				m.On("Count", ctx, "").Return(int64(6), nil)
				m.On("FindAll", ctx, 5, 5, "").Return(users, nil)
			},
			expectedCount: 6,
			expectedError: nil,
		},
		{
			name: "Error - Count fails",
			params: &user.QueryUserRequest{
				Page:   1,
				Limit:  10,
				Search: "",
			},
			setupMock: func(m *MockRepository) {
				m.On("Count", ctx, "").Return(int64(0), errors.New("database error"))
			},
			expectedCount: 0,
			expectedError: errors.New("database error"),
		},
		{
			name: "Error - FindAll fails",
			params: &user.QueryUserRequest{
				Page:   1,
				Limit:  10,
				Search: "",
			},
			setupMock: func(m *MockRepository) {
				m.On("Count", ctx, "").Return(int64(10), nil)
				m.On("FindAll", ctx, 10, 0, "").Return(nil, errors.New("database error"))
			},
			expectedCount: 0,
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			users, count, err := service.GetUsers(ctx, tt.params)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Equal(t, int64(0), count)
				assert.Nil(t, users)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, count)
				assert.NotNil(t, users)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GetUserByID tests the GetUserByID service method.
func TestService_GetUserByID(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		setupMock     func(*MockRepository)
		expectedUser  *user.User
		expectedError error
	}{
		{
			name:   "Success - Get user by ID",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				user := &user.User{
					ID:    validUUID,
					Name:  "Test User",
					Email: "test@example.com",
					Role:  "user",
				}
				m.On("FindByID", ctx, validUUID.String()).Return(user, nil)
			},
			expectedError: nil,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("FindByID", ctx, validUUID.String()).Return(nil, user.ErrUserNotFound)
			},
			expectedError: user.ErrUserNotFound,
		},
		{
			name:   "Error - Repository error",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("FindByID", ctx, validUUID.String()).Return(nil, errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			user, err := service.GetUserByID(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GetUserByEmail tests the GetUserByEmail service method.
func TestService_GetUserByEmail(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		email         string
		setupMock     func(*MockRepository)
		expectedUser  *user.User
		expectedError error
	}{
		{
			name:  "Success - Get user by email",
			email: "test@example.com",
			setupMock: func(m *MockRepository) {
				user := &user.User{
					ID:    uuid.New(),
					Name:  "Test User",
					Email: "test@example.com",
					Role:  "user",
				}
				m.On("FindByEmail", ctx, "test@example.com").Return(user, nil)
			},
			expectedError: nil,
		},
		{
			name:  "Error - User not found",
			email: "notfound@example.com",
			setupMock: func(m *MockRepository) {
				m.On("FindByEmail", ctx, "notfound@example.com").Return(nil, user.ErrUserNotFound)
			},
			expectedError: user.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			user, err := service.GetUserByEmail(ctx, tt.email)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_CreateUser tests the CreateUser service method.
func TestService_CreateUser(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *user.CreateUserRequest
		setupMock     func(*MockRepository)
		expectedError error
		checkError    func(*testing.T, error)
	}{
		{
			name: "Success - Create user",
			request: &user.CreateUserRequest{
				Name:     "New User",
				Email:    "newuser@example.com",
				Password: "Password123!",
				Role:     "user",
			},
			setupMock: func(m *MockRepository) {
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Email already taken",
			request: &user.CreateUserRequest{
				Name:     "Duplicate User",
				Email:    "duplicate@example.com",
				Password: "Password123!",
				Role:     "user",
			},
			setupMock: func(m *MockRepository) {
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(user.ErrEmailTaken)
			},
			expectedError: user.ErrEmailTaken,
		},
		{
			name: "Error - Validation fails (empty name)",
			request: &user.CreateUserRequest{
				Name:     "",
				Email:    "test@example.com",
				Password: "Password123!",
				Role:     "user",
			},
			setupMock: func(_ *MockRepository) {
				// No mock needed - validation fails first
			},
			checkError: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "Error - Repository error",
			request: &user.CreateUserRequest{
				Name:     "Test User",
				Email:    "test@example.com",
				Password: "Password123!",
				Role:     "user",
			},
			setupMock: func(m *MockRepository) {
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).
					Return(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			user, err := service.CreateUser(ctx, tt.request)

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

// TestService_UpdateUser tests the UpdateUser service method.
func TestService_UpdateUser(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		request       *user.UpdateUserRequest
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:   "Success - Update user name and email",
			userID: validUUID.String(),
			request: &user.UpdateUserRequest{
				Name:  "Updated Name",
				Email: "updated@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(1), nil)
				updatedUser := &user.User{
					ID:    validUUID,
					Name:  "Updated Name",
					Email: "updated@example.com",
				}
				m.On("FindByID", ctx, validUUID.String()).Return(updatedUser, nil)
			},
			expectedError: nil,
		},
		{
			name:   "Success - Update user password",
			userID: validUUID.String(),
			request: &user.UpdateUserRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(1), nil)
				updatedUser := &user.User{
					ID: validUUID,
				}
				m.On("FindByID", ctx, validUUID.String()).Return(updatedUser, nil)
			},
			expectedError: nil,
		},
		{
			name:   "Error - All fields empty",
			userID: validUUID.String(),
			request: &user.UpdateUserRequest{
				Name:     "",
				Email:    "",
				Password: "",
			},
			setupMock: func(_ *MockRepository) {
				// No mock needed
			},
			expectedError: pkgErrors.ErrBadRequest,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			request: &user.UpdateUserRequest{
				Name: "Updated Name",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(0), nil)
			},
			expectedError: user.ErrUserNotFound,
		},
		{
			name:   "Error - Email already taken",
			userID: validUUID.String(),
			request: &user.UpdateUserRequest{
				Email: "taken@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(0), user.ErrEmailTaken)
			},
			expectedError: user.ErrEmailTaken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			user, err := service.UpdateUser(ctx, tt.request, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_UpdatePassOrVerify tests the UpdatePassOrVerify service method.
func TestService_UpdatePassOrVerify(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		request       *user.UpdateUserPasswordRequest
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:   "Success - Update password",
			userID: validUUID.String(),
			request: &user.UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(1), nil)
			},
			expectedError: nil,
		},
		{
			name:   "Success - Verify email",
			userID: validUUID.String(),
			request: &user.UpdateUserPasswordRequest{
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(1), nil)
			},
			expectedError: nil,
		},
		{
			name:   "Success - Update password and verify email",
			userID: validUUID.String(),
			request: &user.UpdateUserPasswordRequest{
				Password:      "NewPassword123!",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(1), nil)
			},
			expectedError: nil,
		},
		{
			name:   "Error - Both fields empty/false",
			userID: validUUID.String(),
			request: &user.UpdateUserPasswordRequest{
				Password:      "",
				VerifiedEmail: false,
			},
			setupMock: func(_ *MockRepository) {
				// No mock needed
			},
			expectedError: pkgErrors.ErrBadRequest,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			request: &user.UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(0), nil)
			},
			expectedError: user.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			err := service.UpdatePassOrVerify(ctx, tt.request, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_DeleteUser tests the DeleteUser service method.
func TestService_DeleteUser(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:   "Success - Delete user",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("Delete", ctx, validUUID.String()).Return(int64(1), nil)
			},
			expectedError: nil,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("Delete", ctx, validUUID.String()).Return(int64(0), nil)
			},
			expectedError: user.ErrUserNotFound,
		},
		{
			name:   "Error - Repository error",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				m.On("Delete", ctx, validUUID.String()).Return(int64(0), errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			err := service.DeleteUser(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_CreateGoogleUser tests the CreateGoogleUser service method.
func TestService_CreateGoogleUser(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *user.CreateGoogleUserRequest
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name: "Success - Create new Google user",
			request: &user.CreateGoogleUserRequest{
				Name:          "Google User",
				Email:         "google@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				m.On("FindByEmail", ctx, "google@example.com").Return(nil, user.ErrUserNotFound)
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Success - Update existing user verification",
			request: &user.CreateGoogleUserRequest{
				Name:          "Existing User",
				Email:         "existing@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				existingUser := &user.User{
					ID:            uuid.New(),
					Name:          "Existing User",
					Email:         "existing@example.com",
					VerifiedEmail: false,
				}
				m.On("FindByEmail", ctx, "existing@example.com").Return(existingUser, nil)
				m.On("Save", ctx, mock.AnythingOfType("*user.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Validation fails (empty name)",
			request: &user.CreateGoogleUserRequest{
				Name:          "",
				Email:         "test@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(_ *MockRepository) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
		},
		{
			name: "Error - FindByEmail returns unexpected error",
			request: &user.CreateGoogleUserRequest{
				Name:          "Test User",
				Email:         "test@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				m.On("FindByEmail", ctx, "test@example.com").Return(nil, errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
		{
			name: "Error - Create fails",
			request: &user.CreateGoogleUserRequest{
				Name:          "New User",
				Email:         "new@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				m.On("FindByEmail", ctx, "new@example.com").Return(nil, user.ErrUserNotFound)
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(errors.New("create error"))
			},
			expectedError: errors.New("create error"),
		},
		{
			name: "Error - Save fails",
			request: &user.CreateGoogleUserRequest{
				Name:          "Existing User",
				Email:         "existing@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				existingUser := &user.User{
					ID:            uuid.New(),
					Name:          "Existing User",
					Email:         "existing@example.com",
					VerifiedEmail: false,
				}
				m.On("FindByEmail", ctx, "existing@example.com").Return(existingUser, nil)
				m.On("Save", ctx, mock.AnythingOfType("*user.User")).Return(errors.New("save error"))
			},
			expectedError: errors.New("save error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			user, err := service.CreateGoogleUser(ctx, tt.request)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.request.Email, user.Email)
				assert.Equal(t, tt.request.VerifiedEmail, user.VerifiedEmail)
			}

			if tt.name != "Error - Validation fails (empty name)" {
				mockRepo.AssertExpectations(t)
			}
		})
	}
}
