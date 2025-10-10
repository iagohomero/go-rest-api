package user

import (
	"context"
	"errors"
	"testing"

	pkgErrors "go-rest-api/internal/common/errors"
	"go-rest-api/internal/common/validation"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRepository is a mock implementation of the Repository interface
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) FindAll(ctx context.Context, limit, offset int, search string) ([]User, error) {
	args := m.Called(ctx, limit, offset, search)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]User), args.Error(1)
}

func (m *MockRepository) Count(ctx context.Context, search string) (int64, error) {
	args := m.Called(ctx, search)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRepository) FindByID(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) FindByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) Create(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) Update(ctx context.Context, id string, user *User) (int64, error) {
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

func (m *MockRepository) Save(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// setupTestService creates a new service with a mock repository for testing
func setupTestService() (Service, *MockRepository) {
	mockRepo := new(MockRepository)
	validate := validation.New()
	service := NewService(mockRepo, validate)
	return service, mockRepo
}

// TestNewService tests the service constructor
func TestNewService(t *testing.T) {
	mockRepo := new(MockRepository)
	validate := validation.New()
	service := NewService(mockRepo, validate)

	assert.NotNil(t, service)
}

// TestService_GetUsers tests the GetUsers service method
func TestService_GetUsers(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		params        *QueryUserRequest
		setupMock     func(*MockRepository)
		expectedUsers []User
		expectedCount int64
		expectedError error
	}{
		{
			name: "Success - Get users with default pagination",
			params: &QueryUserRequest{
				Page:   1,
				Limit:  10,
				Search: "",
			},
			setupMock: func(m *MockRepository) {
				users := []User{
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
			params: &QueryUserRequest{
				Page:   1,
				Limit:  10,
				Search: "admin",
			},
			setupMock: func(m *MockRepository) {
				users := []User{
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
			params: &QueryUserRequest{
				Page:   2,
				Limit:  5,
				Search: "",
			},
			setupMock: func(m *MockRepository) {
				users := []User{
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
			params: &QueryUserRequest{
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
			params: &QueryUserRequest{
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
				assert.Error(t, err)
				assert.Equal(t, int64(0), count)
				assert.Nil(t, users)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCount, count)
				assert.NotNil(t, users)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GetUserByID tests the GetUserByID service method
func TestService_GetUserByID(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		setupMock     func(*MockRepository)
		expectedUser  *User
		expectedError error
	}{
		{
			name:   "Success - Get user by ID",
			userID: validUUID.String(),
			setupMock: func(m *MockRepository) {
				user := &User{
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
				m.On("FindByID", ctx, validUUID.String()).Return(nil, ErrUserNotFound)
			},
			expectedError: ErrUserNotFound,
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
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_GetUserByEmail tests the GetUserByEmail service method
func TestService_GetUserByEmail(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		email         string
		setupMock     func(*MockRepository)
		expectedUser  *User
		expectedError error
	}{
		{
			name:  "Success - Get user by email",
			email: "test@example.com",
			setupMock: func(m *MockRepository) {
				user := &User{
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
				m.On("FindByEmail", ctx, "notfound@example.com").Return(nil, ErrUserNotFound)
			},
			expectedError: ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			user, err := service.GetUserByEmail(ctx, tt.email)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_CreateUser tests the CreateUser service method
func TestService_CreateUser(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *CreateUserRequest
		setupMock     func(*MockRepository)
		expectedError error
		checkError    func(*testing.T, error)
	}{
		{
			name: "Success - Create user",
			request: &CreateUserRequest{
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
			request: &CreateUserRequest{
				Name:     "Duplicate User",
				Email:    "duplicate@example.com",
				Password: "Password123!",
				Role:     "user",
			},
			setupMock: func(m *MockRepository) {
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(ErrEmailTaken)
			},
			expectedError: ErrEmailTaken,
		},
		{
			name: "Error - Validation fails (empty name)",
			request: &CreateUserRequest{
				Name:     "",
				Email:    "test@example.com",
				Password: "Password123!",
				Role:     "user",
			},
			setupMock: func(m *MockRepository) {
				// No mock needed - validation fails first
			},
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "Error - Repository error",
			request: &CreateUserRequest{
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

			if tt.checkError != nil {
				tt.checkError(t, err)
			} else if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
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

// TestService_UpdateUser tests the UpdateUser service method
func TestService_UpdateUser(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		request       *UpdateUserRequest
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:   "Success - Update user name and email",
			userID: validUUID.String(),
			request: &UpdateUserRequest{
				Name:  "Updated Name",
				Email: "updated@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(1), nil)
				updatedUser := &User{
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
			request: &UpdateUserRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(1), nil)
				updatedUser := &User{
					ID: validUUID,
				}
				m.On("FindByID", ctx, validUUID.String()).Return(updatedUser, nil)
			},
			expectedError: nil,
		},
		{
			name:   "Error - All fields empty",
			userID: validUUID.String(),
			request: &UpdateUserRequest{
				Name:     "",
				Email:    "",
				Password: "",
			},
			setupMock: func(m *MockRepository) {
				// No mock needed
			},
			expectedError: pkgErrors.ErrBadRequest,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			request: &UpdateUserRequest{
				Name: "Updated Name",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(0), nil)
			},
			expectedError: ErrUserNotFound,
		},
		{
			name:   "Error - Email already taken",
			userID: validUUID.String(),
			request: &UpdateUserRequest{
				Email: "taken@example.com",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(0), ErrEmailTaken)
			},
			expectedError: ErrEmailTaken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			user, err := service.UpdateUser(ctx, tt.request, tt.userID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_UpdatePassOrVerify tests the UpdatePassOrVerify service method
func TestService_UpdatePassOrVerify(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		request       *UpdateUserPasswordRequest
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name:   "Success - Update password",
			userID: validUUID.String(),
			request: &UpdateUserPasswordRequest{
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
			request: &UpdateUserPasswordRequest{
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
			request: &UpdateUserPasswordRequest{
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
			request: &UpdateUserPasswordRequest{
				Password:      "",
				VerifiedEmail: false,
			},
			setupMock: func(m *MockRepository) {
				// No mock needed
			},
			expectedError: pkgErrors.ErrBadRequest,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			request: &UpdateUserPasswordRequest{
				Password: "NewPassword123!",
			},
			setupMock: func(m *MockRepository) {
				m.On("Update", ctx, validUUID.String(), mock.AnythingOfType("*user.User")).
					Return(int64(0), nil)
			},
			expectedError: ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := setupTestService()
			tt.setupMock(mockRepo)

			err := service.UpdatePassOrVerify(ctx, tt.request, tt.userID)

			if tt.expectedError != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_DeleteUser tests the DeleteUser service method
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
			expectedError: ErrUserNotFound,
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
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// TestService_CreateGoogleUser tests the CreateGoogleUser service method
func TestService_CreateGoogleUser(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		request       *CreateGoogleUserRequest
		setupMock     func(*MockRepository)
		expectedError error
	}{
		{
			name: "Success - Create new Google user",
			request: &CreateGoogleUserRequest{
				Name:          "Google User",
				Email:         "google@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				m.On("FindByEmail", ctx, "google@example.com").Return(nil, ErrUserNotFound)
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Success - Update existing user verification",
			request: &CreateGoogleUserRequest{
				Name:          "Existing User",
				Email:         "existing@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				existingUser := &User{
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
			request: &CreateGoogleUserRequest{
				Name:          "",
				Email:         "test@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				// No mock needed - validation fails first
			},
			expectedError: errors.New("validation error"),
		},
		{
			name: "Error - FindByEmail returns unexpected error",
			request: &CreateGoogleUserRequest{
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
			request: &CreateGoogleUserRequest{
				Name:          "New User",
				Email:         "new@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				m.On("FindByEmail", ctx, "new@example.com").Return(nil, ErrUserNotFound)
				m.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(errors.New("create error"))
			},
			expectedError: errors.New("create error"),
		},
		{
			name: "Error - Save fails",
			request: &CreateGoogleUserRequest{
				Name:          "Existing User",
				Email:         "existing@example.com",
				VerifiedEmail: true,
			},
			setupMock: func(m *MockRepository) {
				existingUser := &User{
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
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
