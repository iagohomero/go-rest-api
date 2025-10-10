package user

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockService is a mock implementation of the Service interface
type MockService struct {
	mock.Mock
}

func (m *MockService) GetUsers(ctx context.Context, params *QueryUserRequest) ([]User, int64, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]User), args.Get(1).(int64), args.Error(2)
}

func (m *MockService) GetUserByID(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockService) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockService) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockService) UpdatePassOrVerify(ctx context.Context, req *UpdateUserPasswordRequest, id string) error {
	args := m.Called(ctx, req, id)
	return args.Error(0)
}

func (m *MockService) UpdateUser(ctx context.Context, req *UpdateUserRequest, id string) (*User, error) {
	args := m.Called(ctx, req, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockService) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockService) CreateGoogleUser(ctx context.Context, req *CreateGoogleUserRequest) (*User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

// setupTestHandler creates a new handler with a mock service for testing
func setupTestHandler() (*Handler, *MockService) {
	mockService := new(MockService)
	handler := NewHandler(mockService)
	return handler, mockService
}

// setupFiberApp creates a Fiber app for testing
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

// TestNewHandler tests the handler constructor
func TestNewHandler(t *testing.T) {
	mockService := new(MockService)
	handler := NewHandler(mockService)

	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.service)
}

// TestHandler_GetUsers tests the GetUsers handler
func TestHandler_GetUsers(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		setupMock      func(*MockService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:        "Success - Get users with default pagination",
			queryParams: "",
			setupMock: func(m *MockService) {
				users := []User{
					{ID: uuid.New(), Name: "User 1", Email: "user1@example.com", Role: "user"},
					{ID: uuid.New(), Name: "User 2", Email: "user2@example.com", Role: "admin"},
				}
				m.On("GetUsers", mock.Anything, &QueryUserRequest{Page: 1, Limit: 10, Search: ""}).
					Return(users, int64(2), nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Success - Get users with custom pagination",
			queryParams: "?page=2&limit=5",
			setupMock: func(m *MockService) {
				users := []User{
					{ID: uuid.New(), Name: "User 3", Email: "user3@example.com", Role: "user"},
				}
				m.On("GetUsers", mock.Anything, &QueryUserRequest{Page: 2, Limit: 5, Search: ""}).
					Return(users, int64(6), nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Success - Get users with search filter",
			queryParams: "?search=admin",
			setupMock: func(m *MockService) {
				users := []User{
					{ID: uuid.New(), Name: "Admin User", Email: "admin@example.com", Role: "admin"},
				}
				m.On("GetUsers", mock.Anything, &QueryUserRequest{Page: 1, Limit: 10, Search: "admin"}).
					Return(users, int64(1), nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Service returns error",
			queryParams: "",
			setupMock: func(m *MockService) {
				m.On("GetUsers", mock.Anything, &QueryUserRequest{Page: 1, Limit: 10, Search: ""}).
					Return(nil, int64(0), errors.New("database error"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockService)

			app.Get("/users", handler.GetUsers)

			req := httptest.NewRequest("GET", "/users"+tt.queryParams, nil)
			resp, err := app.Test(req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			mockService.AssertExpectations(t)
		})
	}
}

// TestHandler_GetUserByID tests the GetUserByID handler
func TestHandler_GetUserByID(t *testing.T) {
	validUUID := uuid.New()

	tests := []struct {
		name           string
		userID         string
		setupMock      func(*MockService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:   "Success - Get user by valid ID",
			userID: validUUID.String(),
			setupMock: func(m *MockService) {
				user := &User{
					ID:    validUUID,
					Name:  "Test User",
					Email: "test@example.com",
					Role:  "user",
				}
				m.On("GetUserByID", mock.Anything, validUUID.String()).Return(user, nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:   "Error - Invalid UUID format",
			userID: "invalid-uuid",
			setupMock: func(m *MockService) {
				// No mock setup needed as validation happens before service call
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			setupMock: func(m *MockService) {
				m.On("GetUserByID", mock.Anything, validUUID.String()).Return(nil, ErrUserNotFound)
			},
			expectedStatus: fiber.StatusNotFound,
			expectedError:  true,
		},
		{
			name:   "Error - Service returns error",
			userID: validUUID.String(),
			setupMock: func(m *MockService) {
				m.On("GetUserByID", mock.Anything, validUUID.String()).Return(nil, errors.New("database error"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockService)

			app.Get("/users/:userId", handler.GetUserByID)

			req := httptest.NewRequest("GET", "/users/"+tt.userID, nil)
			resp, err := app.Test(req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError && tt.name == "Success - Get user by valid ID" {
				mockService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_CreateUser tests the CreateUser handler
func TestHandler_CreateUser(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Create user with valid data",
			requestBody: CreateUserRequest{
				Name:     "New User",
				Email:    "newuser@example.com",
				Password: "password123",
				Role:     "user",
			},
			setupMock: func(m *MockService) {
				createdUser := &User{
					ID:    uuid.New(),
					Name:  "New User",
					Email: "newuser@example.com",
					Role:  "user",
				}
				m.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.CreateUserRequest")).
					Return(createdUser, nil)
			},
			expectedStatus: fiber.StatusCreated,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid JSON body",
			requestBody: "invalid json",
			setupMock: func(m *MockService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Error - Email already taken",
			requestBody: CreateUserRequest{
				Name:     "Duplicate User",
				Email:    "duplicate@example.com",
				Password: "password123",
				Role:     "user",
			},
			setupMock: func(m *MockService) {
				m.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.CreateUserRequest")).
					Return(nil, ErrEmailTaken)
			},
			expectedStatus: fiber.StatusConflict,
			expectedError:  true,
		},
		{
			name: "Error - Service returns error",
			requestBody: CreateUserRequest{
				Name:     "Error User",
				Email:    "error@example.com",
				Password: "password123",
				Role:     "user",
			},
			setupMock: func(m *MockService) {
				m.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.CreateUserRequest")).
					Return(nil, errors.New("database error"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockService)

			app.Post("/users", handler.CreateUser)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_UpdateUser tests the UpdateUser handler
func TestHandler_UpdateUser(t *testing.T) {
	validUUID := uuid.New()

	tests := []struct {
		name           string
		userID         string
		requestBody    interface{}
		setupMock      func(*MockService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:   "Success - Update user with valid data",
			userID: validUUID.String(),
			requestBody: UpdateUserRequest{
				Name:  "Updated Name",
				Email: "updated@example.com",
			},
			setupMock: func(m *MockService) {
				updatedUser := &User{
					ID:    validUUID,
					Name:  "Updated Name",
					Email: "updated@example.com",
					Role:  "user",
				}
				m.On("UpdateUser", mock.Anything, mock.AnythingOfType("*user.UpdateUserRequest"), validUUID.String()).
					Return(updatedUser, nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:        "Error - Invalid UUID",
			userID:      "invalid-uuid",
			requestBody: UpdateUserRequest{Name: "Test"},
			setupMock: func(m *MockService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:        "Error - Invalid JSON body",
			userID:      validUUID.String(),
			requestBody: "invalid json",
			setupMock: func(m *MockService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			requestBody: UpdateUserRequest{
				Name: "Updated Name",
			},
			setupMock: func(m *MockService) {
				m.On("UpdateUser", mock.Anything, mock.AnythingOfType("*user.UpdateUserRequest"), validUUID.String()).
					Return(nil, ErrUserNotFound)
			},
			expectedStatus: fiber.StatusNotFound,
			expectedError:  true,
		},
		{
			name:   "Error - Email already taken",
			userID: validUUID.String(),
			requestBody: UpdateUserRequest{
				Email: "taken@example.com",
			},
			setupMock: func(m *MockService) {
				m.On("UpdateUser", mock.Anything, mock.AnythingOfType("*user.UpdateUserRequest"), validUUID.String()).
					Return(nil, ErrEmailTaken)
			},
			expectedStatus: fiber.StatusConflict,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockService)

			app.Patch("/users/:userId", handler.UpdateUser)

			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			req := httptest.NewRequest("PATCH", "/users/"+tt.userID, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockService.AssertExpectations(t)
			}
		})
	}
}

// TestHandler_DeleteUser tests the DeleteUser handler
func TestHandler_DeleteUser(t *testing.T) {
	validUUID := uuid.New()

	tests := []struct {
		name           string
		userID         string
		setupMock      func(*MockService)
		expectedStatus int
		expectedError  bool
	}{
		{
			name:   "Success - Delete user",
			userID: validUUID.String(),
			setupMock: func(m *MockService) {
				m.On("DeleteUser", mock.Anything, validUUID.String()).Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			expectedError:  false,
		},
		{
			name:   "Error - Invalid UUID",
			userID: "invalid-uuid",
			setupMock: func(m *MockService) {
				// No mock setup needed
			},
			expectedStatus: fiber.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			setupMock: func(m *MockService) {
				m.On("DeleteUser", mock.Anything, validUUID.String()).Return(ErrUserNotFound)
			},
			expectedStatus: fiber.StatusNotFound,
			expectedError:  true,
		},
		{
			name:   "Error - Service returns error",
			userID: validUUID.String(),
			setupMock: func(m *MockService) {
				m.On("DeleteUser", mock.Anything, validUUID.String()).Return(errors.New("database error"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockService := setupTestHandler()
			app := setupFiberApp()

			tt.setupMock(mockService)

			app.Delete("/users/:userId", handler.DeleteUser)

			req := httptest.NewRequest("DELETE", "/users/"+tt.userID, nil)
			resp, err := app.Test(req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if !tt.expectedError {
				mockService.AssertExpectations(t)
			}
		})
	}
}
