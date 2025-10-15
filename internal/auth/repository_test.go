package auth_test

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"go-rest-api/internal/auth"
	"go-rest-api/internal/user"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupMockDB creates a mock database connection for testing.
func setupMockDB(t *testing.T) (*gorm.DB, sqlmock.Sqlmock, func()) {
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	dialector := postgres.New(postgres.Config{
		Conn:       sqlDB,
		DriverName: "postgres",
	})

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open gorm db: %v", err)
	}

	cleanup := func() {
		sqlDB.Close()
	}

	return db, mock, cleanup
}

// TestNewRepository tests the repository constructor.
func TestNewRepository(t *testing.T) {
	db, _, cleanup := setupMockDB(t)
	defer cleanup()

	repo := auth.NewRepository(db)

	assert.NotNil(t, repo)
}

// TestCreateUser tests the CreateUser repository method.
func TestCreateUser(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		user          *user.User
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name: "Success - Create user",
			user: &user.User{
				Name:     "New User",
				Email:    "newuser@example.com",
				Password: "hashedpass",
				Role:     "user",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name: "Error - Email already taken (duplicate key)",
			user: &user.User{
				Name:     "Duplicate User",
				Email:    "duplicate@example.com",
				Password: "hashedpass",
				Role:     "user",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
					WillReturnError(gorm.ErrDuplicatedKey)
				mock.ExpectRollback()
			},
			expectedError: auth.ErrEmailTaken,
		},
		{
			name: "Error - Database error",
			user: &user.User{
				Name:     "Error User",
				Email:    "error@example.com",
				Password: "hashedpass",
				Role:     "user",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
					WillReturnError(errors.New("database error"))
				mock.ExpectRollback()
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := auth.NewRepository(db)
			err := repo.CreateUser(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.name == "Error - Email already taken (duplicate key)" {
					assert.Equal(t, auth.ErrEmailTaken, err)
				}
			} else {
				require.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestCreateToken tests the CreateToken repository method.
func TestCreateToken(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		token         *auth.TokenDB
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name: "Success - Create token",
			token: &auth.TokenDB{
				Token:   "test-token",
				UserID:  validUUID,
				Type:    auth.TokenTypeRefresh,
				Expires: time.Now().Add(time.Hour),
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "tokens"`)).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name: "Error - Database error",
			token: &auth.TokenDB{
				Token:   "error-token",
				UserID:  validUUID,
				Type:    auth.TokenTypeRefresh,
				Expires: time.Now().Add(time.Hour),
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "tokens"`)).
					WillReturnError(errors.New("database error"))
				mock.ExpectRollback()
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := auth.NewRepository(db)
			err := repo.CreateToken(ctx, tt.token)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestDeleteToken tests the DeleteToken repository method.
func TestDeleteToken(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		tokenType     string
		userID        string
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:      "Success - Delete token",
			tokenType: auth.TokenTypeRefresh,
			userID:    validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeRefresh, validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:      "Success - No tokens to delete",
			tokenType: auth.TokenTypeRefresh,
			userID:    validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeRefresh, validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:      "Error - Database error",
			tokenType: auth.TokenTypeRefresh,
			userID:    validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeRefresh, validUUID.String()).
					WillReturnError(errors.New("database error"))
				mock.ExpectRollback()
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := auth.NewRepository(db)
			err := repo.DeleteToken(ctx, tt.tokenType, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestDeleteAllTokens tests the DeleteAllTokens repository method.
func TestDeleteAllTokens(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:   "Success - Delete all tokens",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE user_id = $1`)).
					WithArgs(validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 2))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:   "Success - No tokens to delete",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE user_id = $1`)).
					WithArgs(validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:   "Error - Database error",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE user_id = $1`)).
					WithArgs(validUUID.String()).
					WillReturnError(errors.New("database error"))
				mock.ExpectRollback()
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := auth.NewRepository(db)
			err := repo.DeleteAllTokens(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestFindTokenByTokenAndUserID tests the FindTokenByTokenAndUserID repository method.
func TestFindTokenByTokenAndUserID(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		tokenStr      string
		userID        string
		setupMock     func(sqlmock.Sqlmock)
		expectedToken *auth.TokenDB
		expectedError error
	}{
		{
			name:     "Success - Find token",
			tokenStr: "valid-token",
			userID:   validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "token", "user_id", "type", "expires", "created_at", "updated_at"}).
					AddRow(validUUID, "valid-token", validUUID, auth.TokenTypeRefresh, time.Now().Add(time.Hour), 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("valid-token", validUUID.String(), 1).
					WillReturnRows(rows)
			},
			expectedToken: &auth.TokenDB{
				ID:     validUUID,
				Token:  "valid-token",
				UserID: validUUID,
				Type:   auth.TokenTypeRefresh,
			},
			expectedError: nil,
		},
		{
			name:     "Error - Token not found",
			tokenStr: "invalid-token",
			userID:   validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("invalid-token", validUUID.String(), 1).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			expectedToken: nil,
			expectedError: auth.ErrTokenNotFound,
		},
		{
			name:     "Error - Database error",
			tokenStr: "error-token",
			userID:   validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("error-token", validUUID.String(), 1).
					WillReturnError(errors.New("database error"))
			},
			expectedToken: nil,
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := auth.NewRepository(db)
			token, err := repo.FindTokenByTokenAndUserID(ctx, tt.tokenStr, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, token)
				if tt.name == "Error - Token not found" {
					assert.Equal(t, auth.ErrTokenNotFound, err)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, tt.expectedToken.Token, token.Token)
				assert.Equal(t, tt.expectedToken.UserID, token.UserID)
				assert.Equal(t, tt.expectedToken.Type, token.Type)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
