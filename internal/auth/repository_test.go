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

// TestRepository_CreateUser tests the CreateUser repository method.
func TestRepository_CreateUser(t *testing.T) {
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

// TestRepository_CreateToken tests the CreateToken repository method.
func TestRepository_CreateToken(t *testing.T) {
	ctx := context.Background()

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
				UserID:  uuid.New(),
				Type:    auth.TokenTypeAccess,
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
			name: "Success - Create refresh token",
			token: &auth.TokenDB{
				Token:   "refresh-token",
				UserID:  uuid.New(),
				Type:    auth.TokenTypeRefresh,
				Expires: time.Now().Add(time.Hour * 24),
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
				UserID:  uuid.New(),
				Type:    auth.TokenTypeAccess,
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

// TestRepository_DeleteToken tests the DeleteToken repository method.
func TestRepository_DeleteToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		tokenType     string
		userID        string
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:      "Success - Delete access token",
			tokenType: auth.TokenTypeAccess,
			userID:    uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeAccess, sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:      "Success - Delete refresh token",
			tokenType: auth.TokenTypeRefresh,
			userID:    uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeRefresh, sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:      "Success - Delete reset password token",
			tokenType: auth.TokenTypeResetPassword,
			userID:    uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeResetPassword, sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:      "Success - Delete verify email token",
			tokenType: auth.TokenTypeVerifyEmail,
			userID:    uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeVerifyEmail, sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:      "Error - Database error",
			tokenType: auth.TokenTypeAccess,
			userID:    uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE type = $1 AND user_id = $2`)).
					WithArgs(auth.TokenTypeAccess, sqlmock.AnyArg()).
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

// TestRepository_DeleteAllTokens tests the DeleteAllTokens repository method.
func TestRepository_DeleteAllTokens(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		userID        string
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:   "Success - Delete all tokens for user",
			userID: uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE user_id = $1`)).
					WithArgs(sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 3)) // 3 tokens deleted
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:   "Success - No tokens to delete",
			userID: uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE user_id = $1`)).
					WithArgs(sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 0)) // 0 tokens deleted
				mock.ExpectCommit()
			},
			expectedError: nil,
		},
		{
			name:   "Error - Database error",
			userID: uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "tokens" WHERE user_id = $1`)).
					WithArgs(sqlmock.AnyArg()).
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

// TestRepository_FindTokenByTokenAndUserID tests the FindTokenByTokenAndUserID repository method.
func TestRepository_FindTokenByTokenAndUserID(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		tokenStr      string
		userID        string
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:     "Success - Find access token",
			tokenStr: "access-token",
			userID:   uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "token", "user_id", "type", "expires", "created_at", "updated_at"}).
					AddRow(uuid.New(), "access-token", uuid.New(), auth.TokenTypeAccess, time.Now().Add(time.Hour), 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("access-token", sqlmock.AnyArg(), 1).
					WillReturnRows(rows)
			},
			expectedError: nil,
		},
		{
			name:     "Success - Find refresh token",
			tokenStr: "refresh-token",
			userID:   uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "token", "user_id", "type", "expires", "created_at", "updated_at"}).
					AddRow(uuid.New(), "refresh-token", uuid.New(), auth.TokenTypeRefresh, time.Now().Add(time.Hour*24), 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("refresh-token", sqlmock.AnyArg(), 1).
					WillReturnRows(rows)
			},
			expectedError: nil,
		},
		{
			name:     "Success - Find reset password token",
			tokenStr: "reset-token",
			userID:   uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "token", "user_id", "type", "expires", "created_at", "updated_at"}).
					AddRow(uuid.New(), "reset-token", uuid.New(), auth.TokenTypeResetPassword, time.Now().Add(time.Hour), 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("reset-token", sqlmock.AnyArg(), 1).
					WillReturnRows(rows)
			},
			expectedError: nil,
		},
		{
			name:     "Success - Find verify email token",
			tokenStr: "verify-token",
			userID:   uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "token", "user_id", "type", "expires", "created_at", "updated_at"}).
					AddRow(uuid.New(), "verify-token", uuid.New(), auth.TokenTypeVerifyEmail, time.Now().Add(time.Hour), 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("verify-token", sqlmock.AnyArg(), 1).
					WillReturnRows(rows)
			},
			expectedError: nil,
		},
		{
			name:     "Error - Token not found",
			tokenStr: "notfound-token",
			userID:   uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("notfound-token", sqlmock.AnyArg(), 1).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			expectedError: auth.ErrTokenNotFound,
		},
		{
			name:     "Error - Database error",
			tokenStr: "error-token",
			userID:   uuid.New().String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "tokens" WHERE token = $1 AND user_id = $2 ORDER BY "tokens"."id" LIMIT $3`)).
					WithArgs("error-token", sqlmock.AnyArg(), 1).
					WillReturnError(errors.New("database error"))
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
				assert.Equal(t, tt.tokenStr, token.Token)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
