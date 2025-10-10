package user

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupMockDB creates a mock database connection for testing
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

// TestNewRepository tests the repository constructor
func TestNewRepository(t *testing.T) {
	db, _, cleanup := setupMockDB(t)
	defer cleanup()

	repo := NewRepository(db)

	assert.NotNil(t, repo)
}

// TestFindAll tests the FindAll repository method
func TestFindAll(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		limit         int
		offset        int
		search        string
		setupMock     func(sqlmock.Sqlmock)
		expectedCount int
		expectedError bool
	}{
		{
			name:   "Success - Find all users without search",
			limit:  10,
			offset: 0,
			search: "",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "role", "verified_email", "created_at", "updated_at"}).
					AddRow(uuid.New(), "User 1", "user1@example.com", "hashedpass", "user", false, 1234567890, 1234567890).
					AddRow(uuid.New(), "User 2", "user2@example.com", "hashedpass", "admin", true, 1234567891, 1234567891)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" ORDER BY created_at asc LIMIT $1`)).
					WithArgs(10).
					WillReturnRows(rows)
			},
			expectedCount: 2,
			expectedError: false,
		},
		{
			name:   "Success - Find users with search filter",
			limit:  10,
			offset: 0,
			search: "admin",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "role", "verified_email", "created_at", "updated_at"}).
					AddRow(uuid.New(), "Admin User", "admin@example.com", "hashedpass", "admin", true, 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE name ILIKE $1 OR email ILIKE $2 OR role ILIKE $3 ORDER BY created_at asc LIMIT $4`)).
					WithArgs("%admin%", "%admin%", "%admin%", 10).
					WillReturnRows(rows)
			},
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:   "Success - Find users with offset",
			limit:  5,
			offset: 5,
			search: "",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "role", "verified_email", "created_at", "updated_at"}).
					AddRow(uuid.New(), "User 6", "user6@example.com", "hashedpass", "user", false, 1234567895, 1234567895)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" ORDER BY created_at asc LIMIT $1 OFFSET $2`)).
					WithArgs(5, 5).
					WillReturnRows(rows)
			},
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:   "Success - No users found",
			limit:  10,
			offset: 0,
			search: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "role", "verified_email", "created_at", "updated_at"})

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE name ILIKE $1 OR email ILIKE $2 OR role ILIKE $3 ORDER BY created_at asc LIMIT $4`)).
					WithArgs("%nonexistent%", "%nonexistent%", "%nonexistent%", 10).
					WillReturnRows(rows)
			},
			expectedCount: 0,
			expectedError: false,
		},
		{
			name:   "Error - Database error",
			limit:  10,
			offset: 0,
			search: "",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" ORDER BY created_at asc LIMIT $1`)).
					WithArgs(10).
					WillReturnError(errors.New("database connection error"))
			},
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := NewRepository(db)
			users, err := repo.FindAll(ctx, tt.limit, tt.offset, tt.search)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, users)
			} else {
				assert.NoError(t, err)
				assert.Len(t, users, tt.expectedCount)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestCount tests the Count repository method
func TestCount(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		search        string
		setupMock     func(sqlmock.Sqlmock)
		expectedCount int64
		expectedError bool
	}{
		{
			name:   "Success - Count all users",
			search: "",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(10)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users"`)).
					WillReturnRows(rows)
			},
			expectedCount: 10,
			expectedError: false,
		},
		{
			name:   "Success - Count with search filter",
			search: "admin",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(2)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users" WHERE name ILIKE $1 OR email ILIKE $2 OR role ILIKE $3`)).
					WithArgs("%admin%", "%admin%", "%admin%").
					WillReturnRows(rows)
			},
			expectedCount: 2,
			expectedError: false,
		},
		{
			name:   "Success - Count returns zero",
			search: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(0)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users" WHERE name ILIKE $1 OR email ILIKE $2 OR role ILIKE $3`)).
					WithArgs("%nonexistent%", "%nonexistent%", "%nonexistent%").
					WillReturnRows(rows)
			},
			expectedCount: 0,
			expectedError: false,
		},
		{
			name:   "Error - Database error",
			search: "",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users"`)).
					WillReturnError(errors.New("database error"))
			},
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := NewRepository(db)
			count, err := repo.Count(ctx, tt.search)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Equal(t, int64(0), count)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCount, count)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestFindByID tests the FindByID repository method
func TestFindByID(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		userID        string
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:   "Success - Find user by ID",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "role", "verified_email", "created_at", "updated_at"}).
					AddRow(validUUID, "Test User", "test@example.com", "hashedpass", "user", false, 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE id = $1 ORDER BY "users"."id" LIMIT $2`)).
					WithArgs(validUUID.String(), 1).
					WillReturnRows(rows)
			},
			expectedError: nil,
		},
		{
			name:   "Error - User not found",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE id = $1 ORDER BY "users"."id" LIMIT $2`)).
					WithArgs(validUUID.String(), 1).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			expectedError: ErrUserNotFound,
		},
		{
			name:   "Error - Database error",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE id = $1 ORDER BY "users"."id" LIMIT $2`)).
					WithArgs(validUUID.String(), 1).
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

			repo := NewRepository(db)
			user, err := repo.FindByID(ctx, tt.userID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, validUUID, user.ID)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestFindByEmail tests the FindByEmail repository method
func TestFindByEmail(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		email         string
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:  "Success - Find user by email",
			email: "test@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "role", "verified_email", "created_at", "updated_at"}).
					AddRow(validUUID, "Test User", "test@example.com", "hashedpass", "user", false, 1234567890, 1234567890)

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."id" LIMIT $2`)).
					WithArgs("test@example.com", 1).
					WillReturnRows(rows)
			},
			expectedError: nil,
		},
		{
			name:  "Error - User not found",
			email: "notfound@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."id" LIMIT $2`)).
					WithArgs("notfound@example.com", 1).
					WillReturnError(gorm.ErrRecordNotFound)
			},
			expectedError: ErrUserNotFound,
		},
		{
			name:  "Error - Database error",
			email: "error@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."id" LIMIT $2`)).
					WithArgs("error@example.com", 1).
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

			repo := NewRepository(db)
			user, err := repo.FindByEmail(ctx, tt.email)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.email, user.Email)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestCreate tests the Create repository method
func TestCreate(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		user          *User
		setupMock     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name: "Success - Create user",
			user: &User{
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
			user: &User{
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
			expectedError: ErrEmailTaken,
		},
		{
			name: "Error - Database error",
			user: &User{
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

			repo := NewRepository(db)
			err := repo.Create(ctx, tt.user)

			if tt.expectedError != nil {
				assert.Error(t, err)
				if tt.name == "Error - Email already taken (duplicate key)" {
					assert.Equal(t, ErrEmailTaken, err)
				}
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestUpdate tests the Update repository method
func TestUpdate(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name              string
		userID            string
		user              *User
		setupMock         func(sqlmock.Sqlmock)
		expectedRowsAffec int64
		expectedError     error
	}{
		{
			name:   "Success - Update user",
			userID: validUUID.String(),
			user: &User{
				Name:  "Updated Name",
				Email: "updated@example.com",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedRowsAffec: 1,
			expectedError:     nil,
		},
		{
			name:   "Success - No rows affected (user not found)",
			userID: validUUID.String(),
			user: &User{
				Name: "Updated Name",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectCommit()
			},
			expectedRowsAffec: 0,
			expectedError:     nil,
		},
		{
			name:   "Error - Email already taken",
			userID: validUUID.String(),
			user: &User{
				Email: "taken@example.com",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), validUUID.String()).
					WillReturnError(gorm.ErrDuplicatedKey)
				mock.ExpectRollback()
			},
			expectedRowsAffec: 0,
			expectedError:     ErrEmailTaken,
		},
		{
			name:   "Error - Database error",
			userID: validUUID.String(),
			user: &User{
				Name: "Error Name",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), validUUID.String()).
					WillReturnError(errors.New("database error"))
				mock.ExpectRollback()
			},
			expectedRowsAffec: 0,
			expectedError:     errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := NewRepository(db)
			rowsAffected, err := repo.Update(ctx, tt.userID, tt.user)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, int64(0), rowsAffected)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRowsAffec, rowsAffected)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestUpdateFields tests the UpdateFields repository method
func TestUpdateFields(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name              string
		userID            string
		updates           map[string]interface{}
		setupMock         func(sqlmock.Sqlmock)
		expectedRowsAffec int64
		expectedError     bool
	}{
		{
			name:   "Success - Update single field",
			userID: validUUID.String(),
			updates: map[string]interface{}{
				"verified_email": true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
					WithArgs(true, sqlmock.AnyArg(), validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedRowsAffec: 1,
			expectedError:     false,
		},
		{
			name:   "Success - Update multiple fields",
			userID: validUUID.String(),
			updates: map[string]interface{}{
				"name":  "Updated Name",
				"email": "updated@example.com",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedRowsAffec: 1,
			expectedError:     false,
		},
		{
			name:   "Error - Database error",
			userID: validUUID.String(),
			updates: map[string]interface{}{
				"name": "Error Name",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
					WillReturnError(errors.New("database error"))
				mock.ExpectRollback()
			},
			expectedRowsAffec: 0,
			expectedError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := NewRepository(db)
			rowsAffected, err := repo.UpdateFields(ctx, tt.userID, tt.updates)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Equal(t, int64(0), rowsAffected)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRowsAffec, rowsAffected)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestDelete tests the Delete repository method
func TestDelete(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name              string
		userID            string
		setupMock         func(sqlmock.Sqlmock)
		expectedRowsAffec int64
		expectedError     bool
	}{
		{
			name:   "Success - Delete user",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "users" WHERE id = $1`)).
					WithArgs(validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedRowsAffec: 1,
			expectedError:     false,
		},
		{
			name:   "Success - No rows affected (user not found)",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "users" WHERE id = $1`)).
					WithArgs(validUUID.String()).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectCommit()
			},
			expectedRowsAffec: 0,
			expectedError:     false,
		},
		{
			name:   "Error - Database error",
			userID: validUUID.String(),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "users" WHERE id = $1`)).
					WithArgs(validUUID.String()).
					WillReturnError(errors.New("database error"))
				mock.ExpectRollback()
			},
			expectedRowsAffec: 0,
			expectedError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := NewRepository(db)
			rowsAffected, err := repo.Delete(ctx, tt.userID)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Equal(t, int64(0), rowsAffected)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRowsAffec, rowsAffected)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestSave tests the Save repository method
func TestSave(t *testing.T) {
	ctx := context.Background()
	validUUID := uuid.New()

	tests := []struct {
		name          string
		user          *User
		setupMock     func(sqlmock.Sqlmock)
		expectedError bool
	}{
		{
			name: "Success - Save new user",
			user: &User{
				Name:     "New User",
				Email:    "new@example.com",
				Password: "hashedpass",
				Role:     "user",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
				mock.ExpectCommit()
			},
			expectedError: false,
		},
		{
			name: "Success - Save existing user",
			user: &User{
				ID:       validUUID,
				Name:     "Updated User",
				Email:    "updated@example.com",
				Password: "hashedpass",
				Role:     "user",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users"`)).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			expectedError: false,
		},
		{
			name: "Error - Database error",
			user: &User{
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
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, cleanup := setupMockDB(t)
			defer cleanup()

			tt.setupMock(mock)

			repo := NewRepository(db)
			err := repo.Save(ctx, tt.user)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
