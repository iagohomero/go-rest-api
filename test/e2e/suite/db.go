package e2esuite

import (
	"fmt"
	"os"
	"time"

	"go-rest-api/internal/common/crypto"
	"go-rest-api/internal/database"

	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func openGorm(connStr string) (*gorm.DB, error) {
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		TranslateError:         true,
	})
	if err != nil {
		return nil, fmt.Errorf("open gorm: %w", err)
	}
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return nil, fmt.Errorf("enable uuid extension: %w", err)
	}
	return db, nil
}

func runMigrations(db *gorm.DB) error {
	return database.RunMigrations(db)
}

func chdirProjectRoot() (string, error) {
	originalDir, _ := os.Getwd()
	if err := os.Chdir("../../"); err != nil {
		return "", fmt.Errorf("chdir project root: %w", err)
	}
	return originalDir, nil
}

func chdirBack(dir string) error {
	return os.Chdir(dir)
}

// CreateTestUser inserts a user with hashed password and verified_email=true.
func CreateTestUser(name, email, password, role string) error {
	if gormDB == nil {
		return fmt.Errorf("db not initialized")
	}
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	user := map[string]interface{}{
		"name":           name,
		"email":          email,
		"password":       hashedPassword,
		"role":           role,
		"verified_email": true,
		"created_at":     time.Now().Unix(),
		"updated_at":     time.Now().Unix(),
	}
	return gormDB.Table("users").Create(user).Error
}

// CleanupTestData removes test tokens and users created by e2e tests.
func CleanupTestData() {
	if gormDB == nil {
		return
	}
	gormDB.Exec("DELETE FROM tokens")
	gormDB.Exec("DELETE FROM users WHERE email LIKE '%@example.com'")
}
