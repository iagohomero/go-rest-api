package database

import (
	"fmt"

	"go-rest-api/internal/common/logger"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gorm.io/gorm"
)

// RunMigrations executes all pending database migrations.
// It embeds the migrations directory and runs them against the database.
// If migrations fail, the function returns an error.
func RunMigrations(db *gorm.DB) error {
	logger.New().Info("Starting database migrations...")

	// Get the underlying sql.DB from GORM
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// Create postgres driver instance
	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Create migrate instance with file source and postgres driver
	m, err := migrate.NewWithDatabaseInstance("file://migrations", "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Run migrations
	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			logger.New().Info("No pending migrations to run")
			return nil
		}
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	logger.New().Info("Database migrations completed successfully")
	return nil
}
