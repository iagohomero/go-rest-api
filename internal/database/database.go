package database

import (
	"fmt"
	"time"

	"go-rest-api/internal/common/logger"
	"go-rest-api/internal/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Connect establishes a PostgreSQL database connection with optimized settings.
func Connect(cfg *config.Config) (*gorm.DB, error) {
	dsn := cfg.Database.DSN()

	logLevel := gormlogger.Info
	if cfg.App.IsProd() {
		logLevel = gormlogger.Error
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:                 gormlogger.Default.LogMode(logLevel),
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		TranslateError:         true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(60 * time.Minute)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	logger.Log.Info("Database connection established successfully")

	return db, nil
}

// Close closes the database connection gracefully.
func Close(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("failed to close database connection: %w", err)
	}

	logger.Log.Info("Database connection closed successfully")
	return nil
}
