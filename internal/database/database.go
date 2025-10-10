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

const (
	// MaxIdleConns is the maximum number of idle connections in the pool.
	MaxIdleConns = 10
	// MaxOpenConns is the maximum number of open connections to the database.
	MaxOpenConns = 100
	// ConnMaxLifetime is the maximum amount of time a connection may be reused.
	ConnMaxLifetime = 60 * time.Minute
	// ConnMaxIdleTime is the maximum amount of time a connection may be idle.
	ConnMaxIdleTime = 10 * time.Minute
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

	sqlDB.SetMaxIdleConns(MaxIdleConns)
	sqlDB.SetMaxOpenConns(MaxOpenConns)
	sqlDB.SetConnMaxLifetime(ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(ConnMaxIdleTime)

	logger.New().Info("Database connection established successfully")

	return db, nil
}

// Close closes the database connection gracefully.
func Close(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	if closeErr := sqlDB.Close(); closeErr != nil {
		return fmt.Errorf("failed to close database connection: %w", closeErr)
	}

	logger.New().Info("Database connection closed successfully")
	return nil
}
