package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-rest-api/internal/common/logger"
	"go-rest-api/internal/config"
	"go-rest-api/internal/database"
	"go-rest-api/internal/server"
)

// @title go-rest-api API documentation
// @version 1.0.0
// @host localhost:8080
// @BasePath /v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Example Value: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
func main() {
	cfg, err := config.Load()
	if err != nil {
		logger.New().Fatalf("Failed to load configuration: %v", err)
	}

	db, err := database.Connect(cfg)
	if err != nil {
		logger.New().Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if closeErr := database.Close(db); closeErr != nil {
			logger.New().Errorf("Error closing database: %v", closeErr)
		}
	}()

	srv := server.New(cfg, db)
	srv.SetupRoutes()

	go func() {
		if startErr := srv.Start(); startErr != nil {
			logger.New().Fatalf("Server error: %v", startErr)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.New().Info("Received shutdown signal")

	const shutdownTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if shutdownErr := srv.Shutdown(ctx); shutdownErr != nil {
		logger.New().Fatalf("Server forced to shutdown: %v", shutdownErr)
	}

	logger.New().Info("Server exited successfully")
}
