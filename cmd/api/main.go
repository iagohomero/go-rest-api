package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "go-rest-api/api/swagger"
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
		logger.Log.Fatalf("Failed to load configuration: %v", err)
	}

	db, err := database.Connect(cfg)
	if err != nil {
		logger.Log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := database.Close(db); err != nil {
			logger.Log.Errorf("Error closing database: %v", err)
		}
	}()

	srv := server.New(cfg, db)
	srv.SetupRoutes()

	go func() {
		if err := srv.Start(); err != nil {
			logger.Log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Log.Info("Received shutdown signal")

	ctx, cancel := context.WithTimeout(context.Background(), 10)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Log.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Log.Info("Server exited successfully")
}
