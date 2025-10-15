package e2esuite

import (
	"fmt"
	"time"

	"go-rest-api/internal/config"
	"go-rest-api/internal/server"

	"gorm.io/gorm"
)

const (
	// ServerStartupDelay is the server startup delay.
	ServerStartupDelay = 3 * time.Second
)

func startServer(cfg *config.Config, db *gorm.DB) (*server.Server, string) {
	srv := server.New(cfg, db)
	srv.SetupRoutes()
	go func() {
		_ = srv.Start()
	}()
	baseURL := fmt.Sprintf("http://localhost:%d", cfg.App.Port)
	time.Sleep(ServerStartupDelay)
	return srv, baseURL
}
