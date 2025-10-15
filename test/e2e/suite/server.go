package e2esuite

import (
	"fmt"
	"time"

	"go-rest-api/internal/config"
	"go-rest-api/internal/server"

	"gorm.io/gorm"
)

func startServer(cfg *config.Config, db *gorm.DB) (*server.Server, string, error) {
	srv := server.New(cfg, db)
	srv.SetupRoutes()
	go func() {
		_ = srv.Start()
	}()
	baseURL := fmt.Sprintf("http://localhost:%d", cfg.App.Port)
	time.Sleep(3 * time.Second)
	return srv, baseURL, nil
}
