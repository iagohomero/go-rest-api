package e2esuite

import (
	"context"
	"time"

	"go-rest-api/internal/server"

	"github.com/testcontainers/testcontainers-go"
	"gorm.io/gorm"
)

var (
	pgContainer          testcontainers.Container
	mailpitContainer     testcontainers.Container
	gormDB               *gorm.DB
	httpServer           *server.Server
	suiteBaseURL         string
	suiteMailpitHTTPBase string
	originalWD           string
)

func setGlobals(pg testcontainers.Container, mp testcontainers.Container, db *gorm.DB, srv *server.Server, baseURL string, mailHTTP string, cwd string) {
	pgContainer = pg
	mailpitContainer = mp
	gormDB = db
	httpServer = srv
	suiteBaseURL = baseURL
	suiteMailpitHTTPBase = mailHTTP
	originalWD = cwd
}

func terminateAll(ctx context.Context) {
	// Try graceful shutdown server first
	if httpServer != nil {
		_ = httpServer.Shutdown(ctx)
	}
	// Terminate containers
	if pgContainer != nil {
		_ = pgContainer.Terminate(ctx)
	}
	if mailpitContainer != nil {
		_ = mailpitContainer.Terminate(ctx)
	}
	// small delay to free ports
	time.Sleep(300 * time.Millisecond)
	// restore working directory if changed
	if originalWD != "" {
		_ = chdirBack(originalWD)
	}
}
