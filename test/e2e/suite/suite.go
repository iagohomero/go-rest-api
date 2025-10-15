package e2esuite

import (
	"context"
)

// Suite holds initialized resources for the E2E test run.
type Suite struct {
	BaseURL            string
	MailpitHTTPBaseURL string
}

// StartSuite boots containers, DB, runs migrations, and starts the HTTP server.
func StartSuite(ctx context.Context) (*Suite, error) {
	pg, host, port, connStr, err := startPostgres(ctx)
	if err != nil {
		return nil, err
	}

	db, err := openGorm(connStr)
	if err != nil {
		_ = pg.Terminate(ctx)
		return nil, err
	}

	originalDir, err := chdirProjectRoot()
	if err != nil {
		_ = pg.Terminate(ctx)
		return nil, err
	}
	if migrateErr := runMigrations(db); migrateErr != nil {
		_ = pg.Terminate(ctx)
		_ = chdirBack(originalDir)
		return nil, migrateErr
	}

	mp, mailHTTP, smtpHost, smtpPort, err := startMailpit(ctx)
	if err != nil {
		_ = pg.Terminate(ctx)
		_ = chdirBack(originalDir)
		return nil, err
	}

	cfg := buildTestConfig(host, port, smtpHost, smtpPort, mailHTTP)

	srv, baseURL := startServer(cfg, db)

	// register globals for wrappers
	setGlobals(pg, mp, db, srv, baseURL, mailHTTP, originalDir)

	return &Suite{BaseURL: baseURL, MailpitHTTPBaseURL: mailHTTP}, nil
}

// StopSuite tears down containers and restores CWD.
func StopSuite(ctx context.Context) {
	terminateAll(ctx)
}
