package e2esuite

import (
	"context"
	"fmt"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type postgresInfo struct {
	Container testcontainers.Container
	Host      string
	Port      int
	ConnStr   string
}

func startPostgres(ctx context.Context) (testcontainers.Container, string, int, string, error) {
	//nolint:staticcheck // allow deprecated RunContainer used in tests
	pg, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(1).WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, "", 0, "", fmt.Errorf("start postgres: %w", err)
	}

	host, err := pg.Host(ctx)
	if err != nil {
		_ = pg.Terminate(ctx)
		return nil, "", 0, "", fmt.Errorf("postgres host: %w", err)
	}
	port, err := pg.MappedPort(ctx, "5432")
	if err != nil {
		_ = pg.Terminate(ctx)
		return nil, "", 0, "", fmt.Errorf("postgres port: %w", err)
	}
	connStr, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pg.Terminate(ctx)
		return nil, "", 0, "", fmt.Errorf("postgres conn string: %w", err)
	}

	time.Sleep(2 * time.Second)
	return pg, host, port.Int(), connStr, nil
}

func startMailpit(ctx context.Context) (testcontainers.Container, string, string, int, error) {
	req := testcontainers.ContainerRequest{
		Image:        "axllent/mailpit:latest",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("1025/tcp").WithStartupTimeout(30*time.Second),
			wait.ForListeningPort("8025/tcp").WithStartupTimeout(30*time.Second),
		),
	}
	mp, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("start mailpit: %w", err)
	}
	host, err := mp.Host(ctx)
	if err != nil {
		_ = mp.Terminate(ctx)
		return nil, "", "", 0, fmt.Errorf("mailpit host: %w", err)
	}
	smtpPort, err := mp.MappedPort(ctx, "1025")
	if err != nil {
		_ = mp.Terminate(ctx)
		return nil, "", "", 0, fmt.Errorf("mailpit smtp port: %w", err)
	}
	httpPort, err := mp.MappedPort(ctx, "8025")
	if err != nil {
		_ = mp.Terminate(ctx)
		return nil, "", "", 0, fmt.Errorf("mailpit http port: %w", err)
	}

	// Build http base URL
	httpHost := host
	// bracket IPv6 if present
	// simple check handled in caller, keep host as-is here
	httpBase := fmt.Sprintf("http://%s:%d", httpHost, httpPort.Int())
	return mp, httpBase, host, smtpPort.Int(), nil
}
