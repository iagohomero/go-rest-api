//nolint:testpackage // E2E tests need access to internal packages
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"go-rest-api/internal/common/crypto"
	"go-rest-api/internal/config"
	"go-rest-api/internal/database"
	"go-rest-api/internal/server"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	//nolint:gochecknoglobals // Test globals are acceptable for test setup
	testServer *server.Server
	//nolint:gochecknoglobals // Test globals are acceptable for test setup
	testDB *gorm.DB
	//nolint:gochecknoglobals // Test globals are acceptable for test setup
	baseURL string
)

// TestMain sets up the test environment with a PostgreSQL container.
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start PostgreSQL container
	//nolint:staticcheck // SA1019: postgres.RunContainer is deprecated but still functional
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(1).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to start postgres container: %v", err))
	}

	// Get connection details
	host, err := postgresContainer.Host(ctx)
	if err != nil {
		panic(fmt.Sprintf("Failed to get container host: %v", err))
	}

	port, err := postgresContainer.MappedPort(ctx, "5432")
	if err != nil {
		panic(fmt.Sprintf("Failed to get container port: %v", err))
	}

	// Get the connection string from the container
	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic(fmt.Sprintf("Failed to get connection string: %v", err))
	}

	// Wait a bit for the container to be fully ready
	time.Sleep(2 * time.Second)

	// Connect to database using the connection string directly
	testDB, err = gorm.Open(gormpostgres.Open(connStr), &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		TranslateError:         true,
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to test database: %v", err))
	}

	// Enable uuid extension
	if uuidErr := testDB.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; uuidErr != nil {
		panic(fmt.Sprintf("Failed to enable uuid extension: %v", uuidErr))
	}

	// Create test configuration
	cfg := &config.Config{
		App: config.AppConfig{
			Environment: "test",
			Host:        "localhost",
			Port:        8085,
			Name:        "go-rest-api-test",
		},
		Database: config.DatabaseConfig{
			Host:     host,
			User:     "testuser",
			Password: "testpass",
			Name:     "testdb",
			Port:     port.Int(),
		},
		JWT: config.JWTConfig{
			Secret:              "test-secret-key-for-jwt-tokens",
			AccessExpMinutes:    15,
			RefreshExpDays:      7,
			ResetPasswordExpMin: 15,
			VerifyEmailExpMin:   15,
		},
		SMTP: config.SMTPConfig{
			Host:     "localhost",
			Port:     587,
			Username: "test",
			Password: "test",
			From:     "test@example.com",
		},
		OAuth: config.OAuthConfig{
			GoogleClientID:     "test-client-id",
			GoogleClientSecret: "test-client-secret",
			RedirectURL:        "http://localhost:8085/api/v1/auth/google-callback",
		},
	}

	// Run migrations - we need to set the working directory to the project root
	originalDir, _ := os.Getwd()
	if chdirErr := os.Chdir("../../"); chdirErr != nil {
		panic(fmt.Sprintf("Failed to change directory: %v", chdirErr))
	}

	if migrationErr := database.RunMigrations(testDB); migrationErr != nil {
		panic(fmt.Sprintf("Failed to run migrations: %v", migrationErr))
	}

	// Create test server
	testServer = server.New(cfg, testDB)
	testServer.SetupRoutes()

	// Start server in background
	go func() {
		if startErr := testServer.Start(); startErr != nil {
			panic(fmt.Sprintf("Failed to start test server: %v", startErr))
		}
	}()

	// Wait for server to be ready
	baseURL = fmt.Sprintf("http://localhost:%d", cfg.App.Port)

	// Simple check - just wait a bit for server to start
	time.Sleep(3 * time.Second)

	// Run tests
	code := m.Run()

	// Cleanup before exit
	if terminateErr := postgresContainer.Terminate(ctx); terminateErr != nil {
		// Log error but don't fail the test
		_ = terminateErr
	}

	// Change back to original directory before exit
	os.Chdir(originalDir)

	// Exit after cleanup
	os.Exit(code)
}

// makeRequest is a helper to make HTTP requests.
func makeRequest(method, url string, body interface{}, headers map[string]string) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

// createTestUser creates a test user in the database.
//
//nolint:unparam // password parameter is kept for API consistency
func createTestUser(name, email, password, role string) error {
	// Hash the password before storing
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user := map[string]interface{}{
		"name":           name,
		"email":          email,
		"password":       hashedPassword,
		"role":           role,
		"verified_email": true,
		"created_at":     time.Now().Unix(),
		"updated_at":     time.Now().Unix(),
	}

	return testDB.Table("users").Create(user).Error
}

// getAuthToken performs login and returns the access token.
//
//nolint:unparam // password parameter is kept for API consistency
func getAuthToken(email, password string) (string, error) {
	loginData := map[string]string{
		"email":    email,
		"password": password,
	}

	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&result); decodeErr != nil {
		return "", decodeErr
	}

	// Access nested token structure: tokens.access.token
	tokens, ok := result["tokens"].(map[string]interface{})
	if !ok {
		return "", errors.New("tokens not found in response")
	}

	access, ok := tokens["access"].(map[string]interface{})
	if !ok {
		return "", errors.New("access token not found in response")
	}

	accessToken, ok := access["token"].(string)
	if !ok {
		return "", errors.New("access token value not found in response")
	}

	return accessToken, nil
}

// cleanupTestData cleans up test data after each test.
func cleanupTestData() {
	// Clean up test data - delete in order to respect foreign key constraints
	testDB.Exec("DELETE FROM tokens")
	testDB.Exec("DELETE FROM users WHERE email LIKE '%@example.com'")
}
