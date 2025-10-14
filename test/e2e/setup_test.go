package e2e

import (
	"bytes"
	"context"
	"encoding/json"
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
	testServer *server.Server
	testDB     *gorm.DB
	baseURL    string
)

// TestMain sets up the test environment with a PostgreSQL container
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start PostgreSQL container
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
	if err := testDB.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		panic(fmt.Sprintf("Failed to enable uuid extension: %v", err))
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
	if err := os.Chdir("../../"); err != nil {
		panic(fmt.Sprintf("Failed to change directory: %v", err))
	}
	defer os.Chdir(originalDir)

	if err := database.RunMigrations(testDB); err != nil {
		panic(fmt.Sprintf("Failed to run migrations: %v", err))
	}

	// Create test server
	testServer = server.New(cfg, testDB)
	testServer.SetupRoutes()

	// Start server in background
	go func() {
		if err := testServer.Start(); err != nil {
			panic(fmt.Sprintf("Failed to start test server: %v", err))
		}
	}()

	// Wait for server to be ready
	baseURL = fmt.Sprintf("http://localhost:%d", cfg.App.Port)

	// Simple check - just wait a bit for server to start
	time.Sleep(3 * time.Second)

	// Run tests
	code := m.Run()

	// Cleanup
	if err := postgresContainer.Terminate(ctx); err != nil {
		fmt.Printf("Failed to terminate container: %v\n", err)
	}

	os.Exit(code)
}

// waitForServer waits for the server to be ready
func waitForServer(url string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 30; i++ {
		// Try different endpoints to see what's available
		endpoints := []string{"/api/v1/health/", "/api/v1/health", "/health/", "/health"}
		for _, endpoint := range endpoints {
			resp, err := client.Get(url + endpoint)
			if err != nil {
				fmt.Printf("Attempt %d: Error connecting to %s: %v\n", i+1, endpoint, err)
				continue
			}
			fmt.Printf("Attempt %d: Got response from %s with status %d\n", i+1, endpoint, resp.StatusCode)
			if resp.StatusCode == 200 || resp.StatusCode == 503 {
				resp.Body.Close()
				return nil
			}
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("server not ready after 30 seconds")
}

// makeRequest is a helper to make HTTP requests
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

// createTestUser creates a test user in the database
func createTestUser(name, email, password, role string) error {
	// Hash the password before storing
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
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

// getAuthToken performs login and returns the access token
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

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Access nested token structure: tokens.access.token
	tokens, ok := result["tokens"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("tokens not found in response")
	}

	access, ok := tokens["access"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("access token not found in response")
	}

	accessToken, ok := access["token"].(string)
	if !ok {
		return "", fmt.Errorf("access token value not found in response")
	}

	return accessToken, nil
}

// cleanupTestData cleans up test data after each test
func cleanupTestData() {
	// Clean up test data - delete in order to respect foreign key constraints
	testDB.Exec("DELETE FROM tokens")
	testDB.Exec("DELETE FROM users WHERE email LIKE '%@example.com'")
}
