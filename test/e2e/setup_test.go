//nolint:testpackage // E2E tests need access to internal packages
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
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
	//nolint:gochecknoglobals // container reference for cleanup
	mailpitContainer testcontainers.Container
	//nolint:gochecknoglobals // cached Mailpit HTTP base URL for API queries
	mailpitHTTPBaseURL string
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
		// SMTP will be overridden after Mailpit container is started
		SMTP: config.SMTPConfig{
			Host:     "",
			Port:     0,
			Username: "",
			Password: "",
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

	// Start Mailpit container for SMTP + HTTP API assertions
	// Image docs: https://hub.docker.com/r/axllent/mailpit
	mailpitReq := testcontainers.ContainerRequest{
		Image:        "axllent/mailpit:latest",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("1025/tcp").WithStartupTimeout(30*time.Second),
			wait.ForListeningPort("8025/tcp").WithStartupTimeout(30*time.Second),
		),
	}

	var errMailpit error
	mailpitContainer, errMailpit = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: mailpitReq,
		Started:          true,
	})
	if errMailpit != nil {
		panic(fmt.Sprintf("Failed to start mailpit container: %v", errMailpit))
	}

	mailpitHost, err := mailpitContainer.Host(ctx)
	if err != nil {
		panic(fmt.Sprintf("Failed to get mailpit host: %v", err))
	}
	smtpPort, err := mailpitContainer.MappedPort(ctx, "1025")
	if err != nil {
		panic(fmt.Sprintf("Failed to get mailpit SMTP port: %v", err))
	}
	httpPort, err := mailpitContainer.MappedPort(ctx, "8025")
	if err != nil {
		panic(fmt.Sprintf("Failed to get mailpit HTTP port: %v", err))
	}

	// Wire SMTP config to Mailpit
	cfg.SMTP.Host = mailpitHost
	cfg.SMTP.Port = smtpPort.Int()
	cfg.SMTP.Username = "" // Mailpit does not require auth
	cfg.SMTP.Password = ""

	// Build HTTP base URL for Mailpit API
	// Ensure IPv6 or hostname formats are bracketed if necessary
	hostForURL := mailpitHost
	if ip := net.ParseIP(mailpitHost); ip != nil && ip.To4() == nil {
		hostForURL = "[" + mailpitHost + "]"
	}
	mailpitHTTPBaseURL = fmt.Sprintf("http://%s:%d", hostForURL, httpPort.Int())

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

	if mailpitContainer != nil {
		_ = mailpitContainer.Terminate(ctx)
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

// fetchMailpitMessages retrieves messages from Mailpit HTTP API.
func fetchMailpitMessages() ([]map[string]interface{}, error) {
	if mailpitHTTPBaseURL == "" {
		return nil, fmt.Errorf("mailpit not initialized")
	}
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/messages", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		Messages []map[string]interface{} `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Messages, nil
}

// waitForMail blocks until at least one message exists for the given recipient.
func waitForMail(toContains string, subjectContains string, timeout time.Duration) (map[string]interface{}, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs, err := fetchMailpitMessages()
		if err == nil {
			for _, m := range msgs {
				// Mailpit API fields: "To" can be an array of objects or strings depending on version
				subject, _ := m["Subject"].(string)

				matchesTo := toContains == ""
				if !matchesTo {
					if toArr, ok := m["To"].([]interface{}); ok {
						for _, item := range toArr {
							switch v := item.(type) {
							case string:
								if containsFold(v, toContains) {
									matchesTo = true
								}
							case map[string]interface{}:
								if email, _ := v["Address"].(string); email != "" && containsFold(email, toContains) {
									matchesTo = true
								}
								if email, _ := v["Email"].(string); email != "" && containsFold(email, toContains) {
									matchesTo = true
								}
							}
							if matchesTo {
								break
							}
						}
					} else if toStr, ok := m["To"].(string); ok {
						matchesTo = containsFold(toStr, toContains)
					}
				}

				matchesSubject := subjectContains == "" || (subject != "" && containsFold(subject, subjectContains))

				if matchesTo && matchesSubject {
					return m, nil
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return nil, fmt.Errorf("mail not received for recipient=%s subject~=%s within %s", toContains, subjectContains, timeout)
}

// getMailTextBody fetches full message body (text) from Mailpit.
func getMailTextBody(id string) (string, error) { // kept for backwards-compat usage
	// Try to read full message JSON first to get the most reliable body
	body, err := getMailBodyAny(id)
	if err == nil && body != "" {
		return body, nil
	}

	// Fallback to /body.txt endpoint
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/message/"+id+"/body.txt", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// getMailBodyAny tries message JSON (Text and HTML) before falling back to empty.
func getMailBodyAny(id string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/message/"+id, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if text, ok := payload["Text"].(map[string]interface{}); ok {
		if b, _ := text["Body"].(string); b != "" {
			return b, nil
		}
	}
	if html, ok := payload["HTML"].(map[string]interface{}); ok {
		if b, _ := html["Body"].(string); b != "" {
			return b, nil
		}
	}
	return "", nil
}

// getMailHTMLBody fetches HTML body when available
func getMailHTMLBody(id string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/message/"+id+"/body.html", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// extractTokenFromMessage attempts to extract token from multiple message sources
func extractTokenFromMessage(id string) (string, error) {
	// Try JSON fields first
	if body, err := getMailBodyAny(id); err == nil {
		if tok, ok := tryExtractToken(body); ok {
			return tok, nil
		}
	}
	// Then plain text endpoint
	if body, err := getMailTextBody(id); err == nil {
		if tok, ok := tryExtractToken(body); ok {
			return tok, nil
		}
	}
	// Then HTML endpoint
	if body, err := getMailHTMLBody(id); err == nil {
		if tok, ok := tryExtractToken(body); ok {
			return tok, nil
		}
	}

	// Finally, search entire message JSON dump
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/message/"+id, nil)
	if err == nil {
		client := &http.Client{Timeout: 5 * time.Second}
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if tok, ok := tryExtractToken(string(b)); ok {
				return tok, nil
			}
		}
	}
	return "", fmt.Errorf("token not found in email body")
}

func tryExtractToken(body string) (string, bool) {
	// Look for token param in URLs, tolerant to HTML encoding
	patterns := []string{
		`token=([A-Za-z0-9._-]+)`,     // plain
		`token&#61;([A-Za-z0-9._-]+)`, // HTML encoded '='
		`token%3D([A-Za-z0-9._-]+)`,   // URL-encoded '='
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(body); len(m) >= 2 {
			return m[1], true
		}
	}
	return "", false
}

// extractTokenFromBody finds token query param in a URL within the email body.
func extractTokenFromBody(body string) (string, error) {
	re := regexp.MustCompile(`token=([A-Za-z0-9._-]+)`) // JWT-like
	m := re.FindStringSubmatch(body)
	if len(m) >= 2 {
		return m[1], nil
	}
	return "", fmt.Errorf("token not found in email body")
}

// containsFold is case-insensitive substring check.
func containsFold(s, substr string) bool {
	return indexFold(s, substr) >= 0
}

// indexFold returns index of substr in s, case-insensitive.
func indexFold(s, substr string) int {
	return bytes.Index(bytes.ToLower([]byte(s)), bytes.ToLower([]byte(substr)))
}
