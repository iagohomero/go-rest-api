//nolint:testpackage // E2E tests need access to internal packages
package e2e

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	e2esuite "go-rest-api/test/e2e/suite"
	"go-rest-api/test/e2e/suite/helpers"
)

var (
	baseURL            string
	mailpitHTTPBaseURL string
)

// TestMain sets up the test environment with a PostgreSQL container.
func TestMain(m *testing.M) {
	ctx := context.Background()
	s, err := e2esuite.StartSuite(ctx)
	if err != nil {
		panic(err)
	}
	baseURL = s.BaseURL
	mailpitHTTPBaseURL = s.MailpitHTTPBaseURL
	code := m.Run()
	e2esuite.StopSuite(ctx)
	os.Exit(code)
}

// Thin wrappers delegating to suite helpers (preserve current function names/signatures)
// makeRequest
// createTestUser
// getAuthToken
// cleanupTestData
// waitForMail / extractTokenFromMessage / containsFold / indexFold

// expose wrappers with same names used by tests
// makeRequest
func makeRequest(method, url string, body interface{}, headers map[string]string) (*http.Response, error) {
	return helpers.MakeRequest(method, url, body, headers)
}

// createTestUser
func createTestUser(name, email, password, role string) error {
	return e2esuite.CreateTestUser(name, email, password, role)
}

// getAuthToken
func getAuthToken(email, password string) (string, error) {
	return helpers.GetAuthToken(baseURL, email, password)
}

// cleanupTestData
func cleanupTestData() { e2esuite.CleanupTestData() }

// waitForMail
func waitForMail(toContains string, subjectContains string, timeout time.Duration) (map[string]interface{}, error) {
	return e2esuite.WaitForMail(mailpitHTTPBaseURL, toContains, subjectContains, timeout)
}

// extractTokenFromMessage
func extractTokenFromMessage(id string) (string, error) {
	return e2esuite.ExtractTokenFromMessage(mailpitHTTPBaseURL, id)
}

// containsFold / indexFold
func containsFold(s, substr string) bool { return e2esuite.ContainsFold(s, substr) }
func indexFold(s, substr string) int     { return e2esuite.IndexFold(s, substr) }

// removed in favor of suite helpers
