//nolint:testpackage // E2E tests need access to internal packages
package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestHealthCheck(t *testing.T) {
	resp, err := makeRequest("GET", baseURL+"/api/v1/health/", nil, nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&result); decodeErr != nil {
		t.Fatalf("Failed to decode response: %v", decodeErr)
	}

	// Check if response contains expected health check fields
	if _, ok := result["status"]; !ok {
		t.Error("Expected 'status' field in response")
	}

	// Verify status is "success" (as returned by the API)
	status, ok := result["status"].(string)
	if !ok {
		t.Error("Expected status to be a string")
	}

	if status != "success" {
		t.Errorf("Expected status to be 'success', got '%s'", status)
	}
}
