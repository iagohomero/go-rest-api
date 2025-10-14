package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRegister(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	registerData := map[string]string{
		"name":     "Test User",
		"email":    "testuser@example.com",
		"password": "password123",
	}

	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check if response contains expected fields
	if _, ok := result["message"]; !ok {
		t.Error("Expected 'message' field in response")
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create first user
	registerData := map[string]string{
		"name":     "Test User 1",
		"email":    "duplicate@example.com",
		"password": "password123",
	}

	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to make first request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201 for first registration, got %d", resp.StatusCode)
	}

	// Try to register with same email
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to make second request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("Expected status 409 for duplicate email, got %d", resp.StatusCode)
	}
}

func TestLogin(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// First register a user
	registerData := map[string]string{
		"name":     "Test User",
		"email":    "login@example.com",
		"password": "password123",
	}

	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	resp.Body.Close()

	// Now try to login
	loginData := map[string]string{
		"email":    "login@example.com",
		"password": "password123",
	}

	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		t.Fatalf("Failed to make login request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check if response contains tokens in nested structure
	tokens, ok := result["tokens"].(map[string]interface{})
	if !ok {
		t.Error("Expected 'tokens' field in response")
		return
	}

	if _, ok := tokens["access"]; !ok {
		t.Error("Expected 'access' field in tokens")
	}
	if _, ok := tokens["refresh"]; !ok {
		t.Error("Expected 'refresh' field in tokens")
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	loginData := map[string]string{
		"email":    "nonexistent@example.com",
		"password": "wrongpassword",
	}

	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 401 or 400, got %d", resp.StatusCode)
	}
}

func TestRefreshTokens(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// First register and login to get tokens
	registerData := map[string]string{
		"name":     "Test User",
		"email":    "refresh@example.com",
		"password": "password123",
	}

	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	resp.Body.Close()

	loginData := map[string]string{
		"email":    "refresh@example.com",
		"password": "password123",
	}

	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	var loginResult map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&loginResult); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}
	resp.Body.Close()

	// Access nested token structure
	tokens, ok := loginResult["tokens"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected 'tokens' field in login response")
	}

	refresh, ok := tokens["refresh"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected 'refresh' field in tokens")
	}

	refreshToken, ok := refresh["token"].(string)
	if !ok {
		t.Fatal("Expected refresh token value in response")
	}

	// Now try to refresh tokens
	refreshData := map[string]string{
		"refresh_token": refreshToken,
	}

	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/refresh-tokens", refreshData, nil)
	if err != nil {
		t.Fatalf("Failed to make refresh request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check if response contains new tokens in nested structure
	refreshTokens, ok := result["tokens"].(map[string]interface{})
	if !ok {
		t.Error("Expected 'tokens' field in response")
		return
	}

	if _, ok := refreshTokens["access"]; !ok {
		t.Error("Expected 'access' field in tokens")
	}
	if _, ok := refreshTokens["refresh"]; !ok {
		t.Error("Expected 'refresh' field in tokens")
	}
}
