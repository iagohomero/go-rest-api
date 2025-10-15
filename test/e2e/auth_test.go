//nolint:testpackage // E2E tests need access to internal packages
package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
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
	if decodeErr := json.NewDecoder(resp.Body).Decode(&result); decodeErr != nil {
		t.Fatalf("Failed to decode response: %v", decodeErr)
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
	if loginDecodeErr := json.NewDecoder(resp.Body).Decode(&result); loginDecodeErr != nil {
		t.Fatalf("Failed to decode response: %v", loginDecodeErr)
	}

	// Check if response contains tokens in nested structure
	tokens, ok := result["tokens"].(map[string]interface{})
	if !ok {
		t.Error("Expected 'tokens' field in response")
		return
	}

	if _, accessOk := tokens["access"]; !accessOk {
		t.Error("Expected 'access' field in tokens")
	}
	if _, refreshOk := tokens["refresh"]; !refreshOk {
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
	if loginDecodeErr := json.NewDecoder(resp.Body).Decode(&loginResult); loginDecodeErr != nil {
		t.Fatalf("Failed to decode login response: %v", loginDecodeErr)
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
	if refreshDecodeErr := json.NewDecoder(resp.Body).Decode(&result); refreshDecodeErr != nil {
		t.Fatalf("Failed to decode response: %v", refreshDecodeErr)
	}

	// Check if response contains new tokens in nested structure
	refreshTokens, ok := result["tokens"].(map[string]interface{})
	if !ok {
		t.Error("Expected 'tokens' field in response")
		return
	}

	if _, refreshAccessOk := refreshTokens["access"]; !refreshAccessOk {
		t.Error("Expected 'access' field in tokens")
	}
	if _, refreshRefreshOk := refreshTokens["refresh"]; !refreshRefreshOk {
		t.Error("Expected 'refresh' field in tokens")
	}
}

func TestLogoutFlow(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Register
	registerData := map[string]string{
		"name":     "Logout User",
		"email":    "logout@example.com",
		"password": "password123",
	}
	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	resp.Body.Close()

	// Login
	loginData := map[string]string{
		"email":    "logout@example.com",
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

	tokens, ok := loginResult["tokens"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected tokens in login response")
	}
	refresh, ok := tokens["refresh"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected refresh token in login response")
	}
	refreshToken, _ := refresh["token"].(string)
	if refreshToken == "" {
		t.Fatal("Empty refresh token")
	}

	// Logout (invalidate refresh)
	logoutBody := map[string]string{"refresh_token": refreshToken}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/logout", logoutBody, nil)
	if err != nil {
		t.Fatalf("Failed to logout: %v", err)
	}
	resp.Body.Close()

	// Try refresh after logout -> should fail (401)
	refreshBody := map[string]string{"refresh_token": refreshToken}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/refresh-tokens", refreshBody, nil)
	if err != nil {
		t.Fatalf("Failed to call refresh after logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 401/400 after logout when refreshing, got %d", resp.StatusCode)
	}
}

func TestGoogleLoginRedirect(t *testing.T) {
	// No cleanup required; stateless check
	// Use a client that does not follow redirects so we can inspect 302/303
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/auth/google", nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to call /auth/google: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected redirect status, got %d", resp.StatusCode)
	}

	// Location should contain Google's OAuth endpoint
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("Missing Location header")
	}
	if !(containsFold(loc, "https://accounts.google.com") || containsFold(loc, "google")) {
		t.Errorf("Expected Location to be Google OAuth URL, got %s", loc)
	}

	// Cookie oauth_state should be set
	foundState := false
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" && c.Value != "" {
			foundState = true
			break
		}
	}
	if !foundState {
		t.Error("Expected oauth_state cookie to be set")
	}
}

func TestForgotPasswordSendsEmail(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create a user
	registerData := map[string]string{
		"name":     "Forgot User",
		"email":    "forgot@example.com",
		"password": "password123",
	}
	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	resp.Body.Close()

	// Call forgot-password
	reqBody := map[string]string{"email": "forgot@example.com"}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/forgot-password", reqBody, nil)
	if err != nil {
		t.Fatalf("Failed to call forgot-password: %v", err)
	}
	resp.Body.Close()

	// Wait for email to arrive in Mailpit
	msg, err := waitForMail("forgot@example.com", "Reset password", 10*time.Second)
	if err != nil {
		t.Fatalf("Expected reset password email: %v", err)
	}

	id, _ := msg["ID"].(string)
	if id == "" {
		t.Fatalf("Mailpit message ID missing")
	}
	if _, err := extractTokenFromMessage(id); err != nil {
		t.Fatalf("Expected token in email body: %v", err)
	}
}

func TestResetPasswordFlow(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Register
	registerData := map[string]string{
		"name":     "Reset User",
		"email":    "reset@example.com",
		"password": "password123",
	}
	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	resp.Body.Close()

	// Request forgot password -> email with token
	reqBody := map[string]string{"email": "reset@example.com"}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/forgot-password", reqBody, nil)
	if err != nil {
		t.Fatalf("Failed to call forgot-password: %v", err)
	}
	resp.Body.Close()

	msg, err := waitForMail("reset@example.com", "Reset password", 10*time.Second)
	if err != nil {
		t.Fatalf("Expected reset password email: %v", err)
	}
	id, _ := msg["ID"].(string)
	token, err := extractTokenFromMessage(id)
	if err != nil {
		t.Fatalf("Failed to extract token from email: %v", err)
	}

	// Reset password using token
	newPass := map[string]any{"password": "newpassword123", "verified_email": true}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/reset-password?token="+token, newPass, nil)
	if err != nil {
		t.Fatalf("Failed to call reset-password: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 resetting password, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Login with new password should work
	loginData := map[string]string{"email": "reset@example.com", "password": "newpassword123"}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		t.Fatalf("Failed to login with new password: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 login after password reset, got %d", resp.StatusCode)
	}
}

func TestSendVerificationEmail(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Register -> login to get access token
	registerData := map[string]string{
		"name":     "Verify User",
		"email":    "verify@example.com",
		"password": "password123",
	}
	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}
	resp.Body.Close()

	loginData := map[string]string{"email": "verify@example.com", "password": "password123"}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	var loginResult map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&loginResult); err != nil {
		t.Fatalf("Failed to decode login: %v", err)
	}
	resp.Body.Close()
	tokens, _ := loginResult["tokens"].(map[string]any)
	access, _ := tokens["access"].(map[string]any)
	accessToken, _ := access["token"].(string)
	if accessToken == "" {
		t.Fatalf("Missing access token")
	}

	headers := map[string]string{"Authorization": "Bearer " + accessToken}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/send-verification-email", nil, headers)
	if err != nil {
		t.Fatalf("Failed to call send-verification-email: %v", err)
	}
	resp.Body.Close()

	// Expect verification email
	msg, err := waitForMail("verify@example.com", "Email Verification", 10*time.Second)
	if err != nil {
		t.Fatalf("Expected verification email: %v", err)
	}
	id, _ := msg["ID"].(string)
	if id == "" {
		t.Fatalf("Missing Mailpit message ID")
	}
	if _, err := extractTokenFromMessage(id); err != nil {
		t.Fatalf("Expected token in verification email: %v", err)
	}
}

func TestVerifyEmailFlow(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Register and login to get access token
	registerData := map[string]string{
		"name":     "Verify2 User",
		"email":    "verify2@example.com",
		"password": "password123",
	}
	resp, err := makeRequest("POST", baseURL+"/api/v1/auth/register", registerData, nil)
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}
	resp.Body.Close()

	loginData := map[string]string{"email": "verify2@example.com", "password": "password123"}
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	var loginResult map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&loginResult); err != nil {
		t.Fatalf("Failed to decode login: %v", err)
	}
	resp.Body.Close()
	tokens, _ := loginResult["tokens"].(map[string]any)
	access, _ := tokens["access"].(map[string]any)
	accessToken, _ := access["token"].(string)

	headers := map[string]string{"Authorization": "Bearer " + accessToken}

	// Trigger send-verification-email
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/send-verification-email", nil, headers)
	if err != nil {
		t.Fatalf("Failed to send verification email: %v", err)
	}
	resp.Body.Close()

	// Get verification email
	msg, err := waitForMail("verify2@example.com", "Email Verification", 10*time.Second)
	if err != nil {
		t.Fatalf("Expected verification email: %v", err)
	}
	id, _ := msg["ID"].(string)
	token, err := extractTokenFromMessage(id)
	if err != nil {
		t.Fatalf("Failed to extract token: %v", err)
	}

	// Call verify-email
	resp, err = makeRequest("POST", baseURL+"/api/v1/auth/verify-email?token="+token, nil, nil)
	if err != nil {
		t.Fatalf("Failed to verify email: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on verify-email, got %d", resp.StatusCode)
	}
}
