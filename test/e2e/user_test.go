package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestGetUsers(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create admin user
	if err := createTestUser("Admin User", "admin@example.com", "password123", "admin"); err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	// Get auth token for admin
	token, err := getAuthToken("admin@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to get auth token: %v", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	resp, err := makeRequest("GET", baseURL+"/api/v1/users", nil, headers)
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

	// Check if response contains users list
	if _, resultsOk := result["results"]; !resultsOk {
		t.Error("Expected 'results' field in response")
	}
}

func TestGetUsersForbidden(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create regular user
	if err := createTestUser("Regular User", "user@example.com", "password123", "user"); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Get auth token for regular user
	token, err := getAuthToken("user@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to get auth token: %v", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	resp, err := makeRequest("GET", baseURL+"/api/v1/users", nil, headers)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

func TestGetUserByID(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create admin user
	if err := createTestUser("Admin User", "admin@example.com", "password123", "admin"); err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	// Get auth token for admin
	token, err := getAuthToken("admin@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to get auth token: %v", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	// First get users to find a user ID
	resp, err := makeRequest("GET", baseURL+"/api/v1/users", nil, headers)
	if err != nil {
		t.Fatalf("Failed to get users: %v", err)
	}

	var usersResult map[string]interface{}
	if usersDecodeErr := json.NewDecoder(resp.Body).Decode(&usersResult); usersDecodeErr != nil {
		t.Fatalf("Failed to decode users response: %v", usersDecodeErr)
	}
	resp.Body.Close()

	users, ok := usersResult["results"].([]interface{})
	if !ok || len(users) == 0 {
		t.Fatal("Expected results in response")
	}

	user := users[0].(map[string]interface{})
	userID, ok := user["id"].(string)
	if !ok {
		t.Fatal("Expected user ID in response")
	}

	// Now get specific user by ID
	resp, err = makeRequest("GET", baseURL+"/api/v1/users/"+userID, nil, headers)
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

	// Check if response contains user data
	if _, userOk := result["user"]; !userOk {
		t.Error("Expected 'user' field in response")
	}
}

func TestCreateUser(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create admin user
	if err := createTestUser("Admin User", "admin@example.com", "password123", "admin"); err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	// Get auth token for admin
	token, err := getAuthToken("admin@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to get auth token: %v", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	userData := map[string]string{
		"name":     "New User",
		"email":    "newuser@example.com",
		"password": "password123",
		"role":     "user",
	}

	resp, err := makeRequest("POST", baseURL+"/api/v1/users", userData, headers)
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

	// Check if response contains user data
	if _, userOk := result["user"]; !userOk {
		t.Error("Expected 'user' field in response")
	}
}

func TestUpdateUser(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create admin user
	if err := createTestUser("Admin User", "admin@example.com", "password123", "admin"); err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	// Create user to update
	if err := createTestUser("User To Update", "updateme@example.com", "password123", "user"); err != nil {
		t.Fatalf("Failed to create user to update: %v", err)
	}

	// Get auth token for admin
	token, err := getAuthToken("admin@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to get auth token: %v", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	// First get users to find the user ID
	resp, err := makeRequest("GET", baseURL+"/api/v1/users", nil, headers)
	if err != nil {
		t.Fatalf("Failed to get users: %v", err)
	}

	var usersResult map[string]interface{}
	if usersDecodeErr := json.NewDecoder(resp.Body).Decode(&usersResult); usersDecodeErr != nil {
		t.Fatalf("Failed to decode users response: %v", usersDecodeErr)
	}
	resp.Body.Close()

	users, ok := usersResult["results"].([]interface{})
	if !ok {
		t.Fatal("Expected results in response")
	}

	var userID string
	for _, u := range users {
		user := u.(map[string]interface{})
		if user["email"] == "updateme@example.com" {
			userID, ok = user["id"].(string)
			if !ok {
				t.Fatal("Expected user ID in response")
			}
			break
		}
	}

	if userID == "" {
		t.Fatal("Could not find user to update")
	}

	// Update user
	updateData := map[string]string{
		"name": "Updated User Name",
		"role": "admin",
	}

	resp, err = makeRequest("PATCH", baseURL+"/api/v1/users/"+userID, updateData, headers)
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

	// Check if response contains updated user data
	if _, userOk := result["user"]; !userOk {
		t.Error("Expected 'user' field in response")
	}
}

func TestDeleteUser(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Create admin user
	if err := createTestUser("Admin User", "admin@example.com", "password123", "admin"); err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	// Create user to delete
	if err := createTestUser("User To Delete", "deleteme@example.com", "password123", "user"); err != nil {
		t.Fatalf("Failed to create user to delete: %v", err)
	}

	// Get auth token for admin
	token, err := getAuthToken("admin@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to get auth token: %v", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	// First get users to find the user ID
	resp, err := makeRequest("GET", baseURL+"/api/v1/users", nil, headers)
	if err != nil {
		t.Fatalf("Failed to get users: %v", err)
	}

	var usersResult map[string]interface{}
	if usersDecodeErr := json.NewDecoder(resp.Body).Decode(&usersResult); usersDecodeErr != nil {
		t.Fatalf("Failed to decode users response: %v", usersDecodeErr)
	}
	resp.Body.Close()

	users, ok := usersResult["results"].([]interface{})
	if !ok {
		t.Fatal("Expected results in response")
	}

	var userID string
	for _, u := range users {
		user := u.(map[string]interface{})
		if user["email"] == "deleteme@example.com" {
			userID, ok = user["id"].(string)
			if !ok {
				t.Fatal("Expected user ID in response")
			}
			break
		}
	}

	if userID == "" {
		t.Fatal("Could not find user to delete")
	}

	// Delete user
	resp, err = makeRequest("DELETE", baseURL+"/api/v1/users/"+userID, nil, headers)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestUserUnauthorized(t *testing.T) {
	cleanupTestData()
	defer cleanupTestData()

	// Try to access users endpoint without token
	resp, err := makeRequest("GET", baseURL+"/api/v1/users", nil, nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}
