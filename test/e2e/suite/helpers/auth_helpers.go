package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func GetAuthToken(baseURL, email, password string) (string, error) {
	loginData := map[string]string{"email": email, "password": password}
	resp, err := MakeRequest(http.MethodPost, baseURL+"/api/v1/auth/login", loginData, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with status %d", resp.StatusCode)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	tokens, ok := result["tokens"].(map[string]interface{})
	if !ok {
		return "", errors.New("tokens not found in response")
	}
	access, ok := tokens["access"].(map[string]interface{})
	if !ok {
		return "", errors.New("access token not found in response")
	}
	token, ok := access["token"].(string)
	if !ok {
		return "", errors.New("access token value not found in response")
	}
	return token, nil
}
