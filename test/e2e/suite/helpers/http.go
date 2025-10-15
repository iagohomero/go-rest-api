package helpers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

const (
	// HTTPClientTimeout is the HTTP client timeout.
	HTTPClientTimeout = 10 * time.Second
)

func MakeRequest(method, url string, body interface{}, headers map[string]string) (*http.Response, error) {
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
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: HTTPClientTimeout}
	return client.Do(req)
}
