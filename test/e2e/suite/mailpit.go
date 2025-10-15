package e2esuite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

func FetchMailpitMessages(mailpitHTTPBaseURL string) ([]map[string]interface{}, error) {
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

func WaitForMail(mailpitHTTPBaseURL, toContains, subjectContains string, timeout time.Duration) (map[string]interface{}, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs, err := FetchMailpitMessages(mailpitHTTPBaseURL)
		if err == nil {
			for _, m := range msgs {
				subject, _ := m["Subject"].(string)
				matchesTo := toContains == ""
				if !matchesTo {
					if toArr, ok := m["To"].([]interface{}); ok {
						for _, item := range toArr {
							switch v := item.(type) {
							case string:
								if ContainsFold(v, toContains) {
									matchesTo = true
								}
							case map[string]interface{}:
								if email, _ := v["Address"].(string); email != "" && ContainsFold(email, toContains) {
									matchesTo = true
								}
								if email, _ := v["Email"].(string); email != "" && ContainsFold(email, toContains) {
									matchesTo = true
								}
							}
							if matchesTo {
								break
							}
						}
					} else if toStr, ok := m["To"].(string); ok {
						matchesTo = ContainsFold(toStr, toContains)
					}
				}
				matchesSubject := subjectContains == "" || (subject != "" && ContainsFold(subject, subjectContains))
				if matchesTo && matchesSubject {
					return m, nil
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return nil, fmt.Errorf("mail not received for recipient=%s subject~=%s within %s", toContains, subjectContains, timeout)
}

func getMailBodyAny(mailpitHTTPBaseURL, id string) (string, error) {
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

func getMailTextBody(mailpitHTTPBaseURL, id string) (string, error) {
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

func getMailHTMLBody(mailpitHTTPBaseURL, id string) (string, error) {
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

func ExtractTokenFromMessage(mailpitHTTPBaseURL, id string) (string, error) {
	if body, err := getMailBodyAny(mailpitHTTPBaseURL, id); err == nil {
		if tok, ok := TryExtractToken(body); ok {
			return tok, nil
		}
	}
	if body, err := getMailTextBody(mailpitHTTPBaseURL, id); err == nil {
		if tok, ok := TryExtractToken(body); ok {
			return tok, nil
		}
	}
	if body, err := getMailHTMLBody(mailpitHTTPBaseURL, id); err == nil {
		if tok, ok := TryExtractToken(body); ok {
			return tok, nil
		}
	}
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/message/"+id, nil)
	if err == nil {
		client := &http.Client{Timeout: 5 * time.Second}
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if tok, ok := TryExtractToken(string(b)); ok {
				return tok, nil
			}
		}
	}
	return "", fmt.Errorf("token not found in email body")
}

func TryExtractToken(body string) (string, bool) {
	patterns := []string{
		`token=([A-Za-z0-9._-]+)`,
		`token&#61;([A-Za-z0-9._-]+)`,
		`token%3D([A-Za-z0-9._-]+)`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(body); len(m) >= 2 {
			return m[1], true
		}
	}
	return "", false
}

func ContainsFold(s, substr string) bool { return IndexFold(s, substr) >= 0 }
func IndexFold(s, substr string) int {
	return bytes.Index(bytes.ToLower([]byte(s)), bytes.ToLower([]byte(substr)))
}
