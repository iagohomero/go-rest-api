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

const (
	// MailpitClientTimeout is the mailpit client timeouts.
	MailpitClientTimeout = 5 * time.Second
	MailpitPollDelay     = 300 * time.Millisecond
	// RegexMatchIndex is the regex match index for token extraction.
	RegexMatchIndex = 2
)

func FetchMailpitMessages(mailpitHTTPBaseURL string) ([]map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/messages", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: MailpitClientTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		Messages []map[string]interface{} `json:"messages"`
	}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&payload); decodeErr != nil {
		return nil, decodeErr
	}
	return payload.Messages, nil
}

func WaitForMail(
	mailpitHTTPBaseURL,
	toContains,
	subjectContains string,
	timeout time.Duration,
) (map[string]interface{}, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs, err := FetchMailpitMessages(mailpitHTTPBaseURL)
		if err != nil {
			time.Sleep(MailpitPollDelay)
			continue
		}

		for _, m := range msgs {
			if matchesEmailCriteria(m, toContains, subjectContains) {
				return m, nil
			}
		}
		time.Sleep(MailpitPollDelay)
	}
	return nil, fmt.Errorf(
		"mail not received for recipient=%s subject~=%s within %s",
		toContains,
		subjectContains,
		timeout,
	)
}

func matchesEmailCriteria(m map[string]interface{}, toContains, subjectContains string) bool {
	subject, _ := m["Subject"].(string)
	matchesTo := matchesToField(m, toContains)
	matchesSubject := matchesSubjectField(subject, subjectContains)
	return matchesTo && matchesSubject
}

func matchesToField(m map[string]interface{}, toContains string) bool {
	if toContains == "" {
		return true
	}

	if toArr, ok := m["To"].([]interface{}); ok {
		return matchesToArray(toArr, toContains)
	}

	if toStr, ok := m["To"].(string); ok {
		return ContainsFold(toStr, toContains)
	}

	return false
}

func matchesToArray(toArr []interface{}, toContains string) bool {
	for _, item := range toArr {
		if matchesToItem(item, toContains) {
			return true
		}
	}
	return false
}

func matchesToItem(item interface{}, toContains string) bool {
	switch v := item.(type) {
	case string:
		return ContainsFold(v, toContains)
	case map[string]interface{}:
		return matchesToMap(v, toContains)
	}
	return false
}

func matchesToMap(toMap map[string]interface{}, toContains string) bool {
	if email, _ := toMap["Address"].(string); email != "" && ContainsFold(email, toContains) {
		return true
	}
	if email, _ := toMap["Email"].(string); email != "" && ContainsFold(email, toContains) {
		return true
	}
	return false
}

func matchesSubjectField(subject, subjectContains string) bool {
	return subjectContains == "" || (subject != "" && ContainsFold(subject, subjectContains))
}

func getMailBodyAny(mailpitHTTPBaseURL, id string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, mailpitHTTPBaseURL+"/api/v1/message/"+id, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: MailpitClientTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var payload map[string]interface{}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&payload); decodeErr != nil {
		return "", decodeErr
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
	client := &http.Client{Timeout: MailpitClientTimeout}
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
	client := &http.Client{Timeout: MailpitClientTimeout}
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
		client := &http.Client{Timeout: MailpitClientTimeout}
		if resp, doErr := client.Do(req); doErr == nil {
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
		if m := re.FindStringSubmatch(body); len(m) >= RegexMatchIndex {
			return m[1], true
		}
	}
	return "", false
}

func ContainsFold(s, substr string) bool { return IndexFold(s, substr) >= 0 }
func IndexFold(s, substr string) int {
	return bytes.Index(bytes.ToLower([]byte(s)), bytes.ToLower([]byte(substr)))
}
