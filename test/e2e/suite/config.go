package e2esuite

import (
	"go-rest-api/internal/config"
)

func buildTestConfig(dbHost string, dbPort int, smtpHost string, smtpPort int, mailpitHTTPBaseURL string) *config.Config {
	return &config.Config{
		App: config.AppConfig{
			Environment: "test",
			Host:        "localhost",
			Port:        8085,
			Name:        "go-rest-api-test",
		},
		Database: config.DatabaseConfig{
			Host:     dbHost,
			User:     "testuser",
			Password: "testpass",
			Name:     "testdb",
			Port:     dbPort,
		},
		JWT: config.JWTConfig{
			Secret:              "test-secret-key-for-jwt-tokens",
			AccessExpMinutes:    15,
			RefreshExpDays:      7,
			ResetPasswordExpMin: 15,
			VerifyEmailExpMin:   15,
		},
		SMTP: config.SMTPConfig{
			Host:     smtpHost,
			Port:     smtpPort,
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
}
