package e2esuite

import (
	"go-rest-api/internal/config"
)

const (
	// TestServerPort is the test server configuration.
	TestServerPort = 8085

	// JWTAccessExpMinutes is the JWT token expiration times (in minutes/days).
	JWTAccessExpMinutes    = 15
	JWTRefreshExpDays      = 7
	JWTResetPasswordExpMin = 15
	JWTVerifyEmailExpMin   = 15
)

func buildTestConfig(dbHost string, dbPort int, smtpHost string, smtpPort int, _ string) *config.Config {
	return &config.Config{
		App: config.AppConfig{
			Environment: "test",
			Host:        "localhost",
			Port:        TestServerPort,
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
			AccessExpMinutes:    JWTAccessExpMinutes,
			RefreshExpDays:      JWTRefreshExpDays,
			ResetPasswordExpMin: JWTResetPasswordExpMin,
			VerifyEmailExpMin:   JWTVerifyEmailExpMin,
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
