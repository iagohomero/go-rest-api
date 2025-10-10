package config

import (
	"errors"
	"fmt"
	"time"

	"go-rest-api/internal/common/logger"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application.
type Config struct {
	App      AppConfig
	Database DatabaseConfig
	JWT      JWTConfig
	SMTP     SMTPConfig
	OAuth    OAuthConfig
}

// AppConfig holds application server configuration.
type AppConfig struct {
	Environment string
	Host        string
	Port        int
	Name        string
}

// DatabaseConfig holds database connection configuration.
type DatabaseConfig struct {
	Host     string
	User     string
	Password string
	Name     string
	Port     int
}

// JWTConfig holds JWT token configuration.
type JWTConfig struct {
	Secret              string
	AccessExpMinutes    int
	RefreshExpDays      int
	ResetPasswordExpMin int
	VerifyEmailExpMin   int
}

// SMTPConfig holds email server configuration.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// OAuthConfig holds OAuth provider configuration.
type OAuthConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	RedirectURL        string
}

// Address returns the server address in host:port format.
func (a AppConfig) Address() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

// IsProd returns true if running in production environment.
func (a AppConfig) IsProd() bool {
	return a.Environment == "prod" || a.Environment == "production"
}

// DSN returns the PostgreSQL connection string.
func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=UTC",
		d.Host, d.User, d.Password, d.Name, d.Port,
	)
}

// AccessTokenDuration converts access token expiry minutes to time.Duration.
func (j JWTConfig) AccessTokenDuration() time.Duration {
	return time.Duration(j.AccessExpMinutes) * time.Minute
}

// RefreshTokenDuration converts refresh token expiry days to time.Duration.
func (j JWTConfig) RefreshTokenDuration() time.Duration {
	return time.Duration(j.RefreshExpDays) * 24 * time.Hour
}

// ResetPasswordTokenDuration converts reset password token expiry minutes to time.Duration.
func (j JWTConfig) ResetPasswordTokenDuration() time.Duration {
	return time.Duration(j.ResetPasswordExpMin) * time.Minute
}

// VerifyEmailTokenDuration converts verify email token expiry minutes to time.Duration.
func (j JWTConfig) VerifyEmailTokenDuration() time.Duration {
	return time.Duration(j.VerifyEmailExpMin) * time.Minute
}

// Load loads configuration from .env file.
func Load() (*Config, error) {
	if err := loadConfigFile(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	cfg := &Config{
		App: AppConfig{
			Environment: viper.GetString("APP_ENV"),
			Host:        viper.GetString("APP_HOST"),
			Port:        viper.GetInt("APP_PORT"),
			Name:        "go-rest-api",
		},
		Database: DatabaseConfig{
			Host:     viper.GetString("DB_HOST"),
			User:     viper.GetString("DB_USER"),
			Password: viper.GetString("DB_PASSWORD"),
			Name:     viper.GetString("DB_NAME"),
			Port:     viper.GetInt("DB_PORT"),
		},
		JWT: JWTConfig{
			Secret:              viper.GetString("JWT_SECRET"),
			AccessExpMinutes:    viper.GetInt("JWT_ACCESS_EXP_MINUTES"),
			RefreshExpDays:      viper.GetInt("JWT_REFRESH_EXP_DAYS"),
			ResetPasswordExpMin: viper.GetInt("JWT_RESET_PASSWORD_EXP_MINUTES"),
			VerifyEmailExpMin:   viper.GetInt("JWT_VERIFY_EMAIL_EXP_MINUTES"),
		},
		SMTP: SMTPConfig{
			Host:     viper.GetString("SMTP_HOST"),
			Port:     viper.GetInt("SMTP_PORT"),
			Username: viper.GetString("SMTP_USERNAME"),
			Password: viper.GetString("SMTP_PASSWORD"),
			From:     viper.GetString("EMAIL_FROM"),
		},
		OAuth: OAuthConfig{
			GoogleClientID:     viper.GetString("GOOGLE_CLIENT_ID"),
			GoogleClientSecret: viper.GetString("GOOGLE_CLIENT_SECRET"),
			RedirectURL:        viper.GetString("REDIRECT_URL"),
		},
	}

	return cfg, nil
}

func loadConfigFile() error {
	configPaths := []string{
		"./",     // For app
		"../../", // For test folder
	}

	for _, path := range configPaths {
		viper.SetConfigFile(path + ".env")

		if err := viper.ReadInConfig(); err == nil {
			logger.New().Infof("Config file loaded from %s", path)
			return nil
		}
	}

	return errors.New("no config file found")
}
