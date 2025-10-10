package config

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// NewGoogleOAuthConfig creates a Google OAuth2 configuration for authentication.
func NewGoogleOAuthConfig(cfg *Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.OAuth.GoogleClientID,
		ClientSecret: cfg.OAuth.GoogleClientSecret,
		RedirectURL:  cfg.OAuth.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}
