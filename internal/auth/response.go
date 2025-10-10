package auth

import (
	"go-rest-api/internal/user"
	"time"
)

// TokenExpires represents a token with its expiration time.
type TokenExpires struct {
	Token   string    `json:"token"   example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1ZWJhYzUzNDk1NGI1NDEzOTgwNmMxMTIiLCJpYXQiOjE1ODkyOTg0ODQsImV4cCI6MTU4OTMwMDI4NH0.m1U63blB0MLej_WfB7yC2FTMnCziif9X8yzwDEfJXAg"`
	Expires time.Time `json:"expires" example:"2024-10-07T11:56:46.618180553Z"`
}

// Tokens represents access and refresh tokens.
type Tokens struct {
	Access  TokenExpires `json:"access"`
	Refresh TokenExpires `json:"refresh"`
}

// RegisterResponse represents the user registration response.
type RegisterResponse struct {
	Code    int       `json:"code"    example:"201"`
	Status  string    `json:"status"  example:"success"`
	Message string    `json:"message" example:"Register successfully"`
	User    user.User `json:"user"`
	Tokens  Tokens    `json:"tokens"`
}

// LoginResponse represents the user login response.
type LoginResponse struct {
	Code    int       `json:"code"    example:"200"`
	Status  string    `json:"status"  example:"success"`
	Message string    `json:"message" example:"Login successfully"`
	User    user.User `json:"user"`
	Tokens  Tokens    `json:"tokens"`
}

// RefreshTokenResponse represents the token refresh response.
type RefreshTokenResponse struct {
	Code   int    `json:"code"   example:"200"`
	Status string `json:"status" example:"success"`
	Tokens Tokens `json:"tokens"`
}
