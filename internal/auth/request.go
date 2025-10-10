package auth

// RegisterRequest represents the user registration request payload.
type RegisterRequest struct {
	Name     string `json:"name"     validate:"required,max=50"                example:"fake name"`
	Email    string `json:"email"    validate:"required,email,max=50"          example:"fake@example.com"`
	Password string `json:"password" validate:"required,min=8,max=20,password" example:"password1"`
}

// LoginRequest represents the user login request payload.
type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email,max=50"          example:"fake@example.com"`
	Password string `json:"password" validate:"required,min=8,max=20,password" example:"password1"`
}

// LogoutRequest represents the user logout request payload.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,max=255" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1ZWJhYzUzNDk1NGI1NDEzOTgwNmMxMTIiLCJpYXQiOjE1ODkyOTg0ODQsImV4cCI6MTU4OTMwMDI4NH0.m1U63blB0MLej_WfB7yC2FTMnCziif9X8yzwDEfJXAg"`
}

// RefreshTokenRequest represents the token refresh request payload.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,max=255" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1ZWJhYzUzNDk1NGI1NDEzOTgwNmMxMTIiLCJpYXQiOjE1ODkyOTg0ODQsImV4cCI6MTU4OTMwMDI4NH0.m1U63blB0MLej_WfB7yC2FTMnCziif9X8yzwDEfJXAg"`
}

// ForgotPasswordRequest represents the forgot password request payload.
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email,max=50" example:"fake@example.com"`
}

// ResetPasswordRequest represents the password reset request payload.
type ResetPasswordRequest struct {
	Token string `json:"token" validate:"required,max=255" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"`
}
