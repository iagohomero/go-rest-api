package user

// CreateUserRequest represents the request body for creating a new user.
type CreateUserRequest struct {
	Name     string `json:"name"     validate:"required,max=50"                example:"fake name"`
	Email    string `json:"email"    validate:"required,email,max=50"          example:"fake@example.com"`
	Password string `json:"password" validate:"required,min=8,max=20,password" example:"password1"`
	Role     string `json:"role"     validate:"required,role,max=50"           example:"user"`
}

// UpdateUserRequest represents the request body for updating a user.
type UpdateUserRequest struct {
	Name     string `json:"name,omitempty"     validate:"omitempty,max=50"                example:"fake name"`
	Email    string `json:"email"              validate:"omitempty,email,max=50"          example:"fake@example.com"`
	Password string `json:"password,omitempty" validate:"omitempty,min=8,max=20,password" example:"password1"`
}

// UpdateUserPasswordRequest represents the request body for updating user password or email verification.
type UpdateUserPasswordRequest struct {
	Password      string `json:"password,omitempty" validate:"omitempty,min=8,max=20,password" example:"password1"`
	VerifiedEmail bool   `json:"verified_email"     validate:"omitempty,boolean"                                   swaggerignore:"true"`
}

// QueryUserRequest represents query parameters for listing users.
type QueryUserRequest struct {
	Page   int    `validate:"omitempty,number,max=50"`
	Limit  int    `validate:"omitempty,number,max=50"`
	Search string `validate:"omitempty,max=50"`
}

// CreateGoogleUserRequest represents the request body for creating a user from Google OAuth.
type CreateGoogleUserRequest struct {
	Name          string `json:"name"           validate:"required,max=50"`
	Email         string `json:"email"          validate:"required,email,max=50"`
	VerifiedEmail bool   `json:"verified_email" validate:"required"`
}
