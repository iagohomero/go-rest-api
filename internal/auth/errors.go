package auth

import (
	"fmt"

	"go-rest-api/internal/common/errors"
)

var (
	ErrEmailTaken            = fmt.Errorf("email already taken: %w", errors.ErrConflict)
	ErrInvalidCredentials    = fmt.Errorf("invalid email or password: %w", errors.ErrUnauthorized)
	ErrInvalidToken          = fmt.Errorf("invalid or expired token: %w", errors.ErrUnauthorized)
	ErrTokenNotFound         = fmt.Errorf("token not found: %w", errors.ErrNotFound)
	ErrPasswordResetFailed   = fmt.Errorf("password reset failed: %w", errors.ErrInternal)
	ErrVerifyEmailFailed     = fmt.Errorf("email verification failed: %w", errors.ErrInternal)
	ErrTokenGenerationFailed = fmt.Errorf("failed to generate token: %w", errors.ErrInternal)
)

// WrapError wraps an error with additional context message.
func WrapError(err error, msg string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}
