package user

import (
	"fmt"

	"go-rest-api/internal/common/errors"
)

var (
	ErrUserNotFound = fmt.Errorf("user not found: %w", errors.ErrNotFound)
	ErrEmailTaken   = fmt.Errorf("email already taken: %w", errors.ErrConflict)
)

// WrapError wraps an error with additional context message.
func WrapError(err error, msg string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}
