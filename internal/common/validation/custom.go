package validation

import (
	"regexp"

	"go-rest-api/internal/rbac"

	"github.com/go-playground/validator/v10"
)

// Password validates that a password contains at least one letter and one number.
func Password(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)

	return hasLetter && hasNumber
}

// Role validates that a role name is valid according to RBAC definitions.
func Role(fl validator.FieldLevel) bool {
	roleName := fl.Field().String()
	return rbac.IsValidRole(roleName)
}
