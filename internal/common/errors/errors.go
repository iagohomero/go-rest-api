// Package errors defines common application domain errors.
package errors

import "errors"

var (
	ErrNotFound     = errors.New("resource not found")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrConflict     = errors.New("resource already exists")
	ErrBadRequest   = errors.New("bad request")
	ErrInternal     = errors.New("internal server error")
	ErrInvalidInput = errors.New("invalid input")
)
