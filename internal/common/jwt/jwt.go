// Package jwt provides JWT token verification utilities.
package jwt

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidTokenClaims = errors.New("invalid token claims")
	ErrInvalidTokenType   = errors.New("invalid token type")
	ErrInvalidTokenSub    = errors.New("invalid token sub")
)

// VerifyToken validates a JWT token and returns the user ID from the sub claim.
func VerifyToken(tokenStr, secret, tokenType string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(_ *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrInvalidTokenClaims
	}

	jwtType, ok := claims["type"].(string)
	if !ok || jwtType != tokenType {
		return "", ErrInvalidTokenType
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return "", ErrInvalidTokenSub
	}

	return userID, nil
}
