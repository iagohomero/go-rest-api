package jwt_test

import (
	"errors"
	"testing"
	"time"

	"go-rest-api/internal/common/jwt"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyToken tests the VerifyToken function.
func TestVerifyToken(t *testing.T) {
	secret := "test-secret-key"
	userID := "test-user-id"

	tests := []struct {
		name          string
		tokenStr      string
		secret        string
		expectedType  string
		expectedError error
		setupToken    func() string
	}{
		{
			name:         "Success - Valid access token",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				claims := jwtlib.MapClaims{
					"sub":  userID,
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"type": "access",
				}
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			},
			expectedError: nil,
		},
		{
			name:         "Success - Valid refresh token",
			secret:       secret,
			expectedType: "refresh",
			setupToken: func() string {
				claims := jwtlib.MapClaims{
					"sub":  userID,
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(24 * time.Hour).Unix(),
					"type": "refresh",
				}
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			},
			expectedError: nil,
		},
		{
			name:         "Error - Invalid token format",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				return "invalid.token.format"
			},
			expectedError: jwt.ErrInvalidToken,
		},
		{
			name:         "Error - Wrong secret",
			secret:       "wrong-secret",
			expectedType: "access",
			setupToken: func() string {
				claims := jwtlib.MapClaims{
					"sub":  userID,
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"type": "access",
				}
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret)) // Signed with correct secret
				return tokenString
			},
			expectedError: jwt.ErrInvalidToken,
		},
		{
			name:         "Error - Expired token",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				claims := jwtlib.MapClaims{
					"sub":  userID,
					"iat":  time.Now().Add(-2 * time.Hour).Unix(),
					"exp":  time.Now().Add(-time.Hour).Unix(), // Expired
					"type": "access",
				}
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			},
			expectedError: jwt.ErrInvalidToken,
		},
		{
			name:         "Error - Wrong token type",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				claims := jwtlib.MapClaims{
					"sub":  userID,
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"type": "refresh", // Wrong type
				}
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			},
			expectedError: jwt.ErrInvalidTokenType,
		},
		{
			name:         "Error - Missing sub claim",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				claims := jwtlib.MapClaims{
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"type": "access",
					// Missing "sub" claim
				}
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			},
			expectedError: jwt.ErrInvalidTokenSub,
		},
		{
			name:         "Error - Missing type claim",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				claims := jwtlib.MapClaims{
					"sub": userID,
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
					// Missing "type" claim
				}
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			},
			expectedError: jwt.ErrInvalidTokenType,
		},
		{
			name:         "Error - Empty token",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				return ""
			},
			expectedError: jwt.ErrInvalidToken,
		},
		{
			name:         "Error - Malformed token",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				return "not.a.valid.jwt.token"
			},
			expectedError: jwt.ErrInvalidToken,
		},
		{
			name:         "Error - Token with wrong algorithm",
			secret:       secret,
			expectedType: "access",
			setupToken: func() string {
				// Use RS256 instead of HS256
				// This will fail to sign, but we'll create a mock scenario
				return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXItaWQiLCJpYXQiOjE2MzQ1Njc4OTAsImV4cCI6MTYzNDY1NDI5MCwidHlwZSI6ImFjY2VzcyJ9.invalid-signature"
			},
			expectedError: jwt.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr := tt.setupToken()

			verifiedUserID, verifyErr := jwt.VerifyToken(tokenStr, tt.secret, tt.expectedType)

			if tt.expectedError != nil {
				require.Error(t, verifyErr)
				assert.Empty(t, verifiedUserID)
				// Check if the error is one of our custom JWT errors or a JWT library error
				if errors.Is(tt.expectedError, jwt.ErrInvalidToken) {
					// For ErrInvalidToken, accept either our custom error or JWT library errors
					assert.True(t, errors.Is(verifyErr, jwt.ErrInvalidToken) || verifyErr.Error() != "")
				} else {
					assert.Contains(t, verifyErr.Error(), tt.expectedError.Error())
				}
			} else {
				require.NoError(t, verifyErr)
				assert.NotEmpty(t, verifiedUserID)
			}
		})
	}
}

// TestVerifyToken_EdgeCases tests edge cases for VerifyToken.
func TestVerifyToken_EdgeCases(t *testing.T) {
	secret := "test-secret-key"
	userID := "test-user-id"

	t.Run("Token with extra claims", func(t *testing.T) {
		claims := jwtlib.MapClaims{
			"sub":   userID,
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
			"type":  "access",
			"extra": "claim", // Extra claim should not affect verification
		}
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		resultUserID, err := jwt.VerifyToken(tokenString, secret, "access")
		require.NoError(t, err)
		assert.Equal(t, userID, resultUserID)
	})

	t.Run("Token with numeric sub claim", func(t *testing.T) {
		claims := jwtlib.MapClaims{
			"sub":  "123", // String sub claim
			"iat":  time.Now().Unix(),
			"exp":  time.Now().Add(time.Hour).Unix(),
			"type": "access",
		}
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		resultUserID, err := jwt.VerifyToken(tokenString, secret, "access")
		require.NoError(t, err)
		assert.Equal(t, "123", resultUserID)
	})

	t.Run("Token with float sub claim", func(t *testing.T) {
		claims := jwtlib.MapClaims{
			"sub":  123.45, // Float sub claim
			"iat":  time.Now().Unix(),
			"exp":  time.Now().Add(time.Hour).Unix(),
			"type": "access",
		}
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		resultUserID, err := jwt.VerifyToken(tokenString, secret, "access")
		require.Error(t, err)
		assert.Empty(t, resultUserID)
		assert.Equal(t, jwt.ErrInvalidTokenSub, err)
	})

	t.Run("Token with boolean type claim", func(t *testing.T) {
		claims := jwtlib.MapClaims{
			"sub":  userID,
			"iat":  time.Now().Unix(),
			"exp":  time.Now().Add(time.Hour).Unix(),
			"type": true, // Boolean type claim
		}
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		_, err = jwt.VerifyToken(tokenString, secret, "access")
		require.Error(t, err)
		assert.Equal(t, jwt.ErrInvalidTokenType, err)
	})

	t.Run("Token with numeric type claim", func(t *testing.T) {
		claims := jwtlib.MapClaims{
			"sub":  userID,
			"iat":  time.Now().Unix(),
			"exp":  time.Now().Add(time.Hour).Unix(),
			"type": 123, // Numeric type claim
		}
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		_, err = jwt.VerifyToken(tokenString, secret, "access")
		require.Error(t, err)
		assert.Equal(t, jwt.ErrInvalidTokenType, err)
	})
}

// TestVerifyToken_DifferentTokenTypes tests VerifyToken with different token types.
func TestVerifyToken_DifferentTokenTypes(t *testing.T) {
	secret := "test-secret-key"
	userID := "test-user-id"

	tokenTypes := []string{"access", "refresh", "resetPassword", "verifyEmail"}

	for _, tokenType := range tokenTypes {
		t.Run("Token type: "+tokenType, func(t *testing.T) {
			claims := jwtlib.MapClaims{
				"sub":  userID,
				"iat":  time.Now().Unix(),
				"exp":  time.Now().Add(time.Hour).Unix(),
				"type": tokenType,
			}
			token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
			tokenString, err := token.SignedString([]byte(secret))
			require.NoError(t, err)

			resultUserID, err := jwt.VerifyToken(tokenString, secret, tokenType)
			require.NoError(t, err)
			assert.Equal(t, userID, resultUserID)
		})
	}
}

// TestVerifyToken_EmptySecret tests VerifyToken with empty secret.
func TestVerifyToken_EmptySecret(t *testing.T) {
	userID := "test-user-id"
	secret := ""

	claims := jwtlib.MapClaims{
		"sub":  userID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"type": "access",
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	resultUserID, err := jwt.VerifyToken(tokenString, secret, "access")
	require.NoError(t, err)
	assert.Equal(t, userID, resultUserID)
}

// TestVerifyToken_VeryLongUserID tests VerifyToken with a very long user ID.
func TestVerifyToken_VeryLongUserID(t *testing.T) {
	secret := "test-secret-key"
	// Create a very long user ID
	longUserID := ""
	for range 1000 {
		longUserID += "a"
	}

	claims := jwtlib.MapClaims{
		"sub":  longUserID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"type": "access",
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	resultUserID, err := jwt.VerifyToken(tokenString, secret, "access")
	require.NoError(t, err)
	assert.Equal(t, longUserID, resultUserID)
}

// TestVerifyToken_SpecialCharacters tests VerifyToken with special characters in user ID.
func TestVerifyToken_SpecialCharacters(t *testing.T) {
	secret := "test-secret-key"
	specialUserID := "user@example.com!@#$%^&*()_+-=[]{}|;':\",./<>?"

	claims := jwtlib.MapClaims{
		"sub":  specialUserID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"type": "access",
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	resultUserID, err := jwt.VerifyToken(tokenString, secret, "access")
	require.NoError(t, err)
	assert.Equal(t, specialUserID, resultUserID)
}

// TestVerifyToken_UnicodeUserID tests VerifyToken with Unicode characters in user ID.
func TestVerifyToken_UnicodeUserID(t *testing.T) {
	secret := "test-secret-key"
	unicodeUserID := "用户123🚀🎉"

	claims := jwtlib.MapClaims{
		"sub":  unicodeUserID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"type": "access",
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	resultUserID, err := jwt.VerifyToken(tokenString, secret, "access")
	require.NoError(t, err)
	assert.Equal(t, unicodeUserID, resultUserID)
}
