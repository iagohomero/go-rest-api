package crypto_test

import (
	"testing"

	"go-rest-api/internal/common/crypto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHashPassword tests the HashPassword function.
func TestHashPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
		checkResult func(*testing.T, string)
	}{
		{
			name:        "Success - Hash simple password",
			password:    "password123",
			expectError: false,
			checkResult: func(t *testing.T, hash string) {
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, "password123", hash)
				assert.True(t, len(hash) > 50) // bcrypt hashes are typically 60 characters
			},
		},
		{
			name:        "Success - Hash complex password",
			password:    "MySecurePassword123!@#",
			expectError: false,
			checkResult: func(t *testing.T, hash string) {
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, "MySecurePassword123!@#", hash)
				assert.True(t, len(hash) > 50)
			},
		},
		{
			name:        "Success - Hash empty password",
			password:    "",
			expectError: false,
			checkResult: func(t *testing.T, hash string) {
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, "", hash)
				assert.True(t, len(hash) > 50)
			},
		},
		{
			name:        "Error - Hash very long password (exceeds bcrypt 72-byte limit)",
			password:    repeatString("a", 1000),
			expectError: true,
			checkResult: nil,
		},
		{
			name:        "Success - Hash password with special characters",
			password:    "!@#$%^&*()_+-=[]{}|;':\",./<>?",
			expectError: false,
			checkResult: func(t *testing.T, hash string) {
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, "!@#$%^&*()_+-=[]{}|;':\",./<>?", hash)
				assert.True(t, len(hash) > 50)
			},
		},
		{
			name:        "Success - Hash password with unicode characters",
			password:    "密码123🚀🎉",
			expectError: false,
			checkResult: func(t *testing.T, hash string) {
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, "密码123🚀🎉", hash)
				assert.True(t, len(hash) > 50)
			},
		},
		{
			name:        "Success - Hash password with spaces",
			password:    "password with spaces",
			expectError: false,
			checkResult: func(t *testing.T, hash string) {
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, "password with spaces", hash)
				assert.True(t, len(hash) > 50)
			},
		},
		{
			name:        "Success - Hash password with newlines",
			password:    "password\nwith\nnewlines",
			expectError: false,
			checkResult: func(t *testing.T, hash string) {
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, "password\nwith\nnewlines", hash)
				assert.True(t, len(hash) > 50)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := crypto.HashPassword(tt.password)

			if tt.expectError {
				require.Error(t, err)
				assert.Empty(t, hash)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, hash)
				if tt.checkResult != nil {
					tt.checkResult(t, hash)
				}
			}
		})
	}
}

// TestCheckPasswordHash tests the CheckPasswordHash function.
func TestCheckPasswordHash(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		hash      string
		expected  bool
		setupHash func(string) string
	}{
		{
			name:     "Success - Correct password and hash",
			password: "password123",
			expected: true,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword(password)
				return hash
			},
		},
		{
			name:     "Success - Wrong password",
			password: "wrongpassword",
			expected: false,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword("correctpassword")
				return hash
			},
		},
		{
			name:     "Success - Empty password with empty hash",
			password: "",
			expected: true,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword("")
				return hash
			},
		},
		{
			name:     "Success - Complex password",
			password: "MySecurePassword123!@#",
			expected: true,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword(password)
				return hash
			},
		},
		{
			name:     "Success - Unicode password",
			password: "密码123🚀🎉",
			expected: true,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword(password)
				return hash
			},
		},
		{
			name:     "Success - Password with special characters",
			password: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
			expected: true,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword(password)
				return hash
			},
		},
		{
			name:     "Success - Password with spaces",
			password: "password with spaces",
			expected: true,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword(password)
				return hash
			},
		},
		{
			name:     "Success - Password with newlines",
			password: "password\nwith\nnewlines",
			expected: true,
			setupHash: func(password string) string {
				hash, _ := crypto.HashPassword(password)
				return hash
			},
		},
		{
			name:     "Error - Invalid hash format",
			password: "password123",
			expected: false,
			setupHash: func(password string) string {
				return "invalid-hash-format"
			},
		},
		{
			name:     "Error - Empty hash",
			password: "password123",
			expected: false,
			setupHash: func(password string) string {
				return ""
			},
		},
		{
			name:     "Error - Malformed hash",
			password: "password123",
			expected: false,
			setupHash: func(password string) string {
				return "$2a$10$invalid.hash.format"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.setupHash(tt.password)
			result := crypto.CheckPasswordHash(tt.password, hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHashPassword_Consistency tests that HashPassword produces different hashes for the same input.
func TestHashPassword_Consistency(t *testing.T) {
	password := "testpassword123"

	// Hash the same password multiple times
	hash1, err1 := crypto.HashPassword(password)
	require.NoError(t, err1)

	hash2, err2 := crypto.HashPassword(password)
	require.NoError(t, err2)

	// Hashes should be different due to salt
	assert.NotEqual(t, hash1, hash2)

	// But both should verify correctly
	assert.True(t, crypto.CheckPasswordHash(password, hash1))
	assert.True(t, crypto.CheckPasswordHash(password, hash2))
}

// TestCheckPasswordHash_EdgeCases tests edge cases for CheckPasswordHash.
func TestCheckPasswordHash_EdgeCases(t *testing.T) {
	t.Run("Very long password", func(t *testing.T) {
		longPassword := repeatString("a", 10000)
		_, err := crypto.HashPassword(longPassword)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password length exceeds 72 bytes")
	})

	t.Run("Password with null bytes", func(t *testing.T) {
		passwordWithNulls := "pass\x00word"
		hash, err := crypto.HashPassword(passwordWithNulls)
		require.NoError(t, err)

		assert.True(t, crypto.CheckPasswordHash(passwordWithNulls, hash))
	})

	t.Run("Password with control characters", func(t *testing.T) {
		passwordWithControls := "pass\tword\n\r"
		hash, err := crypto.HashPassword(passwordWithControls)
		require.NoError(t, err)

		assert.True(t, crypto.CheckPasswordHash(passwordWithControls, hash))
	})
}

// TestHashPassword_Performance tests that HashPassword completes in reasonable time.
func TestHashPassword_Performance(t *testing.T) {
	password := "testpassword123"

	// This should complete quickly (under 1 second)
	hash, err := crypto.HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
}

// TestCheckPasswordHash_Performance tests that CheckPasswordHash completes in reasonable time.
func TestCheckPasswordHash_Performance(t *testing.T) {
	password := "testpassword123"
	hash, err := crypto.HashPassword(password)
	require.NoError(t, err)

	// This should complete quickly (under 1 second)
	result := crypto.CheckPasswordHash(password, hash)
	assert.True(t, result)
}

// TestHashPassword_Unicode tests HashPassword with various Unicode inputs.
func TestHashPassword_Unicode(t *testing.T) {
	unicodePasswords := []string{
		"Hello 世界",
		"مرحبا بالعالم",
		"Привет мир",
		"🌍🌎🌏",
		"αβγδε",
		"🚀🎉💯",
	}

	for _, password := range unicodePasswords {
		t.Run("Unicode password: "+password, func(t *testing.T) {
			hash, err := crypto.HashPassword(password)
			require.NoError(t, err)
			assert.NotEmpty(t, hash)

			// Verify the hash works
			assert.True(t, crypto.CheckPasswordHash(password, hash))
			assert.False(t, crypto.CheckPasswordHash(password+"x", hash))
		})
	}
}

// TestHashPassword_Security tests that hashed passwords are secure.
func TestHashPassword_Security(t *testing.T) {
	password := "secretpassword"
	hash, err := crypto.HashPassword(password)
	require.NoError(t, err)

	// Hash should not contain the original password
	assert.NotContains(t, hash, password)

	// Hash should be significantly longer than the original password
	assert.True(t, len(hash) > len(password)*2)

	// Hash should start with bcrypt identifier
	assert.True(t, len(hash) >= 60) // bcrypt hashes are 60 characters
}

// TestCheckPasswordHash_CaseSensitivity tests that password checking is case sensitive.
func TestCheckPasswordHash_CaseSensitivity(t *testing.T) {
	password := "Password123"
	hash, err := crypto.HashPassword(password)
	require.NoError(t, err)

	// Exact match should work
	assert.True(t, crypto.CheckPasswordHash(password, hash))

	// Case variations should not work
	assert.False(t, crypto.CheckPasswordHash("password123", hash))
	assert.False(t, crypto.CheckPasswordHash("PASSWORD123", hash))
	assert.False(t, crypto.CheckPasswordHash("pASSWORD123", hash))
}

// Helper function to repeat a string
func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
