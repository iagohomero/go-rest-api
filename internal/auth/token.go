package auth

import (
	"time"

	"go-rest-api/internal/user"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	TokenTypeAccess        = "access"
	TokenTypeRefresh       = "refresh"
	TokenTypeResetPassword = "resetPassword"
	TokenTypeVerifyEmail   = "verifyEmail"
)

// TokenDB represents an authentication token stored in the database.
type TokenDB struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Token     string     `gorm:"not null" json:"token"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	Type      string     `gorm:"not null" json:"type"`
	Expires   time.Time  `gorm:"not null" json:"expires"`
	CreatedAt int64      `gorm:"autoCreateTime:milli" json:"created_at"`
	UpdatedAt int64      `gorm:"autoCreateTime:milli;autoUpdateTime:milli" json:"updated_at"`
	User      *user.User `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
}

// BeforeCreate generates a UUID if not already set.
func (t *TokenDB) BeforeCreate(_ *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}

// TableName returns the database table name for TokenDB.
func (TokenDB) TableName() string {
	return "tokens"
}
