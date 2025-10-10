package user

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system.
type User struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name          string    `gorm:"not null"                                       json:"name"`
	Email         string    `gorm:"uniqueIndex;not null"                           json:"email"`
	Password      string    `gorm:"not null"                                       json:"-"`
	Role          string    `gorm:"default:user;not null"                          json:"role"`
	VerifiedEmail bool      `gorm:"default:false;not null"                         json:"verified_email"`
	CreatedAt     int64     `gorm:"autoCreateTime:milli"                           json:"created_at"`
	UpdatedAt     int64     `gorm:"autoCreateTime:milli;autoUpdateTime:milli"      json:"updated_at"`
}

// BeforeCreate generates a UUID if not already set.
func (u *User) BeforeCreate(_ *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// TableName returns the database table name for User.
func (u *User) TableName() string {
	return "users"
}
