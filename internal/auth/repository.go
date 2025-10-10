package auth

import (
	"context"
	"errors"
	"fmt"

	"go-rest-api/internal/common/logger"
	"go-rest-api/internal/user"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Repository defines the interface for authentication data access operations.
type Repository interface {
	CreateUser(ctx context.Context, user *user.User) error
	CreateToken(ctx context.Context, token *TokenDB) error
	DeleteToken(ctx context.Context, tokenType string, userID string) error
	DeleteAllTokens(ctx context.Context, userID string) error
	FindTokenByTokenAndUserID(ctx context.Context, tokenStr string, userID string) (*TokenDB, error)
}

type repository struct {
	db  *gorm.DB
	log *logrus.Logger
}

// NewRepository creates a new authentication repository instance.
func NewRepository(db *gorm.DB) Repository {
	return &repository{
		db:  db,
		log: logger.Log,
	}
}

func (r *repository) CreateUser(ctx context.Context, userObj *user.User) error {
	result := r.db.WithContext(ctx).Create(userObj)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return ErrEmailTaken
		}
		r.log.Errorf("Failed to create user: %+v", result.Error)
		return fmt.Errorf("create user: %w", result.Error)
	}

	return nil
}

func (r *repository) CreateToken(ctx context.Context, token *TokenDB) error {
	result := r.db.WithContext(ctx).Create(token)

	if result.Error != nil {
		r.log.Errorf("Failed to save token: %+v", result.Error)
		return fmt.Errorf("create token: %w", result.Error)
	}

	return nil
}

func (r *repository) DeleteToken(ctx context.Context, tokenType string, userID string) error {
	result := r.db.WithContext(ctx).
		Where("type = ? AND user_id = ?", tokenType, userID).
		Delete(&TokenDB{})

	if result.Error != nil {
		r.log.Errorf("Failed to delete token: %+v", result.Error)
		return fmt.Errorf("delete token: %w", result.Error)
	}

	return nil
}

func (r *repository) DeleteAllTokens(ctx context.Context, userID string) error {
	result := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&TokenDB{})

	if result.Error != nil {
		r.log.Errorf("Failed to delete all tokens: %+v", result.Error)
		return fmt.Errorf("delete all tokens: %w", result.Error)
	}

	return nil
}

func (r *repository) FindTokenByTokenAndUserID(ctx context.Context, tokenStr string, userID string) (*TokenDB, error) {
	var token TokenDB

	result := r.db.WithContext(ctx).
		Where("token = ? AND user_id = ?", tokenStr, userID).
		First(&token)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		r.log.Errorf("Failed to find token: %+v", result.Error)
		return nil, fmt.Errorf("find token: %w", result.Error)
	}

	return &token, nil
}
