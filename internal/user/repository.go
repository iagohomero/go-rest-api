package user

import (
	"context"
	"errors"
	"fmt"

	"go-rest-api/internal/common/logger"

	"gorm.io/gorm"
)

// Repository defines the interface for user data access operations.
type Repository interface {
	FindAll(ctx context.Context, limit, offset int, search string) ([]User, error)
	Count(ctx context.Context, search string) (int64, error)
	FindByID(ctx context.Context, id string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	Create(ctx context.Context, user *User) error
	Update(ctx context.Context, id string, user *User) (int64, error)
	UpdateFields(ctx context.Context, id string, updates map[string]interface{}) (int64, error)
	Delete(ctx context.Context, id string) (int64, error)
	Save(ctx context.Context, user *User) error
}

type repository struct {
	db  *gorm.DB
	log *logger.Logger
}

// NewRepository creates a new user repository instance.
func NewRepository(db *gorm.DB) Repository {
	return &repository{
		db:  db,
		log: logger.New(),
	}
}

func (r *repository) FindAll(ctx context.Context, limit, offset int, search string) ([]User, error) {
	var users []User

	query := r.db.WithContext(ctx).Order("created_at asc")

	if search != "" {
		query = query.Where("name ILIKE ? OR email ILIKE ? OR role ILIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	result := query.Limit(limit).Offset(offset).Find(&users)
	if result.Error != nil {
		r.log.Errorf("Failed to find users: %+v", result.Error)
		return nil, fmt.Errorf("find users: %w", result.Error)
	}

	return users, nil
}

func (r *repository) Count(ctx context.Context, search string) (int64, error) {
	var count int64

	query := r.db.WithContext(ctx).Model(&User{})

	if search != "" {
		query = query.Where("name ILIKE ? OR email ILIKE ? OR role ILIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	result := query.Count(&count)
	if result.Error != nil {
		r.log.Errorf("Failed to count users: %+v", result.Error)
		return 0, fmt.Errorf("count users: %w", result.Error)
	}

	return count, nil
}

func (r *repository) FindByID(ctx context.Context, id string) (*User, error) {
	var user User

	result := r.db.WithContext(ctx).First(&user, "id = ?", id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		r.log.Errorf("Failed to find user by ID: %+v", result.Error)
		return nil, fmt.Errorf("find user by id: %w", result.Error)
	}

	return &user, nil
}

func (r *repository) FindByEmail(ctx context.Context, email string) (*User, error) {
	var user User

	result := r.db.WithContext(ctx).Where("email = ?", email).First(&user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		r.log.Errorf("Failed to find user by email: %+v", result.Error)
		return nil, fmt.Errorf("find user by email: %w", result.Error)
	}

	return &user, nil
}

func (r *repository) Create(ctx context.Context, user *User) error {
	result := r.db.WithContext(ctx).Create(user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return ErrEmailTaken
		}
		r.log.Errorf("Failed to create user: %+v", result.Error)
		return fmt.Errorf("create user: %w", result.Error)
	}

	return nil
}

func (r *repository) Update(ctx context.Context, id string, user *User) (int64, error) {
	result := r.db.WithContext(ctx).Where("id = ?", id).Updates(user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return 0, ErrEmailTaken
		}
		r.log.Errorf("Failed to update user: %+v", result.Error)
		return 0, fmt.Errorf("update user: %w", result.Error)
	}

	return result.RowsAffected, nil
}

func (r *repository) UpdateFields(ctx context.Context, id string, updates map[string]interface{}) (int64, error) {
	result := r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).Updates(updates)

	if result.Error != nil {
		r.log.Errorf("Failed to update user fields: %+v", result.Error)
		return 0, fmt.Errorf("update user fields: %w", result.Error)
	}

	return result.RowsAffected, nil
}

func (r *repository) Delete(ctx context.Context, id string) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&User{}, "id = ?", id)

	if result.Error != nil {
		r.log.Errorf("Failed to delete user: %+v", result.Error)
		return 0, fmt.Errorf("delete user: %w", result.Error)
	}

	return result.RowsAffected, nil
}

func (r *repository) Save(ctx context.Context, user *User) error {
	result := r.db.WithContext(ctx).Save(user)

	if result.Error != nil {
		r.log.Errorf("Failed to save user: %+v", result.Error)
		return fmt.Errorf("save user: %w", result.Error)
	}

	return nil
}
