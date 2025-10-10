package user

import (
	"context"
	"errors"

	"go-rest-api/internal/common/crypto"
	pkgErrors "go-rest-api/internal/common/errors"
	"go-rest-api/internal/common/logger"

	"github.com/go-playground/validator/v10"
)

// Service defines the interface for user business logic operations.
type Service interface {
	GetUsers(ctx context.Context, params *QueryUserRequest) ([]User, int64, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error)
	UpdatePassOrVerify(ctx context.Context, req *UpdateUserPasswordRequest, id string) error
	UpdateUser(ctx context.Context, req *UpdateUserRequest, id string) (*User, error)
	DeleteUser(ctx context.Context, id string) error
	CreateGoogleUser(ctx context.Context, req *CreateGoogleUserRequest) (*User, error)
}

type service struct {
	log        *logger.Logger
	repository Repository
	validate   *validator.Validate
}

// NewService creates a new user service instance.
func NewService(repository Repository, validate *validator.Validate) Service {
	return &service{
		log:        logger.New(),
		repository: repository,
		validate:   validate,
	}
}

// GetUsers retrieves a paginated list of users with optional search filter.
func (s *service) GetUsers(ctx context.Context, params *QueryUserRequest) ([]User, int64, error) {
	if err := s.validate.Struct(params); err != nil {
		return nil, 0, err
	}

	offset := (params.Page - 1) * params.Limit

	totalResults, err := s.repository.Count(ctx, params.Search)
	if err != nil {
		return nil, 0, err
	}

	users, err := s.repository.FindAll(ctx, params.Limit, offset, params.Search)
	if err != nil {
		return nil, 0, err
	}

	return users, totalResults, nil
}

// GetUserByID retrieves a user by their ID.
func (s *service) GetUserByID(ctx context.Context, id string) (*User, error) {
	return s.repository.FindByID(ctx, id)
}

// GetUserByEmail retrieves a user by their email address.
func (s *service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.repository.FindByEmail(ctx, email)
}

// CreateUser creates a new user with the provided information.
func (s *service) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, err
	}

	hashedPassword, err := crypto.HashPassword(req.Password)
	if err != nil {
		s.log.Errorf("Failed to hash password: %+v", err)
		return nil, WrapError(err, "hash password failed")
	}

	user := &User{
		Name:     req.Name,
		Email:    req.Email,
		Password: hashedPassword,
		Role:     req.Role,
	}

	if createErr := s.repository.Create(ctx, user); createErr != nil {
		return nil, createErr
	}

	return user, nil
}

// UpdateUser updates a user's information.
func (s *service) UpdateUser(ctx context.Context, req *UpdateUserRequest, id string) (*User, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, err
	}

	if req.Email == "" && req.Name == "" && req.Password == "" {
		return nil, pkgErrors.ErrBadRequest
	}

	if req.Password != "" {
		hashedPassword, err := crypto.HashPassword(req.Password)
		if err != nil {
			return nil, WrapError(err, "hash password failed")
		}
		req.Password = hashedPassword
	}

	updateBody := &User{
		Name:     req.Name,
		Password: req.Password,
		Email:    req.Email,
	}

	rowsAffected, err := s.repository.Update(ctx, id, updateBody)
	if err != nil {
		return nil, err
	}

	if rowsAffected == 0 {
		return nil, ErrUserNotFound
	}

	user, err := s.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// UpdatePassOrVerify updates a user's password or email verification status.
func (s *service) UpdatePassOrVerify(ctx context.Context, req *UpdateUserPasswordRequest, id string) error {
	if err := s.validate.Struct(req); err != nil {
		return err
	}

	if req.Password == "" && !req.VerifiedEmail {
		return pkgErrors.ErrBadRequest
	}

	if req.Password != "" {
		hashedPassword, err := crypto.HashPassword(req.Password)
		if err != nil {
			return WrapError(err, "hash password failed")
		}
		req.Password = hashedPassword
	}

	updateBody := &User{
		Password:      req.Password,
		VerifiedEmail: req.VerifiedEmail,
	}

	rowsAffected, err := s.repository.Update(ctx, id, updateBody)
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// DeleteUser deletes a user by their ID.
func (s *service) DeleteUser(ctx context.Context, id string) error {
	rowsAffected, err := s.repository.Delete(ctx, id)
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// CreateGoogleUser creates a new user from Google OAuth data, or updates existing user's verification status.
func (s *service) CreateGoogleUser(ctx context.Context, req *CreateGoogleUserRequest) (*User, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, err
	}

	userFromDB, err := s.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			user := &User{
				Name:          req.Name,
				Email:         req.Email,
				VerifiedEmail: req.VerifiedEmail,
			}

			if createErr := s.repository.Create(ctx, user); createErr != nil {
				return nil, createErr
			}

			return user, nil
		}

		return nil, err
	}

	userFromDB.VerifiedEmail = req.VerifiedEmail
	if updateErr := s.repository.Save(ctx, userFromDB); updateErr != nil {
		return nil, updateErr
	}

	return userFromDB, nil
}
