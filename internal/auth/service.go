package auth

import (
	"context"
	"time"

	"go-rest-api/internal/common/crypto"
	"go-rest-api/internal/common/jwt"
	"go-rest-api/internal/common/logger"
	"go-rest-api/internal/config"
	"go-rest-api/internal/rbac"
	"go-rest-api/internal/user"

	"github.com/go-playground/validator/v10"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Service defines the interface for authentication business logic operations.
type Service interface {
	Register(ctx context.Context, req *RegisterRequest) (*user.User, error)
	Login(ctx context.Context, req *LoginRequest) (*user.User, error)
	Logout(ctx context.Context, req *LogoutRequest) error
	RefreshAuth(ctx context.Context, req *RefreshTokenRequest) (*Tokens, error)
	ResetPassword(ctx context.Context, query *ResetPasswordRequest, req *user.UpdateUserPasswordRequest) error
	VerifyEmail(ctx context.Context, query *ResetPasswordRequest) error
	GenerateToken(userID string, expires time.Time, tokenType string) (string, error)
	SaveToken(ctx context.Context, token, userID, tokenType string, expires time.Time) error
	DeleteToken(ctx context.Context, tokenType string, userID string) error
	DeleteAllToken(ctx context.Context, userID string) error
	GetTokenByUserID(ctx context.Context, tokenStr string) (*TokenDB, error)
	GenerateAuthTokens(ctx context.Context, user *user.User) (*Tokens, error)
	GenerateResetPasswordToken(ctx context.Context, req *ForgotPasswordRequest) (string, error)
	GenerateVerifyEmailToken(ctx context.Context, user *user.User) (*string, error)
}

type service struct {
	log         *logger.Logger
	repository  Repository
	validate    *validator.Validate
	userService user.Service
	cfg         *config.Config
}

// NewService creates a new authentication service instance.
func NewService(
	repository Repository,
	validate *validator.Validate,
	userService user.Service,
	cfg *config.Config,
) Service {
	return &service{
		log:         logger.New(),
		repository:  repository,
		validate:    validate,
		userService: userService,
		cfg:         cfg,
	}
}

func (s *service) Register(ctx context.Context, req *RegisterRequest) (*user.User, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, err
	}

	hashedPassword, err := crypto.HashPassword(req.Password)
	if err != nil {
		s.log.Errorf("Failed to hash password: %+v", err)
		return nil, WrapError(err, "hash password failed")
	}

	newUser := &user.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: hashedPassword,
		Role:     rbac.RoleUser,
	}

	if createErr := s.repository.CreateUser(ctx, newUser); createErr != nil {
		return nil, createErr
	}

	return newUser, nil
}

func (s *service) Login(ctx context.Context, req *LoginRequest) (*user.User, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, err
	}

	foundUser, err := s.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !crypto.CheckPasswordHash(req.Password, foundUser.Password) {
		return nil, ErrInvalidCredentials
	}

	return foundUser, nil
}

func (s *service) Logout(ctx context.Context, req *LogoutRequest) error {
	if err := s.validate.Struct(req); err != nil {
		return err
	}

	token, err := s.GetTokenByUserID(ctx, req.RefreshToken)
	if err != nil {
		return ErrTokenNotFound
	}

	return s.DeleteToken(ctx, TokenTypeRefresh, token.UserID.String())
}

func (s *service) RefreshAuth(ctx context.Context, req *RefreshTokenRequest) (*Tokens, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, err
	}

	token, err := s.GetTokenByUserID(ctx, req.RefreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	user, err := s.userService.GetUserByID(ctx, token.UserID.String())
	if err != nil {
		return nil, ErrInvalidToken
	}

	newTokens, err := s.GenerateAuthTokens(ctx, user)
	if err != nil {
		return nil, WrapError(err, "failed to generate auth tokens")
	}

	return newTokens, nil
}

func (s *service) ResetPassword(
	ctx context.Context,
	query *ResetPasswordRequest,
	req *user.UpdateUserPasswordRequest,
) error {
	if err := s.validate.Struct(query); err != nil {
		return err
	}

	userID, err := jwt.VerifyToken(query.Token, s.cfg.JWT.Secret, TokenTypeResetPassword)
	if err != nil {
		return ErrInvalidToken
	}

	userData, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return ErrPasswordResetFailed
	}

	if errUpdate := s.userService.UpdatePassOrVerify(ctx, &user.UpdateUserPasswordRequest{
		Password:      req.Password,
		VerifiedEmail: req.VerifiedEmail,
	}, userData.ID.String()); errUpdate != nil {
		return errUpdate
	}

	if errToken := s.DeleteToken(ctx, TokenTypeResetPassword, userData.ID.String()); errToken != nil {
		return errToken
	}

	return nil
}

func (s *service) VerifyEmail(ctx context.Context, query *ResetPasswordRequest) error {
	if err := s.validate.Struct(query); err != nil {
		return err
	}

	userID, err := jwt.VerifyToken(query.Token, s.cfg.JWT.Secret, TokenTypeVerifyEmail)
	if err != nil {
		return ErrInvalidToken
	}

	userData, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return ErrVerifyEmailFailed
	}

	if errToken := s.DeleteToken(ctx, TokenTypeVerifyEmail, userData.ID.String()); errToken != nil {
		return errToken
	}

	updateBody := &user.UpdateUserPasswordRequest{
		VerifiedEmail: true,
	}

	if errUpdate := s.userService.UpdatePassOrVerify(ctx, updateBody, userData.ID.String()); errUpdate != nil {
		return errUpdate
	}

	return nil
}

func (s *service) GenerateToken(userID string, expires time.Time, tokenType string) (string, error) {
	claims := jwtlib.MapClaims{
		"sub":  userID,
		"iat":  time.Now().Unix(),
		"exp":  expires.Unix(),
		"type": tokenType,
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(s.cfg.JWT.Secret))
	if err != nil {
		return "", WrapError(err, "failed to sign token")
	}

	return signedToken, nil
}

func (s *service) SaveToken(ctx context.Context, token, userID, tokenType string, expires time.Time) error {
	if err := s.DeleteToken(ctx, tokenType, userID); err != nil {
		return err
	}

	tokenDoc := &TokenDB{
		Token:   token,
		UserID:  uuid.MustParse(userID),
		Type:    tokenType,
		Expires: expires,
	}

	return s.repository.CreateToken(ctx, tokenDoc)
}

func (s *service) DeleteToken(ctx context.Context, tokenType string, userID string) error {
	return s.repository.DeleteToken(ctx, tokenType, userID)
}

func (s *service) DeleteAllToken(ctx context.Context, userID string) error {
	return s.repository.DeleteAllTokens(ctx, userID)
}

func (s *service) GetTokenByUserID(ctx context.Context, tokenStr string) (*TokenDB, error) {
	userID, err := jwt.VerifyToken(tokenStr, s.cfg.JWT.Secret, TokenTypeRefresh)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return s.repository.FindTokenByTokenAndUserID(ctx, tokenStr, userID)
}

func (s *service) GenerateAuthTokens(ctx context.Context, userObj *user.User) (*Tokens, error) {
	accessTokenExpires := time.Now().UTC().Add(s.cfg.JWT.AccessTokenDuration())
	accessToken, err := s.GenerateToken(userObj.ID.String(), accessTokenExpires, TokenTypeAccess)
	if err != nil {
		s.log.Errorf("Failed to generate access token: %+v", err)
		return nil, ErrTokenGenerationFailed
	}

	refreshTokenExpires := time.Now().UTC().Add(s.cfg.JWT.RefreshTokenDuration())
	refreshToken, err := s.GenerateToken(userObj.ID.String(), refreshTokenExpires, TokenTypeRefresh)
	if err != nil {
		s.log.Errorf("Failed to generate refresh token: %+v", err)
		return nil, ErrTokenGenerationFailed
	}

	if err = s.SaveToken(ctx, refreshToken, userObj.ID.String(), TokenTypeRefresh, refreshTokenExpires); err != nil {
		return nil, WrapError(err, "failed to save refresh token")
	}

	return &Tokens{
		Access: TokenExpires{
			Token:   accessToken,
			Expires: accessTokenExpires,
		},
		Refresh: TokenExpires{
			Token:   refreshToken,
			Expires: refreshTokenExpires,
		},
	}, nil
}

func (s *service) GenerateResetPasswordToken(ctx context.Context, req *ForgotPasswordRequest) (string, error) {
	if err := s.validate.Struct(req); err != nil {
		return "", err
	}

	foundUser, err := s.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return "", err
	}

	expires := time.Now().UTC().Add(s.cfg.JWT.ResetPasswordTokenDuration())
	resetPasswordToken, err := s.GenerateToken(foundUser.ID.String(), expires, TokenTypeResetPassword)
	if err != nil {
		s.log.Errorf("Failed to generate reset password token: %+v", err)
		return "", ErrTokenGenerationFailed
	}

	if err = s.SaveToken(ctx, resetPasswordToken, foundUser.ID.String(), TokenTypeResetPassword, expires); err != nil {
		return "", WrapError(err, "failed to save reset password token")
	}

	return resetPasswordToken, nil
}

func (s *service) GenerateVerifyEmailToken(ctx context.Context, userObj *user.User) (*string, error) {
	expires := time.Now().UTC().Add(s.cfg.JWT.VerifyEmailTokenDuration())
	verifyEmailToken, err := s.GenerateToken(userObj.ID.String(), expires, TokenTypeVerifyEmail)
	if err != nil {
		s.log.Errorf("Failed to generate verify email token: %+v", err)
		return nil, ErrTokenGenerationFailed
	}

	if err = s.SaveToken(ctx, verifyEmailToken, userObj.ID.String(), TokenTypeVerifyEmail, expires); err != nil {
		return nil, WrapError(err, "failed to save verify email token")
	}

	return &verifyEmailToken, nil
}
