package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"go-rest-api/internal/common/errors"
	"go-rest-api/internal/common/httputil"
	"go-rest-api/internal/config"
	"go-rest-api/internal/email"
	"go-rest-api/internal/user"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Handler handles authentication HTTP requests.
type Handler struct {
	authService  Service
	userService  user.Service
	emailService email.Service
	cfg          *config.Config
}

// NewHandler creates a new authentication handler.
func NewHandler(
	authService Service,
	userService user.Service,
	emailService email.Service,
	cfg *config.Config,
) *Handler {
	return &Handler{
		authService:  authService,
		userService:  userService,
		emailService: emailService,
		cfg:          cfg,
	}
}

// @Tags         Auth
// @Summary      Register as user
// @Accept       json
// @Produce      json
// @Param        request  body  RegisterRequest  true  "Request body"
// @Router       /auth/register [post]
// @Success      201  {object}  RegisterResponse
// @Failure      409  {object}  errors.ErrorResponse  "Email already taken"
func (h *Handler) Register(c *fiber.Ctx) error {
	req := new(RegisterRequest)

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	user, err := h.authService.Register(c.Context(), req)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	tokens, err := h.authService.GenerateAuthTokens(c.Context(), user)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusCreated).
		JSON(RegisterResponse{
			Code:    fiber.StatusCreated,
			Status:  "success",
			Message: "Register successfully",
			User:    *user,
			Tokens:  *tokens,
		})
}

// @Tags         Auth
// @Summary      Login
// @Accept       json
// @Produce      json
// @Param        request  body  LoginRequest  true  "Request body"
// @Router       /auth/login [post]
// @Success      200  {object}  LoginResponse
// @Failure      401  {object}  errors.ErrorResponse  "Invalid email or password"
func (h *Handler) Login(c *fiber.Ctx) error {
	req := new(LoginRequest)

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	user, err := h.authService.Login(c.Context(), req)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	tokens, err := h.authService.GenerateAuthTokens(c.Context(), user)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(LoginResponse{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Login successfully",
			User:    *user,
			Tokens:  *tokens,
		})
}

// @Tags         Auth
// @Summary      Logout
// @Accept       json
// @Produce      json
// @Param        request  body  LogoutRequest  true  "Request body"
// @Router       /auth/logout [post]
// @Success      200  {object}  httputil.Common
// @Failure      404  {object}  errors.ErrorResponse  "Not found"
func (h *Handler) Logout(c *fiber.Ctx) error {
	req := new(LogoutRequest)

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	if err := h.authService.Logout(c.Context(), req); err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(httputil.Common{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Logout successfully",
		})
}

// @Tags         Auth
// @Summary      Refresh auth tokens
// @Accept       json
// @Produce      json
// @Param        request  body  RefreshTokenRequest  true  "Request body"
// @Router       /auth/refresh-tokens [post]
// @Success      200  {object}  RefreshTokenResponse
// @Failure      401  {object}  errors.ErrorResponse  "Unauthorized"
func (h *Handler) RefreshTokens(c *fiber.Ctx) error {
	req := new(RefreshTokenRequest)

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	tokens, err := h.authService.RefreshAuth(c.Context(), req)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(RefreshTokenResponse{
			Code:   fiber.StatusOK,
			Status: "success",
			Tokens: *tokens,
		})
}

// @Tags         Auth
// @Summary      Forgot password
// @Description  An email will be sent to reset password.
// @Accept       json
// @Produce      json
// @Param        request  body  ForgotPasswordRequest  true  "Request body"
// @Router       /auth/forgot-password [post]
// @Success      200  {object}  httputil.Common
// @Failure      404  {object}  errors.ErrorResponse  "Not found"
func (h *Handler) ForgotPassword(c *fiber.Ctx) error {
	req := new(ForgotPasswordRequest)

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	resetPasswordToken, err := h.authService.GenerateResetPasswordToken(c.Context(), req)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	if errEmail := h.emailService.SendResetPasswordEmail(req.Email, resetPasswordToken); errEmail != nil {
		return errors.HandleHTTPError(c, errEmail)
	}

	return c.Status(fiber.StatusOK).
		JSON(httputil.Common{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "A password reset link has been sent to your email address.",
		})
}

// @Tags         Auth
// @Summary      Reset password
// @Accept       json
// @Produce      json
// @Param        token   query  string  true  "The reset password token"
// @Param        request  body  user.UpdateUserPasswordRequest  true  "Request body"
// @Router       /auth/reset-password [post]
// @Success      200  {object}  httputil.Common
// @Failure      401  {object}  errors.ErrorResponse  "Password reset failed"
func (h *Handler) ResetPassword(c *fiber.Ctx) error {
	req := new(user.UpdateUserPasswordRequest)
	query := &ResetPasswordRequest{
		Token: c.Query("token"),
	}

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	if err := h.authService.ResetPassword(c.Context(), query, req); err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(httputil.Common{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Update password successfully",
		})
}

// @Tags         Auth
// @Summary      Send verification email
// @Description  An email will be sent to verify email.
// @Security BearerAuth
// @Produce      json
// @Router       /auth/send-verification-email [post]
// @Success      200  {object}  httputil.Common
// @Failure      401  {object}  errors.ErrorResponse  "Unauthorized"
func (h *Handler) SendVerificationEmail(c *fiber.Ctx) error {
	userObj, ok := c.Locals("user").(*user.User)
	if !ok {
		return errors.HandleHTTPError(c, errors.ErrUnauthorized)
	}

	verifyEmailToken, err := h.authService.GenerateVerifyEmailToken(c.Context(), userObj)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	if errEmail := h.emailService.SendVerificationEmail(userObj.Email, *verifyEmailToken); errEmail != nil {
		return errors.HandleHTTPError(c, errEmail)
	}

	return c.Status(fiber.StatusOK).
		JSON(httputil.Common{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Please check your email for a link to verify your account",
		})
}

// @Tags         Auth
// @Summary      Verify email
// @Produce      json
// @Param        token   query  string  true  "The verify email token"
// @Router       /auth/verify-email [post]
// @Success      200  {object}  httputil.Common
// @Failure      401  {object}  errors.ErrorResponse  "Verify email failed"
func (h *Handler) VerifyEmail(c *fiber.Ctx) error {
	query := &ResetPasswordRequest{
		Token: c.Query("token"),
	}

	if err := h.authService.VerifyEmail(c.Context(), query); err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(httputil.Common{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Verify email successfully",
		})
}

// @Tags         Auth
// @Summary      Login with google
// @Description  This route initiates the Google OAuth2 login flow. Please try this in your browser.
// @Router       /auth/google [get]
// @Success      200  {object}  LoginResponse
func (h *Handler) GoogleLogin(c *fiber.Ctx) error {
	// Generate a random state
	state := uuid.New().String()

	c.Cookie(&fiber.Cookie{
		Name:   "oauth_state",
		Value:  state,
		MaxAge: 30,
	})

	googleConfig := config.NewGoogleOAuthConfig(h.cfg)
	url := googleConfig.AuthCodeURL(state)

	return c.Status(fiber.StatusSeeOther).Redirect(url)
}

// GoogleCallback handles the OAuth2 callback from Google.
func (h *Handler) GoogleCallback(c *fiber.Ctx) error {
	state := c.Query("state")
	storedState := c.Cookies("oauth_state")

	if state != storedState {
		return errors.HandleHTTPError(c, errors.ErrUnauthorized)
	}

	code := c.Query("code")
	googleConfig := config.NewGoogleOAuthConfig(h.cfg)

	token, err := googleConfig.Exchange(context.Background(), code)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	req, err := http.NewRequestWithContext(
		c.Context(), http.MethodGet,
		"https://www.googleapis.com/oauth2/v2/userinfo?access_token="+token.AccessToken,
		nil,
	)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}
	defer resp.Body.Close()

	userData, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	googleUser := new(user.CreateGoogleUserRequest)
	if errJSON := json.Unmarshal(userData, googleUser); errJSON != nil {
		return errors.HandleHTTPError(c, errJSON)
	}

	createdUser, err := h.userService.CreateGoogleUser(c.Context(), googleUser)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	tokens, err := h.authService.GenerateAuthTokens(c.Context(), createdUser)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(LoginResponse{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Login successfully",
			User:    *createdUser,
			Tokens:  *tokens,
		})

	// Alternative: redirect to frontend OAuth success page with tokens in URL
	// googleLoginURL := fmt.Sprintf("http://your-app/google/success?access_token=%s&refresh_token=%s",
	// 	tokens.Access.Token, tokens.Refresh.Token)
	// return c.Status(fiber.StatusSeeOther).Redirect(googleLoginURL)
}
