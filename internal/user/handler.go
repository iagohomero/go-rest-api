package user

import (
	"math"

	"go-rest-api/internal/common/errors"
	"go-rest-api/internal/common/httputil"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const (
	// DefaultPageLimit is the default number of items per page.
	DefaultPageLimit = 10
)

// Handler handles user HTTP requests.
type Handler struct {
	service Service
}

// NewHandler creates a new user handler.
func NewHandler(service Service) *Handler {
	return &Handler{
		service: service,
	}
}

// GetUsers retrieves all users.
//
// @Tags         Users
// @Summary      Get all users
// @Description  Only admins can retrieve all users.
// @Security BearerAuth
// @Produce      json
// @Param        page     query     int     false   "Page number"  default(1)
// @Param        limit    query     int     false   "Maximum number of users"    default(10)
// @Param        search   query     string  false  "Search by name or email or role"
// @Router       /users [get]
// @Success      200  {object}  UsersListResponse
// @Failure      401  {object}  errors.ErrorResponse  "Unauthorized".
// @Failure      403  {object}  errors.ErrorResponse  "Forbidden".
func (h *Handler) GetUsers(c *fiber.Ctx) error {
	query := &QueryUserRequest{
		Page:   c.QueryInt("page", 1),
		Limit:  c.QueryInt("limit", DefaultPageLimit),
		Search: c.Query("search", ""),
	}

	users, totalResults, err := h.service.GetUsers(c.Context(), query)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(httputil.SuccessWithPaginate[User]{
			Code:         fiber.StatusOK,
			Status:       "success",
			Message:      "Get all users successfully",
			Results:      users,
			Page:         query.Page,
			Limit:        query.Limit,
			TotalPages:   int64(math.Ceil(float64(totalResults) / float64(query.Limit))),
			TotalResults: totalResults,
		})
}

// GetUserByID retrieves a user by ID.
//
// @Tags         Users
// @Summary      Get a user
// @Description  Logged in users can fetch only their own user information. Only admins can fetch other users.
// @Security BearerAuth
// @Produce      json
// @Param        id  path  string  true  "User id"
// @Router       /users/{id} [get]
// @Success      200  {object}  Response
// @Failure      401  {object}  errors.ErrorResponse  "Unauthorized".
// @Failure      403  {object}  errors.ErrorResponse  "Forbidden".
// @Failure      404  {object}  errors.ErrorResponse  "Not found".
func (h *Handler) GetUserByID(c *fiber.Ctx) error {
	userID := c.Params("userId")

	if _, err := uuid.Parse(userID); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	user, err := h.service.GetUserByID(c.Context(), userID)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(Response{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Get user successfully",
			User:    *user,
		})
}

// CreateUser creates a new user.
//
// @Tags         Users
// @Summary      Create a user
// @Description  Only admins can create other users.
// @Security BearerAuth
// @Produce      json
// @Param        request  body  CreateUserRequest  true  "Request body"
// @Router       /users [post]
// @Success      201  {object}  Response
// @Failure      401  {object}  errors.ErrorResponse  "Unauthorized".
// @Failure      403  {object}  errors.ErrorResponse  "Forbidden".
// @Failure      409  {object}  errors.ErrorResponse  "Email already taken".
func (h *Handler) CreateUser(c *fiber.Ctx) error {
	req := new(CreateUserRequest)

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	user, err := h.service.CreateUser(c.Context(), req)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusCreated).
		JSON(Response{
			Code:    fiber.StatusCreated,
			Status:  "success",
			Message: "Create user successfully",
			User:    *user,
		})
}

// UpdateUser updates a user.
//
// @Tags         Users
// @Summary      Update a user
// @Description  Logged in users can only update their own information. Only admins can update other users.
// @Security BearerAuth
// @Produce      json
// @Param        id  path  string  true  "User id"
// @Param        request  body  UpdateUserRequest  true  "Request body"
// @Router       /users/{id} [patch]
// @Success      200  {object}  Response
// @Failure      401  {object}  errors.ErrorResponse  "Unauthorized".
// @Failure      403  {object}  errors.ErrorResponse  "Forbidden".
// @Failure      404  {object}  errors.ErrorResponse  "Not found".
// @Failure      409  {object}  errors.ErrorResponse  "Email already taken".
func (h *Handler) UpdateUser(c *fiber.Ctx) error {
	req := new(UpdateUserRequest)
	userID := c.Params("userId")

	if _, err := uuid.Parse(userID); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	if err := c.BodyParser(req); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	user, err := h.service.UpdateUser(c.Context(), req, userID)
	if err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(Response{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Update user successfully",
			User:    *user,
		})
}

// DeleteUser deletes a user.
//
// @Tags         Users
// @Summary      Delete a user
// @Description  Logged in users can delete only themselves. Only admins can delete other users.
// @Security BearerAuth
// @Produce      json
// @Param        id  path  string  true  "User id"
// @Router       /users/{id} [delete]
// @Success      200  {object}  httputil.Common
// @Failure      401  {object}  errors.ErrorResponse  "Unauthorized".
// @Failure      403  {object}  errors.ErrorResponse  "Forbidden".
// @Failure      404  {object}  errors.ErrorResponse  "Not found".
func (h *Handler) DeleteUser(c *fiber.Ctx) error {
	userID := c.Params("userId")

	if _, err := uuid.Parse(userID); err != nil {
		return errors.HandleHTTPError(c, errors.ErrBadRequest)
	}

	if err := h.service.DeleteUser(c.Context(), userID); err != nil {
		return errors.HandleHTTPError(c, err)
	}

	return c.Status(fiber.StatusOK).
		JSON(httputil.Common{
			Code:    fiber.StatusOK,
			Status:  "success",
			Message: "Delete user successfully",
		})
}
