package userHttp

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"go-boilerplate/internal/pkg/user"
	userService "go-boilerplate/internal/pkg/user/service"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/middleware"
	"go-boilerplate/internal/shared/utils"
)

// UserHandler handles HTTP requests for user operations
type UserHandler struct {
	service userService.UserService
	logger  *logger.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(svc userService.UserService, log *logger.Logger) *UserHandler {
	return &UserHandler{
		service: svc,
		logger:  log.Named("user-handler"),
	}
}

// GetProfile handles the get profile request
func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Get user ID from context (set by auth middleware)
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondWithError(
			w, r, start,
			"Unauthorized",
			nil,
			http.StatusUnauthorized,
			h.logger,
		)
		return
	}

	// Call service
	profile, err := h.service.GetProfile(r.Context(), userID)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == user.ErrUserNotFound {
			statusCode = http.StatusNotFound
		}

		utils.RespondWithError(
			w, r, start,
			err.Error(),
			err,
			statusCode,
			h.logger,
		)
		return
	}

	utils.RespondWithSuccess(
		w, r, start,
		"Profile retrieved successfully",
		user.ProfileResponse{
			User: *profile,
		},
		nil,
		http.StatusOK,
	)
}

// UpdateProfile handles the update profile request
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Get user ID from context (set by auth middleware)
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondWithError(
			w, r, start,
			"Unauthorized",
			nil,
			http.StatusUnauthorized,
			h.logger,
		)
		return
	}

	// Parse request
	var req user.UpdateProfileRequest
	if err := utils.DecodeJSON(r, &req); err != nil {
		utils.RespondWithError(
			w, r, start,
			"Invalid request payload",
			err,
			http.StatusBadRequest,
			h.logger,
		)
		return
	}

	// Call service
	profile, err := h.service.UpdateProfile(r.Context(), userID, &req)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == user.ErrUserNotFound {
			statusCode = http.StatusNotFound
		}

		utils.RespondWithError(
			w, r, start,
			err.Error(),
			err,
			statusCode,
			h.logger,
		)
		return
	}

	utils.RespondWithSuccess(
		w, r, start,
		"Profile updated successfully",
		user.ProfileResponse{
			User: *profile,
		},
		nil,
		http.StatusOK,
	)
}

// GinGetProfile provides Gin-compatible get profile endpoint
func (h *UserHandler) GinGetProfile(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, ok := middleware.GetUserIDFromGin(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Call service
	profile, err := h.service.GetProfile(c.Request.Context(), userID)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == user.ErrUserNotFound {
			statusCode = http.StatusNotFound
		}

		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile retrieved successfully",
		"data": user.ProfileResponse{
			User: *profile,
		},
	})
}

// GinUpdateProfile provides Gin-compatible update profile endpoint
func (h *UserHandler) GinUpdateProfile(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, ok := middleware.GetUserIDFromGin(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse request
	var req user.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Call service
	profile, err := h.service.UpdateProfile(c.Request.Context(), userID, &req)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == user.ErrUserNotFound {
			statusCode = http.StatusNotFound
		}

		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
		"data": user.ProfileResponse{
			User: *profile,
		},
	})
}
