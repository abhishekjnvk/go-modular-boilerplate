package authHttp

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"go-boilerplate/internal/pkg/auth"
	authService "go-boilerplate/internal/pkg/auth/service"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/utils"
)

// AuthHandler handles HTTP requests for authentication
type AuthHandler struct {
	service authService.AuthService
	logger  *logger.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(svc authService.AuthService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		service: svc,
		logger:  log.Named("auth-handler"),
	}
}

// Login handles the login request
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Parse request
	var req auth.LoginRequest
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
	resp, err := h.service.Login(r.Context(), &req)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == auth.ErrInvalidCredentials {
			statusCode = http.StatusUnauthorized
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
		"Login successful",
		resp,
		nil,
		http.StatusOK,
	)
}

// Register handles the registration request
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Parse request
	var req auth.RegisterRequest
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
	user, err := h.service.Register(r.Context(), &req)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == auth.ErrUserAlreadyExists {
			statusCode = http.StatusConflict
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

	// Generate token for the new user
	token, expiresIn, err := h.service.GenerateToken(user)
	if err != nil {
		utils.RespondWithError(
			w, r, start,
			"Failed to generate token",
			err,
			http.StatusInternalServerError,
			h.logger,
		)
		return
	}

	utils.RespondWithSuccess(
		w, r, start,
		"Registration successful",
		auth.LoginResponse{
			Token:     token,
			ExpiresIn: expiresIn,
			User:      *user,
		},
		nil,
		http.StatusCreated,
	)
}

// GinLogin provides Gin-compatible login endpoint
func (h *AuthHandler) GinLogin(c *gin.Context) {
	// Parse request
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Call service
	resp, err := h.service.Login(c.Request.Context(), &req)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == auth.ErrInvalidCredentials {
			statusCode = http.StatusUnauthorized
		}

		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"data":    resp,
	})
}

// GinRegister provides Gin-compatible registration endpoint
func (h *AuthHandler) GinRegister(c *gin.Context) {
	// Parse request
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Call service
	user, err := h.service.Register(c.Request.Context(), &req)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == auth.ErrUserAlreadyExists {
			statusCode = http.StatusConflict
		}

		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	// Generate token for the new user
	token, expiresIn, err := h.service.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Registration successful",
		"data": auth.LoginResponse{
			Token:     token,
			ExpiresIn: expiresIn,
			User:      *user,
		},
	})
}
