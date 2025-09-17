package authHttp

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"go-boilerplate/internal/pkg/auth"
	authService "go-boilerplate/internal/pkg/auth/service"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/utils"
)

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// getDeviceInfo extracts device information from the request
func getDeviceInfo(r *http.Request) *auth.DeviceInfo {
	userAgent := r.Header.Get("User-Agent")

	// Simple device detection based on User-Agent
	var deviceName *string
	if strings.Contains(strings.ToLower(userAgent), "mobile") {
		name := "Mobile Device"
		deviceName = &name
	} else if strings.Contains(strings.ToLower(userAgent), "tablet") {
		name := "Tablet"
		deviceName = &name
	} else {
		name := "Desktop"
		deviceName = &name
	}

	// For fingerprint, we could use a combination of User-Agent and other headers
	// For now, just use User-Agent hash
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(userAgent)))

	return &auth.DeviceInfo{
		Name:        deviceName,
		Fingerprint: &fingerprint,
	}
}

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

	// Get client IP and device info
	ipAddress := getClientIP(r)
	deviceInfo := getDeviceInfo(r)

	// Call service
	resp, err := h.service.Login(r.Context(), &req, ipAddress, deviceInfo)
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

	// Get client IP and device info
	ipAddress := getClientIP(r)
	deviceInfo := getDeviceInfo(r)

	// Call service
	user, err := h.service.Register(r.Context(), &req, ipAddress, deviceInfo)
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

	utils.RespondWithSuccess(
		w, r, start,
		"Registration successful",
		user,
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

	// Get client IP and device info
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	var deviceName *string
	if strings.Contains(strings.ToLower(userAgent), "mobile") {
		name := "Mobile Device"
		deviceName = &name
	} else if strings.Contains(strings.ToLower(userAgent), "tablet") {
		name := "Tablet"
		deviceName = &name
	} else {
		name := "Desktop"
		deviceName = &name
	}

	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(userAgent)))
	deviceInfo := &auth.DeviceInfo{
		Name:        deviceName,
		Fingerprint: &fingerprint,
	}

	// Call service
	resp, err := h.service.Login(c.Request.Context(), &req, ipAddress, deviceInfo)
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

	// Get client IP and device info
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	var deviceName *string
	if strings.Contains(strings.ToLower(userAgent), "mobile") {
		name := "Mobile Device"
		deviceName = &name
	} else if strings.Contains(strings.ToLower(userAgent), "tablet") {
		name := "Tablet"
		deviceName = &name
	} else {
		name := "Desktop"
		deviceName = &name
	}

	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(userAgent)))
	deviceInfo := &auth.DeviceInfo{
		Name:        deviceName,
		Fingerprint: &fingerprint,
	}

	// Call service
	user, err := h.service.Register(c.Request.Context(), &req, ipAddress, deviceInfo)
	if err != nil {
		statusCode := http.StatusInternalServerError

		if err == auth.ErrUserAlreadyExists {
			statusCode = http.StatusConflict
		}

		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Registration successful",
		"data":    user,
	})
}

// JWKKey returns the JSON Web Key Set
func (h *AuthHandler) JWKKey(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	jwks, err := h.service.GetJWKS()
	if err != nil {
		utils.RespondWithError(
			w, r, start,
			"Failed to get JWK",
			err,
			http.StatusInternalServerError,
			h.logger,
		)
		return
	}

	utils.RespondWithSuccess(
		w, r, start,
		"JWK retrieved successfully",
		jwks,
		nil,
		http.StatusOK,
	)
}

// GinJWKKey provides Gin-compatible JWK endpoint
func (h *AuthHandler) GinJWKKey(c *gin.Context) {
	jwks, err := h.service.GetJWKS()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get JWK"})
		return
	}

	c.JSON(http.StatusOK, jwks)
}
