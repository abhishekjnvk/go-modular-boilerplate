package authHttp

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"go-boilerplate/internal/pkg/auth"
	authService "go-boilerplate/internal/pkg/auth/service"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/utils"
)

// AuthHandler handles HTTP requests for authentication operations
type AuthHandler struct {
	service         authService.AuthService
	logger          *logger.Logger
	responseHandler *utils.ResponseHandler
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(svc authService.AuthService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		service:         svc,
		logger:          log.Named("auth-handler"),
		responseHandler: utils.NewResponseHandler(log.Named("auth-responses")),
	}
}

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

// Login handles the login request
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req auth.LoginRequest
	if err := utils.DecodeJSON(r, &req); err != nil {
		h.responseHandler.BadRequest(w, r.Context(), "Invalid request payload")
		return
	}

	// Get client IP and device info
	ipAddress := getClientIP(r)
	deviceInfo := getDeviceInfo(r)

	// Call service
	resp, err := h.service.Login(r.Context(), &req, ipAddress, deviceInfo)
	if err != nil {
		utils.HandleServiceError(w, r.Context(), err, h.responseHandler)
		return
	}

	h.responseHandler.Success(w, r.Context(), resp, "Login successful")
}

// Register handles the registration request
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req auth.RegisterRequest
	if err := utils.DecodeJSON(r, &req); err != nil {
		h.responseHandler.BadRequest(w, r.Context(), "Invalid request payload")
		return
	}

	// Get client IP and device info
	ipAddress := getClientIP(r)
	deviceInfo := getDeviceInfo(r)

	// Call service
	user, err := h.service.Register(r.Context(), &req, ipAddress, deviceInfo)
	if err != nil {
		utils.HandleServiceError(w, r.Context(), err, h.responseHandler)
		return
	}

	h.responseHandler.Created(w, r.Context(), user, "Registration successful")
}

// GinLogin provides Gin-compatible login endpoint
func (h *AuthHandler) GinLogin(c *gin.Context) {
	// Parse request
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.responseHandler.GinBadRequest(c, "Invalid request payload")
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
		utils.GinHandleServiceError(c, err, h.responseHandler)
		return
	}

	h.responseHandler.GinSuccess(c, resp, "Login successful")
}

// GinRegister provides Gin-compatible registration endpoint
func (h *AuthHandler) GinRegister(c *gin.Context) {
	// Parse request
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.responseHandler.GinBadRequest(c, "Invalid request payload")
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
		utils.GinHandleServiceError(c, err, h.responseHandler)
		return
	}

	h.responseHandler.GinSuccess(c, user, "Registration successful")
}

// RefreshToken handles the refresh token request
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req auth.RefreshTokenRequest
	if err := utils.DecodeJSON(r, &req); err != nil {
		h.responseHandler.BadRequest(w, r.Context(), "Invalid request payload")
		return
	}

	// Get client IP and device info
	ipAddress := getClientIP(r)
	deviceInfo := getDeviceInfo(r)

	// Call service
	resp, err := h.service.RefreshToken(r.Context(), &req, ipAddress, deviceInfo)
	if err != nil {
		utils.HandleServiceError(w, r.Context(), err, h.responseHandler)
		return
	}

	h.responseHandler.Success(w, r.Context(), resp, "Token refreshed successfully")
}

// GinRefreshToken provides Gin-compatible refresh token endpoint
func (h *AuthHandler) GinRefreshToken(c *gin.Context) {
	var req auth.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.responseHandler.GinBadRequest(c, "Invalid request payload")
		return
	}

	// Get client IP and device info
	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()
	deviceInfo := &auth.DeviceInfo{
		Name:        &userAgent,
		Fingerprint: nil, // Could be implemented based on device fingerprinting
	}

	// Call service
	resp, err := h.service.RefreshToken(c.Request.Context(), &req, ipAddress, deviceInfo)
	if err != nil {
		utils.GinHandleServiceError(c, err, h.responseHandler)
		return
	}

	h.responseHandler.GinSuccess(c, resp, "Token refreshed successfully")
}

// JWKKey returns the JSON Web Key Set
func (h *AuthHandler) JWKKey(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.service.GetJWKS()
	if err != nil {
		h.responseHandler.InternalError(w, r.Context(), err)
		return
	}

	h.responseHandler.Success(w, r.Context(), jwks, "JWK retrieved successfully")
}

// GinJWKKey provides Gin-compatible JWK endpoint
func (h *AuthHandler) GinJWKKey(c *gin.Context) {
	jwks, err := h.service.GetJWKS()
	if err != nil {
		h.responseHandler.GinInternalError(c, err)
		return
	}

	h.responseHandler.GinSuccess(c, jwks, "JWK retrieved successfully")
}

// GinVerifyEmail provides Gin-compatible email verification endpoint
func (h *AuthHandler) GinVerifyEmail(c *gin.Context) {
	var req auth.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.responseHandler.GinBadRequest(c, "Invalid request payload")
		return
	}

	resp, err := h.service.VerifyEmail(c.Request.Context(), &req)
	if err != nil {
		utils.GinHandleServiceError(c, err, h.responseHandler)
		return
	}

	h.responseHandler.GinSuccess(c, resp, "Email verified successfully")
}

// GinRequestPasswordReset provides Gin-compatible password reset request endpoint
func (h *AuthHandler) GinRequestPasswordReset(c *gin.Context) {
	var req auth.RequestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.responseHandler.GinBadRequest(c, "Invalid request payload")
		return
	}

	resp, err := h.service.RequestPasswordReset(c.Request.Context(), &req)
	if err != nil {
		utils.GinHandleServiceError(c, err, h.responseHandler)
		return
	}

	h.responseHandler.GinSuccess(c, resp, "Password reset email sent successfully")
}

// GinResetPassword provides Gin-compatible password reset endpoint
func (h *AuthHandler) GinResetPassword(c *gin.Context) {
	var req auth.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.responseHandler.GinBadRequest(c, "Invalid request payload")
		return
	}

	resp, err := h.service.ResetPassword(c.Request.Context(), &req)
	if err != nil {
		utils.GinHandleServiceError(c, err, h.responseHandler)
		return
	}

	h.responseHandler.GinSuccess(c, resp, "Password reset successfully")
}

// GinChangePassword provides Gin-compatible change password endpoint
func (h *AuthHandler) GinChangePassword(c *gin.Context) {
	var req auth.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.responseHandler.GinBadRequest(c, "Invalid request payload")
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		h.responseHandler.GinUnauthorized(c, "User not authenticated")
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		h.responseHandler.GinInternalError(c, fmt.Errorf("invalid user ID type"))
		return
	}

	resp, err := h.service.ChangePassword(c.Request.Context(), userIDStr, &req)
	if err != nil {
		utils.GinHandleServiceError(c, err, h.responseHandler)
		return
	}

	h.responseHandler.GinSuccess(c, resp, "Password changed successfully")
}
