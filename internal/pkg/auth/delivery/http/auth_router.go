package authHttp

import (
	"github.com/gin-gonic/gin"

	"go-boilerplate/internal/shared/middleware"
)

// RegisterGinRoutes registers auth routes on the given Gin router
func (h *AuthHandler) RegisterGinRoutes(r *gin.RouterGroup, authMiddleware *middleware.AuthMiddleware) {
	// Public routes
	auth := r.Group("/auth")
	{
		// POST /auth/login - Login endpoint
		auth.POST("/login", h.GinLogin)

		// POST /auth/register - Registration endpoint
		auth.POST("/register", h.GinRegister)

		// Protected routes example
		protected := auth.Group("")
		protected.Use(authMiddleware.GinAuthenticate)
		{
			// protected routes
			// Example: protected.GET("/refresh-token", h.GinRefreshToken)
		}
	}
}
