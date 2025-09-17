package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/utils"
)

// RecoveryMiddleware provides panic recovery functionality
type RecoveryMiddleware struct {
	logger *logger.Logger
}

// NewRecoveryMiddleware creates a new recovery middleware
func NewRecoveryMiddleware(log *logger.Logger) *RecoveryMiddleware {
	return &RecoveryMiddleware{
		logger: log.Named("recovery"),
	}
}

// Recover catches panics and returns a 500 Internal Server Error
func (m *RecoveryMiddleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Defer recovery function
		defer func() {
			if err := recover(); err != nil {
				// Get stack trace
				stack := debug.Stack()

				// Log the panic
				m.logger.Error(
					"Panic recovered",
					zap.Any("error", err),
					zap.String("stack", string(stack)),
				)

				// Respond with error
				utils.RespondWithError(
					w, r, start,
					"Internal server error",
					fmt.Errorf("panic: %v", err),
					http.StatusInternalServerError,
					m.logger,
				)
			}
		}()

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// GinRecover provides Gin-compatible panic recovery middleware
func (m *RecoveryMiddleware) GinRecover(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			// Get stack trace
			stack := debug.Stack()

			// Log the panic
			m.logger.Error(
				"Panic recovered",
				zap.Any("error", err),
				zap.String("stack", string(stack)),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
			)

			// Respond with error
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal server error",
			})
			c.Abort()
		}
	}()

	c.Next()
}
