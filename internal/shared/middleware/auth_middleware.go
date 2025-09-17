package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"go-boilerplate/internal/shared"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/utils"
)

// Key for storing user ID in request context
type contextKey string

const UserIDKey contextKey = "user_id"

// AuthMiddleware provides JWT authentication functionality
type AuthMiddleware struct {
	keyManager *shared.JWKKeyManager
	logger     *logger.Logger
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(keyManager *shared.JWKKeyManager, log *logger.Logger) (*AuthMiddleware, error) {
	return &AuthMiddleware{
		keyManager: keyManager,
		logger:     log.Named("auth-middleware"),
	}, nil
}

// Authenticate validates JWT tokens from the Authorization header
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			utils.RespondWithError(
				w, r, start,
				"Authentication required",
				nil,
				http.StatusUnauthorized,
				m.logger,
			)
			return
		}

		// Check if the Authorization header has the right format
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			utils.RespondWithError(
				w, r, start,
				"Invalid authorization format, expected 'Bearer {token}'",
				nil,
				http.StatusUnauthorized,
				m.logger,
			)
			return
		}

		// Parse the token
		tokenStr := bearerToken[1]
		validKeys := m.keyManager.GetValidKeys()
		var lastErr error
		var validToken *jwt.Token

		for _, key := range validKeys {
			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
				// Validate signing algorithm
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, utils.NewHTTPError(
						http.StatusUnauthorized,
						"Invalid token signing method",
						nil,
					)
				}
				return key.PublicKey, nil
			})

			if err == nil && token.Valid {
				validToken = token
				break
			}
			lastErr = err
		}

		if validToken == nil {
			utils.RespondWithError(
				w, r, start,
				"Invalid or expired token",
				lastErr,
				http.StatusUnauthorized,
				m.logger,
			)
			return
		}

		// Extract user ID from token claims
		claims, ok := validToken.Claims.(jwt.MapClaims)
		if !ok {
			utils.RespondWithError(
				w, r, start,
				"Invalid token claims",
				nil,
				http.StatusUnauthorized,
				m.logger,
			)
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			utils.RespondWithError(
				w, r, start,
				"Invalid user ID in token",
				nil,
				http.StatusUnauthorized,
				m.logger,
			)
			return
		}

		// Add user ID to request context
		ctx := context.WithValue(r.Context(), UserIDKey, userID)

		// Call the next handler with the modified context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserID extracts the user ID from the request context
func GetUserID(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value(UserIDKey).(string)
	return userID, ok
}

// GinAuthenticate provides Gin-compatible JWT authentication middleware
func (m *AuthMiddleware) GinAuthenticate(c *gin.Context) {
	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		c.Abort()
		return
	}

	// Check if the Authorization header has the right format
	bearerToken := strings.Split(authHeader, " ")
	if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format, expected 'Bearer {token}'"})
		c.Abort()
		return
	}

	// Parse the token
	tokenStr := bearerToken[1]
	validKeys := m.keyManager.GetValidKeys()
	var validToken *jwt.Token

	for _, key := range validKeys {
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			// Validate signing algorithm
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signing method"})
				return nil, nil
			}
			return key.PublicKey, nil
		})

		if err == nil && token.Valid {
			validToken = token
			break
		}
	}

	if validToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		c.Abort()
		return
	}

	// Extract user ID from token claims
	claims, ok := validToken.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
		return
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		c.Abort()
		return
	}

	// Add user ID to Gin context
	c.Set("user_id", userID)
	c.Next()
}

// GetUserIDFromGin extracts the user ID from the Gin context
func GetUserIDFromGin(c *gin.Context) (string, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", false
	}
	uid, ok := userID.(string)
	return uid, ok
}
