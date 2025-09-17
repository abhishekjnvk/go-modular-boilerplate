package authService

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"go-boilerplate/internal/app/config"
	"go-boilerplate/internal/pkg/auth"
	authRepository "go-boilerplate/internal/pkg/auth/repository"
	"go-boilerplate/internal/shared"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/metrics"

	"github.com/google/uuid"
)

// AuthService defines the interface for authentication service
type AuthService interface {
	Login(ctx context.Context, req *auth.LoginRequest, ipAddress string, deviceInfo *auth.DeviceInfo) (*auth.LoginResponse, error)
	Register(ctx context.Context, req *auth.RegisterRequest, ipAddress string, deviceInfo *auth.DeviceInfo) (*auth.User, error)
	GenerateToken(user *auth.User) (string, int64, error)
	ValidateToken(tokenString string) (*auth.User, error)
	GetJWKS() (map[string]interface{}, error)
}

// DefaultAuthService is the default implementation of AuthService
type DefaultAuthService struct {
	repo       authRepository.AuthRepository
	config     *config.Config
	logger     *logger.Logger
	metrics    *metrics.Metrics
	keyManager *shared.JWKKeyManager
}

// NewAuthService creates a new authentication service
func NewAuthService(repo authRepository.AuthRepository, cfg *config.Config, log *logger.Logger, metrics *metrics.Metrics, keyManager *shared.JWKKeyManager) (AuthService, error) {
	return &DefaultAuthService{
		repo:       repo,
		config:     cfg,
		logger:     log.Named("auth-service"),
		metrics:    metrics,
		keyManager: keyManager,
	}, nil
}

// Login authenticates a user and returns a JWT token
func (s *DefaultAuthService) Login(ctx context.Context, req *auth.LoginRequest, ipAddress string, deviceInfo *auth.DeviceInfo) (*auth.LoginResponse, error) {
	// Validate request
	if err := auth.Validate(req); err != nil {
		if s.metrics != nil {
			s.metrics.RecordUserLoginError()
		}
		return nil, err
	}

	// Find user by email
	user, err := s.repo.FindUserByEmail(ctx, req.Email)
	if err != nil {
		if s.metrics != nil {
			s.metrics.RecordUserLoginError()
		}
		return nil, auth.ErrInvalidCredentials
	}

	// Check if user is disabled
	if user.IsDisabled {
		if s.metrics != nil {
			s.metrics.RecordUserLoginError()
		}
		return nil, auth.ErrInvalidCredentials
	}

	// Compare password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		if s.metrics != nil {
			s.metrics.RecordUserLoginError()
		}
		return nil, auth.ErrInvalidCredentials
	}

	// Generate JWT token
	token, expiresIn, err := s.GenerateToken(user)
	if err != nil {
		if s.metrics != nil {
			s.metrics.RecordUserLoginError()
		}
		return nil, err
	}

	// Create session
	sessionID := uuid.New().String()
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashStr := hex.EncodeToString(tokenHash[:])

	session := &auth.Session{
		ID:                sessionID,
		UserID:            user.ID,
		TokenHash:         tokenHashStr,
		IPAddress:         ipAddress,
		DeviceName:        deviceInfo.Name,
		DeviceFingerprint: deviceInfo.Fingerprint,
		IsActive:          true,
		TrustedDevice:     false, // Could be determined based on previous logins
		CreatedAt:         time.Now().UTC(),
		ValidTill:         time.Now().UTC().Add(time.Duration(s.config.JWTExpiryHours) * time.Hour),
		LastUsed:          nil,
		RevokedAt:         nil,
	}

	err = s.repo.CreateSession(ctx, session)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err))
		// Don't fail the login if session creation fails
	}

	// Record successful login
	if s.metrics != nil {
		s.metrics.RecordUserLogin()
	}

	// Hide password hash in response
	user.Password = ""

	return &auth.LoginResponse{
		Token:     token,
		ExpiresIn: expiresIn,
		User:      *user,
	}, nil
}

// Register creates a new user
func (s *DefaultAuthService) Register(ctx context.Context, req *auth.RegisterRequest, ipAddress string, deviceInfo *auth.DeviceInfo) (*auth.User, error) {
	// Validate request
	if err := auth.Validate(req); err != nil {
		return nil, err
	}

	// Check if user already exists
	_, err := s.repo.FindUserByEmail(ctx, req.Email)
	if err == nil {
		return nil, auth.ErrUserAlreadyExists
	} else if err != auth.ErrUserNotFound {
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	now := time.Now().UTC()
	user := &auth.User{
		ID:                uuid.New().String(),
		Email:             req.Email,
		Password:          string(hashedPassword),
		EmailVerified:     false,     // No email verification as requested
		VendorID:          "default", // Default vendor
		Country:           nil,
		City:              nil,
		IsActive:          true,
		IsDisabled:        false,
		EnableSocialLogin: false,
		SignupSource:      nil,
		CreatedAt:         now,
	}

	// Save user
	err = s.repo.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	// Generate token for auto-login after registration
	token, _, err := s.GenerateToken(user)
	if err != nil {
		s.logger.Error("Failed to generate token after registration", zap.Error(err))
		// Don't fail registration if token generation fails
	} else {
		// Create session
		sessionID := uuid.New().String()
		tokenHash := sha256.Sum256([]byte(token))
		tokenHashStr := hex.EncodeToString(tokenHash[:])

		session := &auth.Session{
			ID:                sessionID,
			UserID:            user.ID,
			TokenHash:         tokenHashStr,
			IPAddress:         ipAddress,
			DeviceName:        deviceInfo.Name,
			DeviceFingerprint: deviceInfo.Fingerprint,
			IsActive:          true,
			TrustedDevice:     false,
			CreatedAt:         now,
			ValidTill:         now.Add(time.Duration(s.config.JWTExpiryHours) * time.Hour),
			LastUsed:          nil,
			RevokedAt:         nil,
		}

		err = s.repo.CreateSession(ctx, session)
		if err != nil {
			s.logger.Error("Failed to create session after registration", zap.Error(err))
			// Don't fail registration if session creation fails
		}
	}

	// Record successful registration
	if s.metrics != nil {
		s.metrics.RecordUserRegistration()
	}

	// Hide password hash in response
	user.Password = ""

	return user, nil
}

// GenerateToken generates a JWT token for a user
func (s *DefaultAuthService) GenerateToken(user *auth.User) (string, int64, error) {
	// Set expiration time
	expirationHours := s.config.JWTExpiryHours
	expiresAt := time.Now().Add(time.Duration(expirationHours) * time.Hour)
	expiresIn := int64(time.Until(expiresAt).Seconds())

	// Create claims
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     expiresAt.Unix(),
		"iat":     time.Now().Unix(),
		"iss":     "go-boilerplate",
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Generate encoded token
	activeKey, err := s.keyManager.GetActiveKey()
	if err != nil {
		return "", 0, fmt.Errorf("failed to get active key: %w", err)
	}
	tokenString, err := token.SignedString(activeKey.PrivateKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresIn, nil
}

// ValidateToken validates a JWT token and returns the user
func (s *DefaultAuthService) ValidateToken(tokenString string) (*auth.User, error) {
	validKeys := s.keyManager.GetValidKeys()

	var lastErr error
	for _, key := range validKeys {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return key.PublicKey, nil
		})

		if err == nil && token.Valid {
			// Token is valid, extract claims
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				userID, ok := claims["user_id"].(string)
				if !ok {
					return nil, fmt.Errorf("invalid user_id in token")
				}

				email, ok := claims["email"].(string)
				if !ok {
					return nil, fmt.Errorf("invalid email in token")
				}

				// Find user by ID to ensure they still exist and are active
				ctx := context.Background()
				user, err := s.repo.FindUserByEmail(ctx, email)
				if err != nil {
					return nil, err
				}

				if user.ID != userID {
					return nil, fmt.Errorf("token user mismatch")
				}

				// Check if user is still active
				if !user.IsActive || user.IsDisabled {
					return nil, fmt.Errorf("user is not active")
				}

				return user, nil
			}
		}
		lastErr = err
	}

	return nil, lastErr

	return nil, fmt.Errorf("invalid token")
}

// GetJWKS returns the JSON Web Key Set for the public key
func (s *DefaultAuthService) GetJWKS() (map[string]interface{}, error) {
	return s.keyManager.GetJWKS()
}
