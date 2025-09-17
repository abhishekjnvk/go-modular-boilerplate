package authService

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"go-boilerplate/internal/app/config"
	"go-boilerplate/internal/pkg/auth"
	authRepository "go-boilerplate/internal/pkg/auth/repository"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/metrics"

	"github.com/google/uuid"
)

// AuthService defines the interface for authentication service
type AuthService interface {
	Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error)
	Register(ctx context.Context, req *auth.RegisterRequest) (*auth.User, error)
	GenerateToken(user *auth.User) (string, int64, error)
}

// DefaultAuthService is the default implementation of AuthService
type DefaultAuthService struct {
	repo    authRepository.AuthRepository
	config  *config.Config
	logger  *logger.Logger
	metrics *metrics.Metrics
}

// NewAuthService creates a new authentication service
func NewAuthService(repo authRepository.AuthRepository, cfg *config.Config, log *logger.Logger, metrics *metrics.Metrics) AuthService {
	return &DefaultAuthService{
		repo:    repo,
		config:  cfg,
		logger:  log.Named("auth-service"),
		metrics: metrics,
	}
}

// Login authenticates a user and returns a JWT token
func (s *DefaultAuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
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
func (s *DefaultAuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.User, error) {
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
		ID:        uuid.New().String(),
		Email:     req.Email,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Save user
	err = s.repo.CreateUser(ctx, user)
	if err != nil {
		return nil, err
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
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token
	tokenString, err := token.SignedString([]byte(s.config.JWTSecretKey))
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresIn, nil
}
