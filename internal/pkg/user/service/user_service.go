package userService

import (
	"context"

	"go-boilerplate/internal/pkg/user"
	userRepository "go-boilerplate/internal/pkg/user/repository"
	"go-boilerplate/internal/shared/logger"
)

// UserService defines the interface for user service operations
type UserService interface {
	GetProfile(ctx context.Context, userID string) (*user.Profile, error)
	UpdateProfile(ctx context.Context, userID string, req *user.UpdateProfileRequest) (*user.Profile, error)
}

// DefaultUserService is the default implementation of UserService
type DefaultUserService struct {
	repo   userRepository.UserRepository
	logger *logger.Logger
}

// NewUserService creates a new user service
func NewUserService(repo userRepository.UserRepository, log *logger.Logger) UserService {
	return &DefaultUserService{
		repo:   repo,
		logger: log.Named("user-service"),
	}
}

// GetProfile retrieves a user's profile
func (s *DefaultUserService) GetProfile(ctx context.Context, userID string) (*user.Profile, error) {
	return s.repo.GetUserByID(ctx, userID)
}

// UpdateProfile updates a user's profile
func (s *DefaultUserService) UpdateProfile(ctx context.Context, userID string, req *user.UpdateProfileRequest) (*user.Profile, error) {
	// Validate request
	if err := user.Validate(req); err != nil {
		return nil, err
	}

	// Create updates map
	updates := make(map[string]interface{})

	// Add fields to update
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}

	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}

	// Add more fields as needed

	// Skip update if no fields to update
	if len(updates) > 0 {
		if err := s.repo.UpdateUser(ctx, userID, updates); err != nil {
			return nil, err
		}
	}

	// Get updated profile
	return s.repo.GetUserByID(ctx, userID)
}
