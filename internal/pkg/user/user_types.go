package user

import (
	"github.com/go-playground/validator/v10"

	"go-boilerplate/internal/pkg/auth"
)

// Profile extends the auth.User to include additional user-specific fields
type Profile struct {
	auth.User
	// Add additional user profile fields here, for example:
	// Bio        string    `json:"bio" db:"bio"`
	// AvatarURL  string    `json:"avatar_url" db:"avatar_url"`
}

// ProfileResponse represents the user profile response
type ProfileResponse struct {
	User Profile `json:"user"`
}

// UpdateProfileRequest represents the request to update a user profile
type UpdateProfileRequest struct {
	FirstName string `json:"first_name" validate:"omitempty"`
	LastName  string `json:"last_name" validate:"omitempty"`
	// Add additional fields that can be updated, for example:
	// Bio       string `json:"bio" validate:"omitempty"`
	// AvatarURL string `json:"avatar_url" validate:"omitempty,url"`
}

// Validate validates a struct using the validator package
func Validate(s interface{}) error {
	validate := validator.New()
	return validate.Struct(s)
}

// Domain errors for user module
var (
	ErrUserNotFound = NewUserError("user not found")
)

// UserError represents a user-related error
type UserError struct {
	Message string
}

// NewUserError creates a new UserError
func NewUserError(message string) *UserError {
	return &UserError{
		Message: message,
	}
}

func (e *UserError) Error() string {
	return e.Message
}
