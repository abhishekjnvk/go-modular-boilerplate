package auth

import (
	"time"

	"github.com/go-playground/validator/v10"
)

// User represents a user in the authentication system
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password_hash"` // Password hash, not returned in JSON
	FirstName string    `json:"first_name" db:"first_name"`
	LastName  string    `json:"last_name" db:"last_name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
}

// LoginResponse represents the login response payload
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"` // Token expiration in seconds
	User      User   `json:"user"`
}

// Validate validates a struct using the validator package
func Validate(s interface{}) error {
	validate := validator.New()
	return validate.Struct(s)
}

// Domain errors for authentication
var (
	ErrInvalidCredentials = NewAuthError("invalid email or password")
	ErrUserAlreadyExists  = NewAuthError("user with this email already exists")
	ErrUserNotFound       = NewAuthError("user not found")
)

// AuthError represents an authentication error
type AuthError struct {
	Message string
}

// NewAuthError creates a new AuthError
func NewAuthError(message string) *AuthError {
	return &AuthError{
		Message: message,
	}
}

func (e *AuthError) Error() string {
	return e.Message
}
