package auth

import (
	"time"

	"github.com/go-playground/validator/v10"
)

// User represents a user in the authentication system
type User struct {
	ID                string    `json:"id" db:"id"`
	Email             string    `json:"email" db:"email"`
	Password          string    `json:"-" db:"password_hash"` // Password hash, not returned in JSON
	EmailVerified     bool      `json:"email_verified" db:"email_verified"`
	VendorID          string    `json:"vendor_id" db:"vendor_id"`
	Country           *string   `json:"country" db:"country"`
	City              *string   `json:"city" db:"city"`
	IsActive          bool      `json:"is_active" db:"is_active"`
	IsDisabled        bool      `json:"is_disabled" db:"is_disabled"`
	EnableSocialLogin bool      `json:"enable_social_login" db:"enable_social_login"`
	SignupSource      *string   `json:"signup_source" db:"signup_source"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

// Session represents a user session in the authentication system
type Session struct {
	ID                string     `json:"id" db:"id"`
	UserID            string     `json:"user_id" db:"user_id"`
	TokenHash         string     `json:"-" db:"token_hash"` // Token hash, not returned in JSON
	IPAddress         string     `json:"ip_address" db:"ip_address"`
	DeviceName        *string    `json:"device_name" db:"device_name"`
	DeviceFingerprint *string    `json:"device_fingerprint" db:"device_fingerprint"`
	IsActive          bool       `json:"is_active" db:"is_active"`
	TrustedDevice     bool       `json:"trusted_device" db:"trusted_device"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	ValidTill         time.Time  `json:"valid_till" db:"valid_till"`
	LastUsed          *time.Time `json:"last_used" db:"last_used"`
	RevokedAt         *time.Time `json:"revoked_at" db:"revoked_at"`
}

// DeviceInfo represents device information for session tracking
type DeviceInfo struct {
	Name        *string
	Fingerprint *string
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string  `json:"email" validate:"required,email"`
	Password string  `json:"password" validate:"required,min=6"`
	VendorID *string `json:"vendor_id" validate:"required"`
}

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Email    string  `json:"email" validate:"required,email"`
	Password string  `json:"password" validate:"required,min=6"`
	VendorID *string `json:"vendor_id" validate:"required"`
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
