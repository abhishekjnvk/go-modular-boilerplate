package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"go-boilerplate/internal/pkg/auth"
	"go-boilerplate/internal/shared/database"
	"go-boilerplate/internal/shared/interfaces"
	"go-boilerplate/internal/shared/logger"
)

// AuthRepository defines the interface for authentication operations
type AuthRepository interface {
	interfaces.Repository
	FindUserByEmail(ctx context.Context, email string, vendorId string) (*auth.User, error)
	FindUserByID(ctx context.Context, userID string) (*auth.User, error)
	CreateUser(ctx context.Context, user *auth.User) error
	CreateSession(ctx context.Context, session *auth.Session) error
	FindSessionByTokenHash(ctx context.Context, tokenHash string) (*auth.Session, error)
	FindSessionByID(ctx context.Context, sessionID string) (*auth.Session, error)
	UpdateSessionLastUsed(ctx context.Context, sessionID string) error
	RevokeSession(ctx context.Context, sessionID string) error
}

// PostgresAuthRepository is a PostgreSQL implementation of AuthRepository
type PostgresAuthRepository struct {
	rwDB   *database.ReadWriteDatabase
	logger *logger.Logger
}

// NewPostgresAuthRepository creates a new PostgreSQL auth repository
func NewPostgresAuthRepository(rwDB *database.ReadWriteDatabase, log *logger.Logger) AuthRepository {
	return &PostgresAuthRepository{
		rwDB:   rwDB,
		logger: log.Named("auth-repo"),
	}
}

// FindUserByEmail finds a user by email
func (r *PostgresAuthRepository) FindUserByEmail(ctx context.Context, email string, vendorId string) (*auth.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, vendor_id, country, city, is_active, is_disabled, enable_social_login, created_at
		FROM users
		WHERE email = $1 AND vendor_id = $2 AND is_active = true
	`

	var user auth.User
	err := r.rwDB.ReadDB().GetContext(ctx, &user, query, email, vendorId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// FindUserByID finds a user by ID
func (r *PostgresAuthRepository) FindUserByID(ctx context.Context, userID string) (*auth.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, vendor_id, country, city, is_active, is_disabled, enable_social_login, signup_source, created_at
		FROM users
		WHERE id = $1 AND is_active = true
	`

	var user auth.User
	err := r.rwDB.ReadDB().GetContext(ctx, &user, query, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// CreateUser creates a new user
func (r *PostgresAuthRepository) CreateUser(ctx context.Context, user *auth.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, email_verified, vendor_id, country, city, is_active, is_disabled, enable_social_login, signup_source, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.rwDB.WriteDB().ExecContext(
		ctx,
		query,
		user.ID,
		user.Email,
		user.Password,
		user.EmailVerified,
		user.VendorID,
		user.Country,
		user.City,
		user.IsActive,
		user.IsDisabled,
		user.EnableSocialLogin,
		user.SignupSource,
		user.CreatedAt,
	)

	return err
}

// CreateSession creates a new session
func (r *PostgresAuthRepository) CreateSession(ctx context.Context, session *auth.Session) error {
	query := `
		INSERT INTO auth_session (id, user_id, refresh_token_hash, ip_address, device_name, trust_score, city, country, region, timezone, isp, device_fingerprint, is_active, trusted_device, created_at, valid_till, last_used, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err := r.rwDB.WriteDB().ExecContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.RefreshTokenHash,
		session.IPAddress,
		session.DeviceName,
		session.TrustScore,
		session.City,
		session.Country,
		session.Region,
		session.Timezone,
		session.ISP,
		session.DeviceFingerprint,
		session.IsActive,
		session.TrustedDevice,
		session.CreatedAt,
		session.ValidTill,
		session.LastUsed,
		session.RevokedAt,
	)

	return err
}

// FindSessionByTokenHash finds a session by token hash
func (r *PostgresAuthRepository) FindSessionByTokenHash(ctx context.Context, tokenHash string) (*auth.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, ip_address, device_name, trust_score, city, country, country_code, region, region_code, latitude, longitude, timezone, isp, device_fingerprint, is_active, trusted_device, created_at, valid_till, last_used, revoked_at
		FROM auth_session
		WHERE refresh_token_hash = $1 AND is_active = true
	`

	var session auth.Session
	err := r.rwDB.ReadDB().GetContext(ctx, &session, query, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrSessionNotFound
		}
		return nil, err
	}

	return &session, nil
}

// FindSessionByID finds a session by ID
func (r *PostgresAuthRepository) FindSessionByID(ctx context.Context, sessionID string) (*auth.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, ip_address, device_name, trust_score, city, country, country_code, region, region_code, latitude, longitude, timezone, isp, device_fingerprint, is_active, trusted_device, created_at, valid_till, last_used, revoked_at
		FROM auth_session
		WHERE id = $1 AND is_active = true AND valid_till > CURRENT_TIMESTAMP
	`

	var session auth.Session
	err := r.rwDB.ReadDB().GetContext(ctx, &session, query, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrSessionNotFound
		}
		return nil, err
	}

	return &session, nil
}

// UpdateSessionLastUsed updates the last used time for a session
func (r *PostgresAuthRepository) UpdateSessionLastUsed(ctx context.Context, sessionID string) error {
	query := `
		UPDATE auth_session
		SET last_used = CURRENT_TIMESTAMP
		WHERE id = $1 AND is_active = true
	`

	_, err := r.rwDB.WriteDB().ExecContext(ctx, query, sessionID)
	return err
}

// RevokeSession revokes a session
func (r *PostgresAuthRepository) RevokeSession(ctx context.Context, sessionID string) error {
	query := `
		UPDATE auth_session
		SET is_active = false, revoked_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	_, err := r.rwDB.WriteDB().ExecContext(ctx, query, sessionID)
	return err
}

// Health performs health check for the auth repository
func (r *PostgresAuthRepository) Health(ctx context.Context) error {
	if r.rwDB == nil {
		return fmt.Errorf("database connection is nil")
	}

	// Test read database connection
	if err := r.rwDB.ReadDB().PingContext(ctx); err != nil {
		return fmt.Errorf("read database health check failed: %w", err)
	}

	// Test write database connection
	if err := r.rwDB.WriteDB().PingContext(ctx); err != nil {
		return fmt.Errorf("write database health check failed: %w", err)
	}

	return nil
}
