package authRepository

import (
	"context"
	"database/sql"
	"errors"

	"go-boilerplate/internal/pkg/auth"
	"go-boilerplate/internal/shared/database"
	"go-boilerplate/internal/shared/logger"
)

// AuthRepository defines the interface for authentication operations
type AuthRepository interface {
	FindUserByEmail(ctx context.Context, email string) (*auth.User, error)
	CreateUser(ctx context.Context, user *auth.User) error
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
func (r *PostgresAuthRepository) FindUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	var user auth.User
	err := r.rwDB.ReadDB().GetContext(ctx, &user, query, email)
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
		INSERT INTO users (id, email, password_hash, first_name, last_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.rwDB.WriteDB().ExecContext(
		ctx,
		query,
		user.ID,
		user.Email,
		user.Password,
		user.FirstName,
		user.LastName,
		user.CreatedAt,
		user.UpdatedAt,
	)

	return err
}
