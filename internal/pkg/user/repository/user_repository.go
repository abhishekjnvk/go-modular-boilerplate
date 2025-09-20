package userRepository

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"go-boilerplate/internal/pkg/auth"
	"go-boilerplate/internal/pkg/user"
	"go-boilerplate/internal/shared/database"
	"go-boilerplate/internal/shared/interfaces"
	"go-boilerplate/internal/shared/logger"
)

// UserRepository defines the interface for user operations
type UserRepository interface {
	interfaces.Repository
	GetUserByID(ctx context.Context, id string) (*user.Profile, error)
	UpdateUser(ctx context.Context, id string, updates map[string]interface{}) error
}

// PostgresUserRepository is a PostgreSQL implementation of UserRepository
type PostgresUserRepository struct {
	rwDB   *database.ReadWriteDatabase
	logger *logger.Logger
}

// NewPostgresUserRepository creates a new PostgreSQL user repository
func NewPostgresUserRepository(rwDB *database.ReadWriteDatabase, log *logger.Logger) UserRepository {
	return &PostgresUserRepository{
		rwDB:   rwDB,
		logger: log.Named("user-repo"),
	}
}

// GetUserByID retrieves a user profile by ID
func (r *PostgresUserRepository) GetUserByID(ctx context.Context, id string) (*user.Profile, error) {
	query := `
		SELECT id, email, email_verified, name, is_active, country, city, created_at
		FROM users
		WHERE id = $1
	`

	var u auth.User
	err := r.rwDB.ReadDB().GetContext(ctx, &u, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, user.ErrUserNotFound
		}
		return nil, err
	}

	// Create profile from user
	profile := &user.Profile{
		User: u,
	}

	return profile, nil
}

// UpdateUser updates a user with the given fields
func (r *PostgresUserRepository) UpdateUser(ctx context.Context, id string, updates map[string]interface{}) error {
	// Ensure the user exists
	_, err := r.GetUserByID(ctx, id)
	if err != nil {
		return err
	}

	// Build dynamic update query
	// In a real application, you'd want to use a more sophisticated approach to prevent SQL injection
	query := "UPDATE users SET "
	args := []interface{}{}
	i := 1

	for field, value := range updates {
		if i > 1 {
			query += ", "
		}
		query += field + " = $" + strconv.Itoa(i)
		args = append(args, value)
		i++
	}

	query += ", updated_at = NOW() WHERE id = $" + strconv.Itoa(i)
	args = append(args, id)

	_, err = r.rwDB.WriteDB().ExecContext(ctx, query, args...)
	return err
}
