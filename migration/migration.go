package migration

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/lib/pq"
)

type Migration interface {
	Up(tx *sql.Tx) error
	Down(tx *sql.Tx) error
}

type migrationEntry struct {
	id   string
	name string
	m    Migration
}

var registry = []migrationEntry{}

// Register adds a migration to the registry. Typically called from init() in migration files.
func Register(id, name string, m Migration) {
	registry = append(registry, migrationEntry{id: id, name: name, m: m})
}

// EnsureMigrationTable makes sure migrations table exists.
func EnsureMigrationTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    )`)
	return err
}

// AppliedMigrations fetches applied migration ids into a map.
func AppliedMigrations(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("SELECT id FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		m[id] = true
	}
	return m, rows.Err()
}

// ApplyUp runs pending migrations in order (registry order).
func ApplyUp(connStr string) error {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := EnsureMigrationTable(db); err != nil {
		return err
	}

	applied, err := AppliedMigrations(db)
	if err != nil {
		return err
	}

	for _, entry := range registry {
		if applied[entry.id] {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := entry.m.Up(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s up failed: %w", entry.id, err)
		}
		if _, err := tx.Exec("INSERT INTO schema_migrations (id, name) VALUES ($1,$2)", entry.id, entry.name); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ApplyDown rolls back migrations in reverse order. If targetID is empty, roll back all applied migrations.
func ApplyDown(connStr string, targetID string) error {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := EnsureMigrationTable(db); err != nil {
		return err
	}

	applied, err := AppliedMigrations(db)
	if err != nil {
		return err
	}

	// If a targetID is provided, only attempt to roll back that specific applied migration.
	if targetID != "" {
		// Find the migration entry in the registry
		var found *migrationEntry
		for _, entry := range registry {
			if entry.id == targetID {
				found = &entry
				break
			}
		}
		if found == nil {
			return errors.New("target migration id not found in registry")
		}
		if !applied[found.id] {
			return errors.New("target migration id not applied")
		}

		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := found.m.Down(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s down failed: %w", found.id, err)
		}
		if _, err := tx.Exec("DELETE FROM schema_migrations WHERE id=$1", found.id); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return nil
	}

	// No target provided: roll back all applied migrations in reverse registry order.
	appliedList := []migrationEntry{}
	for _, entry := range registry {
		if applied[entry.id] {
			appliedList = append(appliedList, entry)
		}
	}

	// iterate in reverse
	for i := len(appliedList) - 1; i >= 0; i-- {
		entry := appliedList[i]
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := entry.m.Down(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s down failed: %w", entry.id, err)
		}
		if _, err := tx.Exec("DELETE FROM schema_migrations WHERE id=$1", entry.id); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
