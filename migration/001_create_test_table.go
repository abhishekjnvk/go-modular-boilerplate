package migration

import "database/sql"

type initialMigration struct{}

func (m *initialMigration) Up(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS test_table (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
    )`)
	return err
}

func (m *initialMigration) Down(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS test_table`)
	return err
}

func init() {
	// id-of-migration, name-of-migration, migration-struct
	Register("001", "create-test-table", &initialMigration{})
}
