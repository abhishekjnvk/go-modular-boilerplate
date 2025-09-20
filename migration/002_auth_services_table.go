package migration

import "database/sql"

type authServiceMigration struct{}

func (m *authServiceMigration) Up(tx *sql.Tx) error {
	_, err := tx.Exec(`
            -- Create orgs table
            CREATE TABLE orgs (
                id VARCHAR(50) PRIMARY KEY, 
                name VARCHAR(255) NOT NULL,
                activation_code VARCHAR(50),
                vendor_id VARCHAR(50) NOT NULL,
                website_url VARCHAR(255),
                created_by VARCHAR(25) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                subscription_grace_day INTEGER,
                UNIQUE (activation_code)
            );

            -- Create roles table
            CREATE TABLE roles (
                id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                permissions JSONB DEFAULT '{}'::JSONB,
                org_id VARCHAR(50) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                is_admin BOOLEAN DEFAULT FALSE,
                data_hash VARCHAR(50),
                description TEXT,
                vendor_id VARCHAR(50),
                created_by VARCHAR(25) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (org_id) REFERENCES orgs(id) ON UPDATE CASCADE ON DELETE CASCADE
            );

            CREATE INDEX roles_index_org_id ON roles (org_id, is_active) WHERE is_active = TRUE;

            -- Create users table
            CREATE TABLE users (
                id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100) DEFAULT '',
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                email_verified BOOLEAN DEFAULT FALSE,
                vendor_id VARCHAR(50) NOT NULL,
                country VARCHAR(2) DEFAULT '',
                city VARCHAR(50) DEFAULT '',
                is_active BOOLEAN DEFAULT TRUE,
                is_disabled BOOLEAN DEFAULT FALSE,
                enable_social_login BOOLEAN DEFAULT FALSE,
                signup_source VARCHAR(25) DEFAULT '',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );

            CREATE UNIQUE INDEX users_unique_email_vendor_id ON users (email, vendor_id, is_active) WHERE is_active = TRUE;
            CREATE INDEX users_index_vendor_id ON users (vendor_id) WHERE is_active = TRUE;

            -- Create verification_token table
            CREATE TABLE verification_token (
                id VARCHAR(50) PRIMARY KEY,
                user_id VARCHAR(50) NOT NULL,
                token_type VARCHAR(25) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                valid_till TIMESTAMPTZ NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE
            );

            -- Create sso_config table
            CREATE TABLE sso_config (
                id VARCHAR(50) PRIMARY KEY,
                org_id VARCHAR(50) NOT NULL,
                client_id VARCHAR(255) NOT NULL,
                client_secret VARCHAR(255) NOT NULL,
                discovery_url VARCHAR(255),
                issuer VARCHAR(255) NOT NULL,
                force_sso_only BOOLEAN DEFAULT FALSE,
                auto_signup BOOLEAN DEFAULT TRUE,
                authorization_endpoint VARCHAR(255) NOT NULL,
                token_endpoint VARCHAR(255) NOT NULL,
                userinfo_endpoint VARCHAR(255),
                jwks_uri VARCHAR(255) NOT NULL,
                scopes_supported VARCHAR(255),
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ,
                FOREIGN KEY (org_id) REFERENCES orgs(id) ON UPDATE CASCADE ON DELETE CASCADE
            );

            CREATE INDEX sso_config_index_org_id ON sso_config (org_id) WHERE is_active = TRUE;
            CREATE INDEX sso_config_index_client_id ON sso_config (client_id) WHERE is_active = TRUE;

            -- Create auth_session table
            CREATE TABLE auth_session (
                id VARCHAR(50) PRIMARY KEY,
                user_id VARCHAR(50) NOT NULL,
                refresh_token_hash VARCHAR(255) NOT NULL,
                ip_address VARCHAR(255) NOT NULL,
                device_name VARCHAR(255),
                trust_score INTEGER DEFAULT 0,
                city VARCHAR(100) DEFAULT '',
                country VARCHAR(2) DEFAULT '',
                timezone VARCHAR(50) DEFAULT '',
                region VARCHAR(100) DEFAULT '',
                isp VARCHAR(100) DEFAULT '',
                device_fingerprint VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE,
                trusted_device BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                valid_till TIMESTAMPTZ NOT NULL,
                last_used TIMESTAMPTZ,
                revoked_at TIMESTAMPTZ,
                FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE
            );

            CREATE INDEX auth_session_index_refresh_token_hash ON auth_session (refresh_token_hash) WHERE is_active = TRUE;
            CREATE INDEX auth_session_index_user_valid_till ON auth_session (user_id, valid_till) WHERE is_active = TRUE;

            -- Create org_user table
            CREATE TABLE org_user (
                id VARCHAR(50) PRIMARY KEY,
                user_id VARCHAR(50) NOT NULL,
                org_id VARCHAR(50) NOT NULL,
                role_id VARCHAR(50) NOT NULL,
                created_by VARCHAR(25) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
                FOREIGN KEY (org_id) REFERENCES orgs(id) ON UPDATE CASCADE ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
                UNIQUE (org_id, user_id)
            );

            CREATE INDEX org_user_index_user_id_is_active ON org_user (user_id, is_active);
            CREATE INDEX org_user_index_org_is_active ON org_user (org_id, is_active);

            -- Create mfa_methods table
            CREATE TABLE mfa_methods (
                id VARCHAR(50) PRIMARY KEY,
                device_name VARCHAR(255) NOT NULL,
                user_id VARCHAR(50) NOT NULL,
                method VARCHAR(50) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT FALSE,
                secret_key VARCHAR(255),
                recovery_email VARCHAR(255),
                recovery_phone VARCHAR(255),
                web_authn_counter BIGINT,
                credential_id TEXT,
                public_key TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE
            );

            CREATE INDEX mfa_methods_index_user_is_active ON mfa_methods (user_id, is_active) WHERE is_active = TRUE;
`)
	return err
}

func (m *authServiceMigration) Down(tx *sql.Tx) error {
	_, err := tx.Exec(`
			
			-- Drop indexes before dropping tables
			DROP INDEX IF EXISTS mfa_methods_index_user_is_active;
			DROP INDEX IF EXISTS org_user_index_org_is_active;
			DROP INDEX IF EXISTS org_user_index_user_id_is_active;
			DROP INDEX IF EXISTS auth_session_index_user_valid_till;
			DROP INDEX IF EXISTS auth_session_index_token_hash;
			DROP INDEX IF EXISTS sso_config_index_client_id;
			DROP INDEX IF EXISTS sso_config_index_org_id;
			DROP INDEX IF EXISTS users_index_vendor_id;
			DROP INDEX IF EXISTS users_unique_email_vendor_id;
			DROP INDEX IF EXISTS roles_index_org_id;

			-- Drop tables in order respecting foreign keys
			DROP TABLE IF EXISTS mfa_methods;
			DROP TABLE IF EXISTS org_user;
			DROP TABLE IF EXISTS auth_session;
			DROP TABLE IF EXISTS sso_config;
			DROP TABLE IF EXISTS verification_token;
			DROP TABLE IF EXISTS roles;
			DROP TABLE IF EXISTS users;
			DROP TABLE IF EXISTS orgs;
	`)
	return err
}

func init() {
	// id-of-migration, name-of-migration, migration-struct
	Register("002", "create-auth-service-table", &authServiceMigration{})
}
