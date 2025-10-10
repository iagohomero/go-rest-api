CREATE TABLE users(
    id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255)    NOT NULL,
    email           VARCHAR(255)    NOT NULL UNIQUE,
    password        VARCHAR(255)    NOT NULL,
    role            VARCHAR(255)    NOT NULL DEFAULT 'user',
    verified_email  BOOLEAN         DEFAULT FALSE  NOT NULL,
    created_at      BIGINT          NOT NULL,
    updated_at      BIGINT          NOT NULL
);

-- Create index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);

-- Create index on role for admin queries
CREATE INDEX idx_users_role ON users(role);

