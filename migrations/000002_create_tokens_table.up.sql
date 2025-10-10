CREATE TABLE tokens(
    id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    token           VARCHAR(500)    NOT NULL,
    user_id         UUID            NOT NULL,
    type            VARCHAR(50)     NOT NULL,
    expires         TIMESTAMP       NOT NULL,
    created_at      BIGINT          NOT NULL,
    updated_at      BIGINT          NOT NULL,
    CONSTRAINT fk_tokens_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for token lookups
CREATE INDEX idx_tokens_token ON tokens(token);

-- Create index for user_id and type (common query pattern)
CREATE INDEX idx_tokens_user_type ON tokens(user_id, type);

-- Create index for cleanup of expired tokens
CREATE INDEX idx_tokens_expires ON tokens(expires);

