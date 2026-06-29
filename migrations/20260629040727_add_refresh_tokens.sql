ALTER TABLE sessions ADD COLUMN IF NOT EXISTS refresh_token_hash TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS refresh_token_expires_at TIMESTAMPTZ;