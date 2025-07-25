-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Drop tables if they exist (for clean setup)
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT, -- NULL for OAuth-only users
  name TEXT NOT NULL,
  google_id TEXT UNIQUE, -- NULL for traditional users
  is_verified BOOLEAN DEFAULT FALSE,
  drive_connected BOOLEAN DEFAULT FALSE,
  google_refresh_token TEXT, -- Encrypted with AES-256
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Ensure either password_hash or google_id is provided
  CONSTRAINT password_or_oauth CHECK (
    (password_hash IS NOT NULL) OR (google_id IS NOT NULL)
  )
);

-- Refresh tokens table for granular revocation
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL, -- Hashed refresh token
  user_agent TEXT, -- For auditing
  ip_address TEXT, -- For security monitoring
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
  
  -- Ensure token is not expired when created
  CONSTRAINT token_not_expired_on_creation CHECK (expires_at > created_at)
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_google_id ON users(google_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Create a read-only user for the application (optional but recommended)
-- Note: This is just a template, replace 'your_password' with a secure password
-- CREATE USER cloudcam_ro WITH PASSWORD 'your_secure_password';
-- GRANT CONNECT ON DATABASE your_database TO cloudcam_ro;
-- GRANT USAGE ON SCHEMA public TO cloudcam_ro;
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO cloudcam_ro;
