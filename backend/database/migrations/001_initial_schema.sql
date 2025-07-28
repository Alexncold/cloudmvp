-- Migration: 001_initial_schema
-- Description: Initial simplified schema for CloudCam MVP

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Drop existing tables if they exist (for clean setup)
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS cameras CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  google_id TEXT UNIQUE,
  drive_folder_id TEXT,
  google_refresh_token TEXT, -- Encrypted with AES-256
  encryption_enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Cameras table (consolidated with upload jobs)
CREATE TABLE cameras (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  rtsp_url TEXT NOT NULL,
  username TEXT,
  password TEXT, -- Encrypted with AES-256
  is_active BOOLEAN DEFAULT true,
  is_recording BOOLEAN DEFAULT false,
  segment_duration_seconds INTEGER DEFAULT 300, -- 5 minutes
  current_segment_path TEXT,
  last_heartbeat TIMESTAMP WITH TIME ZONE,
  last_upload_status TEXT,
  last_uploaded_file_id TEXT,
  retry_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Refresh tokens table for authentication
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL, -- Hashed refresh token
  user_agent TEXT,
  ip_address TEXT,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
  
  -- Ensure token is not expired when created
  CONSTRAINT token_not_expired_on_creation CHECK (expires_at > created_at)
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_google_id ON users(google_id);
CREATE INDEX idx_cameras_user_id ON cameras(user_id);
CREATE INDEX idx_cameras_is_active ON cameras(is_active) WHERE is_active = true;
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

-- Triggers to automatically update updated_at
CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cameras_updated_at
BEFORE UPDATE ON cameras
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Create a read-only user for the application (optional)
-- Note: Replace 'your_secure_password' with a secure password in production
-- CREATE USER cloudcam_ro WITH PASSWORD 'your_secure_password';
-- GRANT CONNECT ON DATABASE your_database TO cloudcam_ro;
-- GRANT USAGE ON SCHEMA public TO cloudcam_ro;
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO cloudcam_ro;
