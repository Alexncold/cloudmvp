-- Migration: 002_add_user_drive_fields
-- Description: Add Google Drive related fields to users table

-- Add new columns to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS drive_quota_limit BIGINT,
ADD COLUMN IF NOT EXISTS drive_quota_usage BIGINT,
ADD COLUMN IF NOT EXISTS drive_quota_usage_in_trash BIGINT,
ADD COLUMN IF NOT EXISTS drive_quota_last_checked TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS drive_encryption_key_id TEXT,
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true,
ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS login_attempts INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS account_locked_until TIMESTAMP WITH TIME ZONE;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

-- Add comments for documentation
COMMENT ON COLUMN users.drive_quota_limit IS 'Total storage quota in bytes';
COMMENT ON COLUMN users.drive_quota_usage IS 'Current storage usage in bytes';
COMMENT ON COLUMN users.drive_quota_usage_in_trash IS 'Storage used by trashed items in bytes';
COMMENT ON COLUMN users.drive_quota_last_checked IS 'When the quota was last checked';
COMMENT ON COLUMN users.drive_encryption_key_id IS 'ID of the encryption key used for this user';
COMMENT ON COLUMN users.is_active IS 'Whether the user account is active';
COMMENT ON COLUMN users.last_login_at IS 'When the user last logged in';
COMMENT ON COLUMN users.login_attempts IS 'Number of failed login attempts';
COMMENT ON COLUMN users.account_locked_until IS 'When the account will be unlocked';

-- Update the updated_at trigger if it exists
CREATE OR REPLACE FUNCTION update_modified_column() 
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW; 
END;
$$ LANGUAGE plpgsql;

-- Apply the trigger to the users table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_users_modtime') THEN
        CREATE TRIGGER update_users_modtime
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION update_modified_column();
    END IF;
END
$$;
