
-- Run this in your Supabase SQL Editor

-- 1. Create admins table if not exists
CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Insert default admin user (if not exists)
INSERT INTO admins (username, password)
VALUES ('admin', 'admin123')
ON CONFLICT (username) DO NOTHING;
