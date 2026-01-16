
-- Run this in your Supabase SQL Editor

-- 1. Create table
CREATE TABLE IF NOT EXISTS partners (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Insert test user (if not exists)
INSERT INTO partners (username, password)
VALUES ('partner', 'partner123')
ON CONFLICT (username) DO NOTHING;
