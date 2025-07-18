-- Create the users table
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at DATETIME NOT NULL
);

-- Insert test user: admin (system_admin)
INSERT INTO users (user_id, username, password_hash, role, email, created_at)
VALUES (
    '550e8400-e29b-41d4-a716-446655440000',
    'admin',
    '$2b$12$2b2X3b7Z3b7Z3b7Z3b7Z3u3b7Z3b7Z3b7Z3b7Z3b7Z3b7Z3b7Z3b7', -- bcrypt hash for 'admin123'
    'system_admin',
    'admin@example.com',
    '2025-07-18 18:27:00'
);

-- Insert test user: user1 (system_user)
INSERT INTO users (user_id, username, password_hash, role, email, created_at)
VALUES (
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'user1',
    '$2b$12$3c3X4c8Z4c8Z4c8Z4c8Z4u4c8Z4c8Z4c8Z4c8Z4c8Z4c8Z4c8Z4c8', -- bcrypt hash for 'user123'
    'system_user',
    'user1@example.com',
    '2025-07-18 18:27:00'
);

-- Create the databases table
CREATE TABLE databases (
    db_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    db_name TEXT NOT NULL,
    db_path TEXT NOT NULL,
    website_url TEXT,
    status TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Insert test database for user1
INSERT INTO databases (db_id, user_id, db_name, db_path, website_url, status, created_at)
VALUES (
    'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'test_database',
    '/data/user1/test_database.db',
    'user1-test_database.datasette-portal.fly.dev',
    'Draft',
    '2025-07-18 18:27:00'
);

-- Create the user_database_roles table
CREATE TABLE user_database_roles (
    user_id TEXT NOT NULL,
    db_id TEXT NOT NULL,
    role TEXT NOT NULL,
    assigned_at DATETIME NOT NULL,
    PRIMARY KEY (user_id, db_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (db_id) REFERENCES databases(db_id)
);

-- Insert test user_database_role for user1
INSERT INTO user_database_roles (user_id, db_id, role, assigned_at)
VALUES (
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
    'admin',
    '2025-07-18 18:27:00'
);

-- Create the invites table
CREATE TABLE invites (
    code TEXT PRIMARY KEY,
    inviter_id TEXT NOT NULL,
    email TEXT NOT NULL,
    used_by TEXT,
    created_at DATETIME NOT NULL,
    used_at DATETIME,
    FOREIGN KEY (inviter_id) REFERENCES users(user_id),
    FOREIGN KEY (used_by) REFERENCES users(user_id)
);

-- Insert test invite code for registering a new system_admin
INSERT INTO invites (code, inviter_id, email, used_by, created_at, used_at)
VALUES (
    '123e4567-e89b-12d3-a456-426614174000',
    '550e8400-e29b-41d4-a716-446655440000',
    'newadmin@example.com',
    NULL,
    '2025-07-18 18:27:00',
    NULL
);

-- Create the publish_requests table
CREATE TABLE publish_requests (
    request_id TEXT PRIMARY KEY,
    db_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    status TEXT NOT NULL,
    submitted_at DATETIME NOT NULL,
    feedback TEXT,
    updated_at DATETIME,
    FOREIGN KEY (db_id) REFERENCES databases(db_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Insert test publish request for user1's database
INSERT INTO publish_requests (request_id, db_id, user_id, status, submitted_at, feedback, updated_at)
VALUES (
    'f1e2d3c4-b5a6-4c7d-8e9f-0a1b2c3d4e5f',
    'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'Pending',
    '2025-07-18 18:27:00',
    NULL,
    NULL
);

-- Create the activity_logs table
CREATE TABLE activity_logs (
    log_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    timestamp DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Insert test activity logs
INSERT INTO activity_logs (log_id, user_id, action, details, timestamp)
VALUES (
    'b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e',
    '550e8400-e29b-41d4-a716-446655440000',
    'login',
    'User admin logged in',
    '2025-07-18 18:27:00'
),
(
    'c2d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e6f',
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'login',
    'User user1 logged in',
    '2025-07-18 18:27:00'
),
(
    'd3e4f5a6-b7c8-4d9e-0f1a-2b3c4d5e6f7a',
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'create_database',
    'Created database test_database',
    '2025-07-18 18:27:00'
),
(
    'e4f5a6b7-c8d9-4e0f-1a2b-3c4d5e6f7a8b',
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'publish_request',
    'Submitted publish request for test_database',
    '2025-07-18 18:27:00'
),
(
    'f5a6b7c8-d9e0-4f1a-2b3c-4d5e6f7a8b9c',
    '550e8400-e29b-41d4-a716-446655440000',
    'invite_user',
    'Invited user with email newadmin@example.com and code 123e4567-e89b-12d3-a456-426614174000',
    '2025-07-18 18:27:00'
);

-- Create the admin_content table
CREATE TABLE admin_content (
    section TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    updated_at DATETIME NOT NULL,
    updated_by TEXT
);

-- Insert test admin_content
INSERT INTO admin_content (section, content, updated_at, updated_by)
VALUES (
    'title',
    '{"content": "EDGI Datasette Cloud Portal"}',
    '2025-07-18 18:27:00',
    'system'
),
(
    'header_image',
    '{"image_url": "/static/header.jpg", "alt_text": "", "credit_url": "", "credit_text": ""}',
    '2025-07-18 18:27:00',
    'system'
),
(
    'info',
    '{"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.", "paragraphs": ["The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites."]}',
    '2025-07-18 18:27:00',
    'system'
),
(
    'feature_cards',
    '[]',
    '2025-07-18 18:27:00',
    'system'
),
(
    'statistics',
    '[]',
    '2025-07-18 18:27:00',
    'system'
);
