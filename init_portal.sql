-- Drop existing tables to ensure a clean slate
DROP TABLE IF EXISTS activity_logs;
DROP TABLE IF EXISTS publish_requests;
DROP TABLE IF EXISTS user_database_roles;
DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS admin_content;
DROP TABLE IF EXISTS databases;
DROP TABLE IF EXISTS users;

-- Create tables
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT CHECK(role IN ('system_admin', 'system_user')),
    email TEXT,
    created_at TIMESTAMP
);

CREATE TABLE databases (
    db_id TEXT PRIMARY KEY,
    user_id TEXT,
    db_name TEXT,
    db_path TEXT,
    website_url TEXT,
    status TEXT DEFAULT 'Draft',
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE user_database_roles (
    user_id TEXT,
    db_id TEXT,
    role TEXT,
    assigned_at TIMESTAMP,
    PRIMARY KEY (user_id, db_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (db_id) REFERENCES databases(db_id)
);

CREATE TABLE admin_content (
    section TEXT PRIMARY KEY,
    content JSON,
    updated_at TIMESTAMP,
    updated_by TEXT
);

CREATE TABLE invites (
    code TEXT PRIMARY KEY,
    inviter_id TEXT,
    email TEXT,
    used_by TEXT,
    created_at TIMESTAMP,
    used_at TIMESTAMP,
    FOREIGN KEY (inviter_id) REFERENCES users(user_id),
    FOREIGN KEY (used_by) REFERENCES users(user_id)
);

CREATE TABLE publish_requests (
    request_id TEXT PRIMARY KEY,
    db_id TEXT,
    user_id TEXT,
    status TEXT DEFAULT 'Pending',
    feedback TEXT,
    submitted_at TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (db_id) REFERENCES databases(db_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE activity_logs (
    log_id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT,
    details TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Insert initial users
INSERT INTO users (user_id, username, password_hash, role, email, created_at) VALUES (
    '550e8400-e29b-41d4-a716-446655440000',
    'admin',
    '$2b$12$WXrVBU6WwiWEA/2E6wZDlOgWVTHNINOJ4KaFNfk6qJSmHryfHp92W',
    'system_admin',
    'admin@example.com',
    '2025-07-21T18:00:00'
);

INSERT INTO users (user_id, username, password_hash, role, email, created_at) VALUES (
    '7a9db897-a52c-4ea9-a618-33779d516d91',
    'user1',
    '$2b$12$8trC/NOv1NS0O5yNjJC6GOANDDO9A52kGwOLZHpzQ3ZwO2XbIuveu    ',
    'system_user',
    'user1@example.com',
    '2025-07-21T18:00:00'
);

-- Insert initial admin_content for index page
INSERT INTO admin_content (section, content, updated_at, updated_by) VALUES (
    'title',
    '{"content": "EDGI Datasette Cloud Portal"}',
    '2025-07-21T18:00:00',
    'admin'
);

INSERT INTO admin_content (section, content, updated_at, updated_by) VALUES (
    'header_image',
    '{"image_url": "/static/header.jpg", "alt_text": "", "credit_url": "", "credit_text": ""}',
    '2025-07-21T18:00:00',
    'admin'
);

INSERT INTO admin_content (section, content, updated_at, updated_by) VALUES (
    'info',
    '{"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.", "paragraphs": ["The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites."]}',
    '2025-07-21T18:00:00',
    'admin'
);