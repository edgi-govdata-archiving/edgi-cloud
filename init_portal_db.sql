-- Portal Database Setup Script (Updated for Separation)
-- Creates portal.db with test data
-- Uses admin_content for global portal content (db_id = NULL, editable by system_admin)
-- New web_content for user database-specific content (db_id FK to databases, editable by user)

-- Create Users table
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('system_admin', 'system_user')),
    email TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);

-- Create Databases table
CREATE TABLE IF NOT EXISTS databases (
    db_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    db_name TEXT UNIQUE NOT NULL,
    website_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Draft', 'Published', 'Deleted')),
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create Admin Content Table (global portal content only, db_id = NULL)
CREATE TABLE IF NOT EXISTS admin_content (
    db_id TEXT CHECK (db_id IS NULL),  -- Must be NULL for global content
    section TEXT NOT NULL,
    content TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (db_id, section)  -- Composite PK allows NULL db_id
);

-- Create Web Content Table (user database-specific content)
CREATE TABLE IF NOT EXISTS web_content (
    db_id TEXT NOT NULL,
    section TEXT NOT NULL,
    content TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (db_id, section),
    FOREIGN KEY (db_id) REFERENCES databases(db_id) ON DELETE CASCADE
);

-- Create Activity Logs table
CREATE TABLE IF NOT EXISTS activity_logs (
    log_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Insert test users
-- Password for all users is "123456"
-- Hash: $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdqxJkB.6WsLQ6G
INSERT INTO users (user_id, username, password_hash, role, email, created_at) VALUES 
('7a9db897-a52c-4ea9-a618-33779d516d92', 'user1', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdqxJkB.6WsLQ6G', 'system_user', 'user1@example.com', '2024-01-15 10:30:00'),
('8b2ec998-b63d-5fb0-b719-44880e627e03', 'user2', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdqxJkB.6WsLQ6G', 'system_user', 'user2@example.com', '2024-01-16 11:45:00'),
('9c3fd099-c74e-6gc1-c81a-55991f738f14', 'admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdqxJkB.6WsLQ6G', 'system_admin', 'admin@example.com', '2024-01-10 09:00:00'),
('ad4fe19a-d85f-7hd2-d92b-666a20849025', 'user3', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdqxJkB.6WsLQ6G', 'system_user', 'user3@example.com', '2024-01-20 14:20:00');

-- Insert test databases (removed archived status)
INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at, deleted_at) VALUES 
-- User1 databases
('d1e2f3a4-5678-9012-b345-c678d9012345', '7a9db897-a52c-4ea9-a618-33779d516d92', 'air_quality', '/air_quality/', 'Draft', '2024-01-15 11:00:00', NULL),
('d1e2f3a4-5678-9012-b345-c678d9012346', '7a9db897-a52c-4ea9-a618-33779d516d92', 'water_quality', '/water_quality/', 'Published', '2024-01-16 12:00:00', NULL),
('0fd26236-867d-4bac-8e07-56015069fba2', '7a9db897-a52c-4ea9-a618-33779d516d92', 'soil_data', '/soil_data/', 'Deleted', '2024-01-17 13:00:00', '2024-01-25 10:00:00'),

-- User2 databases  
('e2f3a4b5-6789-0123-c456-d789e0123456', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'biodiversity', '/biodiversity/', 'Published', '2024-01-17 15:00:00', NULL),
('f3a4b5c6-7890-1234-d567-e890f1234567', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'emissions', '/emissions/', 'Draft', '2024-01-18 16:00:00', NULL),

-- User3 databases
('a4b5c6d7-8901-2345-e678-f901a2345678', 'ad4fe19a-d85f-7hd2-d92b-666a20849025', 'energy_consumption', '/energy_consumption/', 'Published', '2024-01-20 17:00:00', NULL);

-- Insert portal-wide admin content (db_id = NULL)
INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES 
(NULL, 'title', '{"content": "EDGI Datasette Cloud Portal"}', '2024-01-10 09:00:00', 'system'),
(NULL, 'header_image', '{"image_url": "/static/header.jpg", "alt_text": "EDGI Portal Header", "credit_url": "", "credit_text": ""}', '2024-01-10 09:00:00', 'system'),
(NULL, 'info', '{"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites. Upload your CSV data and create beautiful, searchable databases.", "paragraphs": ["The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.", "Upload your CSV data and create beautiful, searchable databases."]}', '2024-01-10 09:00:00', 'system');

-- Insert database-specific web content
-- Air Quality database content (Draft)
INSERT INTO web_content (db_id, section, content, updated_at, updated_by) VALUES 
('d1e2f3a4-5678-9012-b345-c678d9012345', 'title', '{"content": "Air Quality Monitoring"}', '2024-01-15 11:00:00', 'user1'),
('d1e2f3a4-5678-9012-b345-c678d9012345', 'description', '{"content": "Real-time air quality monitoring data from stations across the region."}', '2024-01-15 11:00:00', 'user1'),
('d1e2f3a4-5678-9012-b345-c678d9012345', 'footer', '{"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}', '2024-01-15 11:00:00', 'user1'),

-- Water Quality database content (Published)
('d1e2f3a4-5678-9012-b345-c678d9012346', 'title', '{"content": "Water Quality Monitoring Data"}', '2024-01-16 12:00:00', 'user1'),
('d1e2f3a4-5678-9012-b345-c678d9012346', 'description', '{"content": "Comprehensive water quality measurements from monitoring stations across the region, including pH, dissolved oxygen, temperature, and pollutant levels."}', '2024-01-16 12:00:00', 'user1'),
('d1e2f3a4-5678-9012-b345-c678d9012346', 'header_image', '{"image_url": "/static/header.jpg", "alt_text": "Water Quality Monitoring", "credit_text": "Environmental Data Portal", "credit_url": ""}', '2024-01-16 12:00:00', 'user1'),
('d1e2f3a4-5678-9012-b345-c678d9012346', 'footer', '{"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}', '2024-01-16 12:00:00', 'user1'),

-- Biodiversity database content (Published)
('e2f3a4b5-6789-0123-c456-d789e0123456', 'title', '{"content": "Regional Biodiversity Survey"}', '2024-01-17 15:00:00', 'user2'),
('e2f3a4b5-6789-0123-c456-d789e0123456', 'description', '{"content": "Species observation data from biodiversity surveys conducted in protected areas and urban environments."}', '2024-01-17 15:00:00', 'user2'),
('e2f3a4b5-6789-0123-c456-d789e0123456', 'footer', '{"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}', '2024-01-17 15:00:00', 'user2'),

-- Energy Consumption database content (Published)
('a4b5c6d7-8901-2345-e678-f901a2345678', 'title', '{"content": "Municipal Energy Consumption Analysis"}', '2024-01-20 17:00:00', 'user3'),
('a4b5c6d7-8901-2345-e678-f901a2345678', 'description', '{"content": "Monthly energy consumption data by sector including residential, commercial, and industrial usage patterns."}', '2024-01-20 17:00:00', 'user3'),
('a4b5c6d7-8901-2345-e678-f901a2345678', 'footer', '{"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}', '2024-01-20 17:00:00', 'user3'),

-- Emissions database content (Draft)
('f3a4b5c6-7890-1234-d567-e890f1234567', 'title', '{"content": "Emissions Monitoring"}', '2024-01-18 16:00:00', 'user2'),
('f3a4b5c6-7890-1234-d567-e890f1234567', 'description', '{"content": "CO2 and greenhouse gas emissions monitoring from various facilities."}', '2024-01-18 16:00:00', 'user2'),
('f3a4b5c6-7890-1234-d567-e890f1234567', 'footer', '{"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}', '2024-01-18 16:00:00', 'user2');

-- Insert activity logs
INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES 
('log001', '9c3fd099-c74e-6gc1-c81a-55991f738f14', 'register', 'User admin registered', '2024-01-10 09:00:00'),
('log002', '7a9db897-a52c-4ea9-a618-33779d516d92', 'register', 'User user1 registered', '2024-01-15 10:30:00'),
('log003', '7a9db897-a52c-4ea9-a618-33779d516d92', 'create_database', 'Created database air_quality', '2024-01-15 11:00:00'),
('log004', '7a9db897-a52c-4ea9-a618-33779d516d92', 'add_table', 'Added table monitoring_stations to database air_quality', '2024-01-15 11:30:00'),
('log005', '7a9db897-a52c-4ea9-a618-33779d516d92', 'add_table', 'Added table air_quality_data to database air_quality', '2024-01-15 12:00:00'),
('log006', '7a9db897-a52c-4ea9-a618-33779d516d92', 'create_database', 'Created database water_quality', '2024-01-16 12:00:00'),
('log007', '7a9db897-a52c-4ea9-a618-33779d516d92', 'add_table', 'Added table water_samples to database water_quality', '2024-01-16 12:15:00'),
('log008', '7a9db897-a52c-4ea9-a618-33779d516d92', 'publish_database', 'Published database water_quality', '2024-01-16 12:30:00'),
('log009', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'register', 'User user2 registered', '2024-01-16 11:45:00'),
('log010', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'create_database', 'Created database biodiversity', '2024-01-17 15:00:00'),
('log011', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'add_table', 'Added table species_observations to database biodiversity', '2024-01-17 15:15:00'),
('log012', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'publish_database', 'Published database biodiversity', '2024-01-17 15:30:00'),
('log013', '7a9db897-a52c-4ea9-a618-33779d516d92', 'create_database', 'Created database soil_data', '2024-01-17 13:00:00'),
('log014', '7a9db897-a52c-4ea9-a618-33779d516d92', 'delete_database', 'Deleted database soil_data', '2024-01-25 10:00:00'),
('log015', 'ad4fe19a-d85f-7hd2-d92b-666a20849025', 'register', 'User user3 registered', '2024-01-20 14:20:00'),
('log016', 'ad4fe19a-d85f-7hd2-d92b-666a20849025', 'create_database', 'Created database energy_consumption', '2024-01-20 17:00:00'),
('log017', 'ad4fe19a-d85f-7hd2-d92b-666a20849025', 'add_table', 'Added table monthly_usage to database energy_consumption', '2024-01-20 17:15:00'),
('log018', 'ad4fe19a-d85f-7hd2-d92b-666a20849025', 'publish_database', 'Published database energy_consumption', '2024-01-20 17:30:00'),
('log019', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'create_database', 'Created database emissions', '2024-01-18 16:00:00'),
('log020', '8b2ec998-b63d-5fb0-b719-44880e627e03', 'add_table', 'Added table co2_measurements to database emissions', '2024-01-18 16:15:00');

-- Create sample data tables for testing
-- Air Quality Database Tables (Draft)
CREATE TABLE IF NOT EXISTS air_quality_monitoring_stations (
    station_id INTEGER PRIMARY KEY,
    station_name TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    location_type TEXT NOT NULL,
    installation_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS air_quality_data (
    measurement_id INTEGER PRIMARY KEY,
    station_id INTEGER NOT NULL,
    measurement_date TEXT NOT NULL,
    pm25 REAL,
    pm10 REAL,
    ozone REAL,
    no2 REAL,
    so2 REAL,
    aqi INTEGER,
    FOREIGN KEY (station_id) REFERENCES air_quality_monitoring_stations(station_id)
);

-- Water Quality Database Tables (Published)
CREATE TABLE IF NOT EXISTS water_quality_water_samples (
    sample_id INTEGER PRIMARY KEY,
    site_name TEXT NOT NULL,
    sample_date TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    ph_level REAL,
    dissolved_oxygen REAL,
    temperature REAL,
    turbidity REAL,
    nitrates REAL,
    phosphates REAL,
    water_quality_index INTEGER
);

-- Biodiversity Database Tables (Published)
CREATE TABLE IF NOT EXISTS biodiversity_species_observations (
    observation_id INTEGER PRIMARY KEY,
    species_name TEXT NOT NULL,
    common_name TEXT,
    observation_date TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    habitat_type TEXT,
    abundance_count INTEGER,
    observer_name TEXT,
    conservation_status TEXT
);

-- Energy Consumption Database Tables (Published)
CREATE TABLE IF NOT EXISTS energy_consumption_monthly_usage (
    usage_id INTEGER PRIMARY KEY,
    reporting_month TEXT NOT NULL,
    sector TEXT NOT NULL,
    energy_type TEXT NOT NULL,
    consumption_mwh REAL NOT NULL,
    cost_usd REAL,
    co2_emissions_tons REAL
);

-- Emissions Database Tables (Draft)
CREATE TABLE IF NOT EXISTS emissions_co2_measurements (
    measurement_id INTEGER PRIMARY KEY,
    facility_name TEXT NOT NULL,
    measurement_date TEXT NOT NULL,
    co2_emissions_tons REAL NOT NULL,
    methane_emissions_tons REAL,
    facility_type TEXT,
    latitude REAL,
    longitude REAL
);

-- Insert sample data
INSERT INTO air_quality_monitoring_stations VALUES 
(1, 'Downtown Monitor', 42.3314, -85.5811, 'Urban', '2023-01-15'),
(2, 'Suburban Station', 42.3150, -85.5750, 'Suburban', '2023-02-01'),
(3, 'Industrial Area', 42.3400, -85.6000, 'Industrial', '2023-03-01');

INSERT INTO air_quality_data VALUES 
(1, 1, '2024-01-15 08:00:00', 25.5, 45.2, 65.1, 35.8, 15.2, 85),
(2, 1, '2024-01-15 12:00:00', 30.2, 52.1, 72.3, 42.1, 18.5, 95),
(3, 2, '2024-01-15 08:00:00', 18.3, 35.7, 55.2, 28.4, 12.1, 70),
(4, 2, '2024-01-15 12:00:00', 22.1, 40.8, 60.5, 32.7, 14.8, 78),
(5, 3, '2024-01-15 08:00:00', 45.8, 78.9, 85.6, 68.2, 32.4, 125);

INSERT INTO water_quality_water_samples VALUES 
(1, 'Kalamazoo River - Main St', '2024-01-15', 42.2917, -85.5872, 7.2, 8.5, 4.2, 15.2, 2.1, 0.8, 82),
(2, 'Portage Creek - Stadium Dr', '2024-01-15', 42.3014, -85.5678, 6.8, 7.8, 3.8, 18.5, 2.8, 1.2, 76),
(3, 'Asylum Lake', '2024-01-15', 42.2456, -85.6123, 7.5, 9.2, 5.1, 8.2, 1.5, 0.5, 92),
(4, 'Galesburg Pond', '2024-01-15', 42.2889, -85.4267, 7.1, 8.1, 4.8, 12.8, 2.3, 0.9, 85);

INSERT INTO biodiversity_species_observations VALUES 
(1, 'Turdus migratorius', 'American Robin', '2024-01-15', 42.3314, -85.5811, 'Urban Park', 12, 'Jane Smith', 'Least Concern'),
(2, 'Sciurus carolinensis', 'Eastern Gray Squirrel', '2024-01-15', 42.3150, -85.5750, 'Suburban', 8, 'John Doe', 'Least Concern'),
(3, 'Quercus alba', 'White Oak', '2024-01-15', 42.2456, -85.6123, 'Forest', 25, 'Bob Wilson', 'Stable'),
(4, 'Rana clamitans', 'Green Frog', '2024-01-15', 42.2917, -85.5872, 'Wetland', 6, 'Alice Johnson', 'Stable');

INSERT INTO energy_consumption_monthly_usage VALUES 
(1, '2024-01', 'Residential', 'Electricity', 1250.5, 125000, 625.25),
(2, '2024-01', 'Commercial', 'Electricity', 2840.2, 284000, 1420.1),
(3, '2024-01', 'Industrial', 'Electricity', 4560.8, 456000, 2280.4),
(4, '2024-01', 'Residential', 'Natural Gas', 980.3, 98000, 490.15),
(5, '2024-01', 'Commercial', 'Natural Gas', 1650.7, 165000, 825.35);

INSERT INTO emissions_co2_measurements VALUES 
(1, 'Kalamazoo Power Plant', '2024-01-15', 245.8, 12.3, 'Power Generation', 42.3100, -85.5900),
(2, 'Industrial Complex A', '2024-01-15', 156.2, 8.7, 'Manufacturing', 42.3400, -85.6000),
(3, 'Waste Treatment Facility', '2024-01-15', 89.5, 25.1, 'Waste Management', 42.2800, -85.5600);