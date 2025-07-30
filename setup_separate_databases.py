#!/usr/bin/env python3
"""
EDGI Portal Setup Script for Separate SQLite Databases
Run this script to set up the new file-based database system.
"""

import os
import sqlite3
import sqlite_utils
import shutil
from pathlib import Path
import json
from datetime import datetime

# Configuration
BASE_PATH = r"C:\MS Data Science - WMU\EDGI\edgi-cloud"
DATA_PATH = os.path.join(BASE_PATH, "data")
PORTAL_DB_PATH = os.path.join(BASE_PATH, "portal.db")

def create_directory_structure():
    """Create the required directory structure."""
    print("Creating directory structure...")
    
    directories = [
        DATA_PATH,
        os.path.join(DATA_PATH, "shared"),
        os.path.join(BASE_PATH, "uploads"),
        os.path.join(BASE_PATH, "uploads", "temp"),
        os.path.join(BASE_PATH, "static"),
        os.path.join(BASE_PATH, "static", "js"),
        os.path.join(BASE_PATH, "plugins"),
        os.path.join(BASE_PATH, "templates")
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"  ✓ Created: {directory}")

def create_static_files():
    """Create required static files."""
    print("Creating static files...")
    
    # Create basic CSS file
    css_content = """/* EDGI Portal Styles */
body {
  font-family: Arial, sans-serif;
  background-color: #F7F7F7;
  color: #333;
}

.map-container {
  width: 100%;
  height: 350px;
  overflow: hidden;
  position: relative;
  border: 1px solid #CCC;
}

.map-image {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

th, td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid #CCC;
}

th {
  background-color: #0071BC;
  color: white;
}

tr:hover {
  background-color: #F5F5F5;
}

.custom-file-input {
  position: relative;
  display: inline-block;
  cursor: pointer;
}

.custom-file-input input[type=file] {
  position: absolute;
  opacity: 0;
  width: 100%;
  height: 100%;
  cursor: pointer;
}

.custom-file-input label {
  display: inline-block;
  padding: 8px 16px;
  background-color: #0071BC;
  color: white;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.3s;
}

.custom-file-input label:hover {
  background-color: #1A4480;
}

@media (max-width: 600px) {
  th, td {
    font-size: 0.9rem;
    padding: 0.5rem;
  }
  
  .map-container {
    height: 250px;
  }
}"""
    
    css_path = os.path.join(BASE_PATH, "static", "styles.css")
    with open(css_path, 'w') as f:
        f.write(css_content)
    print(f"  ✓ Created: {css_path}")
    
    # Create Tailwind config
    tailwind_config = """tailwind.config = {
  theme: {
    extend: {
      colors: {
        header: '#005EA2',
        primary: '#1A4480',
        accent: '#0071BC',
        background: '#F7F7F7',
        card: '#FFFFFF',
        border: '#CCCCCC',
        text: '#333333',
        textlight: '#666666'
      },
      borderRadius: {
        button: '8px',
        card: '0px'
      }
    }
  }
};"""
    
    tailwind_path = os.path.join(BASE_PATH, "static", "js", "tailwind.config.js")
    with open(tailwind_path, 'w') as f:
        f.write(tailwind_config)
    print(f"  ✓ Created: {tailwind_path}")
    
    # Create placeholder header image (you'll need to replace this with actual image)
    header_path = os.path.join(BASE_PATH, "static", "header.jpg")
    if not os.path.exists(header_path):
        print(f"  ! Please add a header image at: {header_path}")
        print(f"    You can use any environmental image (1200x350px recommended)")

def update_portal_database():
    """Update the portal database schema for separate files."""
    print("Updating portal database schema...")
    
    db = sqlite_utils.Database(PORTAL_DB_PATH)
    
    # Create enhanced schema
    print("  ✓ Creating/updating tables...")
    
    # Users table
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('system_admin', 'system_user')),
            email TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    
    # Enhanced databases table
    db.executescript("""
        CREATE TABLE IF NOT EXISTS databases_new (
            db_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            db_name TEXT UNIQUE NOT NULL,
            website_url TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('Draft', 'Published', 'Deleted')),
            created_at TEXT NOT NULL,
            deleted_at TEXT,
            database_type TEXT DEFAULT 'sqlite',
            is_public INTEGER DEFAULT 0,
            file_path TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );
        
        -- Migrate existing data if databases table exists
        INSERT OR IGNORE INTO databases_new 
        SELECT db_id, user_id, db_name, website_url, status, created_at, deleted_at,
               'sqlite' as database_type, 0 as is_public, NULL as file_path
        FROM databases WHERE EXISTS (SELECT name FROM sqlite_master WHERE type='table' AND name='databases');
        
        DROP TABLE IF EXISTS databases;
        ALTER TABLE databases_new RENAME TO databases;
    """)
    
    # New tables for file management
    db.executescript("""
        CREATE TABLE IF NOT EXISTS admin_content (
            db_id TEXT,
            section TEXT NOT NULL,
            content TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            PRIMARY KEY (db_id, section)
        );
        
        CREATE TABLE IF NOT EXISTS database_configs (
            db_id TEXT NOT NULL,
            config_key TEXT NOT NULL,
            config_value TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (db_id, config_key),
            FOREIGN KEY (db_id) REFERENCES databases(db_id)
        );
        
        CREATE TABLE IF NOT EXISTS database_files (
            db_id TEXT PRIMARY KEY,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            table_count INTEGER DEFAULT 0,
            last_modified TEXT,
            FOREIGN KEY (db_id) REFERENCES databases(db_id)
        );
        
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );
    """)

def create_test_data():
    """Create test data with file-based databases."""
    print("Creating test data...")
    
    db = sqlite_utils.Database(PORTAL_DB_PATH)
    
    # Insert test users (password is "123456" for all)
    test_users = [
        {
            'user_id': '7a9db897-a52c-4ea9-a618-33779d516d92',
            'username': 'user1',
            'password_hash': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdqxJkB.6WsLQ6G',
            'role': 'system_user',
            'email': 'user1@example.com',
            'created_at': '2024-01-15 10:30:00'
        },
        {
            'user_id': '9c3fd099-c74e-6gc1-c81a-55991f738f14',
            'username': 'admin',
            'password_hash': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdqxJkB.6WsLQ6G',
            'role': 'system_admin',
            'email': 'admin@example.com',
            'created_at': '2024-01-10 09:00:00'
        }
    ]
    
    for user in test_users:
        db.execute("""
            INSERT OR IGNORE INTO users 
            (user_id, username, password_hash, role, email, created_at) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, [user['user_id'], user['username'], user['password_hash'], 
              user['role'], user['email'], user['created_at']])
        
        # Create user directory
        user_dir = os.path.join(DATA_PATH, user['username'])
        os.makedirs(user_dir, exist_ok=True)
        print(f"  ✓ Created user directory: {user_dir}")
    
    # Insert global admin content
    global_content = [
        ('title', {"content": "EDGI Datasette Cloud Portal"}),
        ('header_image', {"image_url": "/static/header.jpg", "alt_text": "EDGI Portal Header", "credit_url": "", "credit_text": ""}),
        ('info', {"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites. Upload your CSV data and create beautiful, searchable databases.", "paragraphs": ["The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.", "Upload your CSV data and create beautiful, searchable databases."]}),
        ('footer', {"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]})
    ]
    
    for section, content_data in global_content:
        db.execute("""
            INSERT OR REPLACE INTO admin_content 
            (db_id, section, content, updated_at, updated_by) 
            VALUES (?, ?, ?, ?, ?)
        """, [None, section, json.dumps(content_data), datetime.now().isoformat(), "system"])
    
    print("  ✓ Inserted global content")

def create_sample_database():
    """Create a sample database with test data."""
    print("Creating sample database...")
    
    # Create sample database file
    user_dir = os.path.join(DATA_PATH, "user1")
    sample_db_path = os.path.join(user_dir, "water_quality.db")
    
    sample_db = sqlite_utils.Database(sample_db_path)
    
    # Create metadata table
    sample_db.execute("""
        CREATE TABLE IF NOT EXISTS _database_metadata (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        )
    """)
    
    # Insert metadata
    metadata = {
        'created_at': datetime.now().isoformat(),
        'version': '1.0',
        'type': 'environmental_data'
    }
    
    for key, value in metadata.items():
        sample_db.execute(
            "INSERT OR REPLACE INTO _database_metadata (key, value, updated_at) VALUES (?, ?, ?)",
            [key, str(value), datetime.now().isoformat()]
        )
    
    # Create sample data table
    sample_data = [
        {
            'sample_id': 1,
            'site_name': 'Kalamazoo River - Main St',
            'sample_date': '2024-01-15',
            'latitude': 42.2917,
            'longitude': -85.5872,
            'ph_level': 7.2,
            'dissolved_oxygen': 8.5,
            'temperature': 4.2,
            'water_quality_index': 82
        },
        {
            'sample_id': 2,
            'site_name': 'Portage Creek - Stadium Dr',
            'sample_date': '2024-01-15',
            'latitude': 42.3014,
            'longitude': -85.5678,
            'ph_level': 6.8,
            'dissolved_oxygen': 7.8,
            'temperature': 3.8,
            'water_quality_index': 76
        },
        {
            'sample_id': 3,
            'site_name': 'Asylum Lake',
            'sample_date': '2024-01-15',
            'latitude': 42.2456,
            'longitude': -85.6123,
            'ph_level': 7.5,
            'dissolved_oxygen': 9.2,
            'temperature': 5.1,
            'water_quality_index': 92
        }
    ]
    
    sample_db['water_samples'].insert_all(sample_data)
    
    # Register in portal database
    portal_db = sqlite_utils.Database(PORTAL_DB_PATH)
    
    db_id = 'd1e2f3a4-5678-9012-b345-c678d9012346'
    portal_db.execute("""
        INSERT OR REPLACE INTO databases 
        (db_id, user_id, db_name, website_url, status, created_at, file_path) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, [
        db_id,
        '7a9db897-a52c-4ea9-a618-33779d516d92',  # user1
        'water_quality',
        'http://127.0.0.1:8001/water_quality/',
        'Published',
        '2024-01-16 12:00:00',
        sample_db_path
    ])
    
    # Add database content
    database_content = [
        ('title', {"content": "Water Quality Monitoring Data"}),
        ('description', {"content": "Comprehensive water quality measurements from monitoring stations across the region, including pH, dissolved oxygen, temperature, and water quality indices."}),
        ('header_image', {"image_url": "/static/header.jpg", "alt_text": "Water Quality Monitoring", "credit_text": "Environmental Data Portal", "credit_url": ""}),
        ('footer', {"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]})
    ]
    
    for section, content_data in database_content:
        portal_db.execute("""
            INSERT OR REPLACE INTO admin_content 
            (db_id, section, content, updated_at, updated_by) 
            VALUES (?, ?, ?, ?, ?)
        """, [db_id, section, json.dumps(content_data), datetime.now().isoformat(), "user1"])
    
    print(f"  ✓ Created sample database: {sample_db_path}")
    print(f"  ✓ Added {len(sample_data)} sample records")

def create_metadata_yaml():
    """Create Datasette metadata configuration."""
    print("Creating Datasette metadata configuration...")
    
    metadata_content = """title: EDGI Datasette Cloud Portal
description: Environmental Data Governance Initiative - Cloud Portal
source: EDGI
source_url: https://envirodatagov.org
license: ODbL
license_url: https://opendatacommons.org/licenses/odbl/

databases:
  portal:
    title: Portal Database
    description: Main portal configuration and user data

settings:
  default_page_size: 100
  max_returned_rows: 1000
  num_sql_threads: 3
  allow_download: true
  allow_facet: true
  allow_raw_sql: false

extra_css_urls:
  - /static/styles.css
  
extra_js_urls:
  - /static/js/tailwind.config.js

plugins:
  datasette-admin-panel:
    portal_db_path: portal.db
"""
    
    metadata_path = os.path.join(BASE_PATH, "metadata.yaml")
    with open(metadata_path, 'w') as f:
        f.write(metadata_content)
    print(f"  ✓ Created: {metadata_path}")

def create_startup_script():
    """Create a startup script for the portal."""
    print("Creating startup script...")
    
    startup_content = """#!/usr/bin/env python3
\"\"\"
EDGI Portal Startup Script
Run this to start the portal with the new file-based database system.
\"\"\"

import os
import subprocess
import sys

BASE_PATH = r"C:\\MS Data Science - WMU\\EDGI\\edgi-cloud"
PORTAL_DB = os.path.join(BASE_PATH, "portal.db")

def main():
    print("Starting EDGI Datasette Cloud Portal...")
    
    # Change to the correct directory
    os.chdir(BASE_PATH)
    
    # Verify required files exist
    required_files = [
        "portal.db",
        "plugins/datasette_admin_panel.py",
        "static/styles.css",
        "templates/index.html"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print("❌ Missing required files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("\\nPlease run setup_separate_databases.py first.")
        return
    
    print("✅ All required files found")
    print("🚀 Starting Datasette...")
    
    # Start Datasette
    cmd = [
        sys.executable, "-m", "datasette",
        "portal.db",
        "--host", "127.0.0.1",
        "--port", "8001",
        "--reload",
        "--plugins-dir", "plugins",
        "--static", "static:static",
        "--template-dir", "templates"
    ]
    
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\\n👋 Portal stopped")
    except Exception as e:
        print(f"❌ Error starting portal: {e}")

if __name__ == "__main__":
    main()
"""
    
    startup_path = os.path.join(BASE_PATH, "start_portal.py")
    with open(startup_path, 'w') as f:
        f.write(startup_content)
    print(f"  ✓ Created: {startup_path}")

def print_next_steps():
    """Print next steps for the user."""
    print("\n" + "="*60)
    print("🎉 SETUP COMPLETE!")
    print("="*60)
    print("\nNext steps:")
    print("1. Copy the updated datasette_admin_panel.py to:")
    print(f"   {os.path.join(BASE_PATH, 'plugins', 'datasette_admin_panel.py')}")
    print("\n2. Copy all HTML templates to:")
    print(f"   {os.path.join(BASE_PATH, 'templates')}")
    print("   Required templates:")
    print("   - index.html")
    print("   - login.html") 
    print("   - register.html")
    print("   - change_password.html")
    print("   - create_database.html")
    print("   - manage_databases.html (use the updated version)")
    print("   - template.html (new file)")
    print("   - dashboard.html")
    print("   - system_admin.html")
    print("   - database_homepage.html")
    print("   - database_tables.html")
    print("   - database_table.html")
    print("\n3. Add a header image:")
    print(f"   {os.path.join(BASE_PATH, 'static', 'header.jpg')}")
    print("   (1200x350px recommended)")
    print("\n4. Start the portal:")
    print(f"   cd \"{BASE_PATH}\"")
    print("   python start_portal.py")
    print("\n5. Test login credentials:")
    print("   Username: admin, Password: 123456 (system_admin)")
    print("   Username: user1, Password: 123456 (system_user)")
    print("\n6. Access the portal at:")
    print("   http://127.0.0.1:8001")
    print("\n" + "="*60)

def main():
    """Run the complete setup process."""
    print("EDGI Portal Setup - Separate SQLite Databases")
    print("=" * 50)
    
    try:
        create_directory_structure()
        create_static_files()
        update_portal_database()
        create_test_data()
        create_sample_database()
        create_metadata_yaml()
        create_startup_script()
        print_next_steps()
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        print("Please check the error and try again.")
        return False
    
    return True

if __name__ == "__main__":
    main()