#!/usr/bin/env python3
"""
EDGI Cloud Portal - Database Initialization Script
Updated to support three-tier deletion system with trash bin functionality
"""

import sqlite_utils
import bcrypt
import uuid
import json
import os
from datetime import datetime, timedelta, timezone
import random

# Configuration
PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
DATA_DIR = os.getenv('EDGI_DATA_DIR', "/data")
STATIC_DIR = os.getenv('EDGI_STATIC_DIR', "/static")

def create_database_schema(portal_db):
    """Create all required database tables with enhanced deletion support."""
    print("🗄️ Creating database tables...")
    
    # Users table - unchanged
    portal_db.create_table("users", {
        "user_id": str,
        "username": str,
        "password_hash": str,
        "role": str,
        "email": str,
        "created_at": str
    }, pk="user_id", if_not_exists=True)
    print("   ✅ Created users table")

    # Enhanced databases table with COMPLETE schema
    portal_db.create_table("databases", {
        "db_id": str,                    # Primary key
        "user_id": str,                  # Foreign key to users
        "db_name": str,                  # Database name (must be unique when active)
        "website_url": str,              # Public URL for published databases
        "status": str,                   # Draft, Published, Unpublished, Trashed, Deleted
        "created_at": str,               # ISO timestamp of creation
        "updated_at": str,               # ISO timestamp of last update - ADDED
        "file_path": str,                # Path to SQLite database file
        
        # Three-tier deletion system fields
        "trashed_at": str,               # ISO timestamp when moved to trash
        "restore_deadline": str,         # ISO timestamp for auto-deletion
        "deleted_by_user_id": str,       # User who moved to trash
        "deleted_at": str,               # ISO timestamp of permanent deletion
        "deletion_reason": str,          # Reason for deletion (admin use) - ADDED
    }, pk="db_id", if_not_exists=True)
    print("   ✅ Created databases table (with complete deletion support)")

    # Admin content table
    portal_db.create_table("admin_content", {
        "db_id": str,                    # Database ID (NULL for portal content)
        "section": str,                  # Content section (title, info, footer, header_image)
        "content": str,                  # JSON content
        "updated_at": str,               # ISO timestamp
        "updated_by": str                # Username who updated
    }, pk=("db_id", "section"), if_not_exists=True)
    print("   ✅ Created admin_content table")

    # Enhanced activity logs table with metadata support
    portal_db.create_table("activity_logs", {
        "log_id": str,                   # Primary key
        "user_id": str,                  # User who performed action
        "action": str,                   # Action type
        "details": str,                  # Human-readable description
        "timestamp": str,                # ISO timestamp
        "action_metadata": str           # JSON metadata for enhanced logging
    }, pk="log_id", if_not_exists=True)
    print("   ✅ Created activity_logs table (with metadata support)")

def create_indexes(portal_db):
    """Create database indexes for optimal performance."""
    print("📊 Creating database indexes...")
    
    try:
        # Users table indexes
        portal_db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
        """)
        
        # Databases table indexes
        portal_db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_databases_user_id ON databases(user_id);
            CREATE INDEX IF NOT EXISTS idx_databases_name ON databases(db_name);
            CREATE INDEX IF NOT EXISTS idx_databases_status ON databases(status);
            CREATE INDEX IF NOT EXISTS idx_databases_created_at ON databases(created_at);
            CREATE INDEX IF NOT EXISTS idx_databases_trashed_at ON databases(trashed_at);
            CREATE INDEX IF NOT EXISTS idx_databases_restore_deadline ON databases(restore_deadline);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_databases_name_active 
                ON databases(db_name) WHERE status IN ('Draft', 'Published', 'Unpublished', 'Trashed');
        """)
        
        # Activity logs indexes
        portal_db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON activity_logs(action);
            CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp);
        """)
        
        # Admin content indexes
        portal_db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_admin_content_db_id ON admin_content(db_id);
            CREATE INDEX IF NOT EXISTS idx_admin_content_section ON admin_content(section);
        """)
        
        print("   ✅ Created performance indexes")
        
    except Exception as e:
        print(f"   ⚠️  Warning: Could not create some indexes: {e}")

def create_test_users(portal_db):
    """Create test users for development and testing."""
    print("👥 Creating test users...")
    
    # Test password
    test_password = os.getenv('DEFAULT_PASSWORD', 'edgi2025!')
    hashed_password = bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    users = [
        {
            "user_id": uuid.uuid4().hex[:20],
            "username": "admin",
            "password_hash": hashed_password,
            "role": "system_admin",
            "email": "admin@edgi.org",
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "user_id": uuid.uuid4().hex[:20],
            "username": "researcher",
            "password_hash": hashed_password,
            "role": "system_user",
            "email": "researcher@university.edu",
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "user_id": uuid.uuid4().hex[:20],
            "username": "analyst",
            "password_hash": hashed_password,
            "role": "system_user",
            "email": "analyst@ngo.org",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Insert users
    for user in users:
        try:
            portal_db["users"].insert(user, ignore=True)
            print(f"   ✅ Created user: {user['username']} ({user['role']})")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not create user {user['username']}: {e}")
    
    return users

def create_portal_content(portal_db):
    """Create default portal homepage content."""
    print("🏠 Creating portal homepage content...")
    
    portal_content = [
        {
            "db_id": None,
            "section": "title",
            "content": json.dumps({"content": "EDGI Datasette Cloud Portal"}),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": None,
            "section": "info",
            "content": json.dumps({
                "content": "The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites. Upload CSV files, customize your data portal, and publish environmental data for public access.",
                "paragraphs": [
                    "The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites.",
                    "Upload CSV files, customize your data portal, and publish environmental data for public access."
                ]
            }),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": None,
            "section": "header_image",
            "content": json.dumps({
                "image_url": "/static/default_header.jpg",
                "alt_text": "EDGI Environmental Data Portal",
                "credit_text": "Environmental Data Governance Initiative",
                "credit_url": "https://envirodatagov.org"
            }),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": None,
            "section": "footer",
            "content": json.dumps({
                "content": "Made with ❤️ by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/).",
                "odbl_text": "Data licensed under ODbL",
                "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                "paragraphs": ["Made with ❤️ by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/)."]
            }),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        }
    ]
    
    for content in portal_content:
        try:
            portal_db["admin_content"].insert(content, ignore=True)
            print(f"   ✅ Created portal content: {content['section']}")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not create content {content['section']}: {e}")

def create_sample_databases(portal_db, users):
    """Create sample databases for demonstration (optional)."""
    print("📊 Creating sample databases...")
    
    if not users:
        print("   ⚠️  No users available, skipping sample databases")
        return
    
    # Find a regular user (not admin) for sample databases
    regular_user = next((u for u in users if u['role'] == 'system_user'), users[0])
    
    sample_databases = [
        {
            "db_id": uuid.uuid4().hex[:20],
            "user_id": regular_user['user_id'],
            "db_name": "air_quality_demo",
            "website_url": "/air_quality_demo/",
            "status": "Published",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "file_path": f"{DATA_DIR}/{regular_user['user_id']}/air_quality_demo.db",
            "trashed_at": None,
            "restore_deadline": None,
            "deleted_by_user_id": None,
            "deleted_at": None
        },
        {
            "db_id": uuid.uuid4().hex[:20],
            "user_id": regular_user['user_id'],
            "db_name": "water_monitoring",
            "website_url": "/water_monitoring/",
            "status": "Draft",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "file_path": f"{DATA_DIR}/{regular_user['user_id']}/water_monitoring.db",
            "trashed_at": None,
            "restore_deadline": None,
            "deleted_by_user_id": None,
            "deleted_at": None
        }
    ]
    
    for db_info in sample_databases:
        try:
            portal_db["databases"].insert(db_info, ignore=True)
            print(f"   ✅ Created sample database: {db_info['db_name']} ({db_info['status']})")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not create database {db_info['db_name']}: {e}")

def create_initial_activity_logs(portal_db, users):
    """Create initial activity logs for system startup."""
    print("📝 Creating initial activity logs...")
    
    initial_logs = [
        {
            "log_id": uuid.uuid4().hex[:20],
            "user_id": "system",
            "action": "database_initialization",
            "details": "Portal database initialized with three-tier deletion system",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_metadata": json.dumps({
                "initialization_version": "3.0",
                "features_enabled": ["three_tier_deletion", "trash_bin", "auto_cleanup"],
                "user_count": len(users) if users else 0,
                "database_version": "sqlite3"
            })
        }
    ]
    
    for log_entry in initial_logs:
        try:
            portal_db["activity_logs"].insert(log_entry, ignore=True)
            print(f"   ✅ Created initial log: {log_entry['action']}")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not create log: {e}")

def setup_file_structure():
    """Create necessary directory structure and default files."""
    print("📁 Setting up file structure...")
    
    # Ensure directories exist
    directories = [DATA_DIR, STATIC_DIR, os.path.dirname(PORTAL_DB_PATH)]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"   ✅ Ensured directory: {directory}")
    
    # Create default header image placeholder
    default_header = os.path.join(STATIC_DIR, 'default_header.jpg')
    if not os.path.exists(default_header):
        try:
            # Try to create a simple image with PIL
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new('RGB', (1200, 300), color='#2563eb')
            draw = ImageDraw.Draw(img)
            
            # Try to use a default font
            try:
                font = ImageFont.truetype("arial.ttf", 48)
            except:
                font = ImageFont.load_default()
            
            text = "EDGI Environmental Data Portal"
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = (1200 - text_width) // 2
            y = (300 - text_height) // 2
            
            draw.text((x, y), text, fill='white', font=font)
            img.save(default_header, 'JPEG', quality=95)
            print(f"   ✅ Created default header image: {default_header}")
            
        except ImportError:
            # If PIL not available, create a placeholder file
            with open(default_header, 'w') as f:
                f.write("# EDGI Environmental Data Portal Header Image Placeholder\n")
                f.write("# Replace this file with an actual image (1200x300 recommended)\n")
            print(f"   ✅ Created header placeholder: {default_header}")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not create header image: {e}")

def check_existing_database():
    """Check if database already exists and handle accordingly."""
    if os.path.exists(PORTAL_DB_PATH):
        print(f"📊 Database already exists at: {PORTAL_DB_PATH}")
        
        # Check if this is an old version that needs migration
        try:
            existing_db = sqlite_utils.Database(PORTAL_DB_PATH)
            tables = existing_db.table_names()
            
            if 'databases' in tables:
                # Check if new columns exist
                db_columns = [col.name for col in existing_db['databases'].columns]
                new_columns = ['trashed_at', 'restore_deadline', 'deleted_by_user_id']
                missing_columns = [col for col in new_columns if col not in db_columns]
                
                if missing_columns:
                    print(f"🔄 Database needs migration for three-tier deletion system")
                    print(f"   Missing columns: {missing_columns}")
                    
                    response = input("Do you want to migrate the database? [y/N]: ")
                    if response.lower() == 'y':
                        migrate_database(existing_db)
                        return False  # Continue with rest of initialization
                    else:
                        print("   Skipping migration. Some features may not work.")
                        return True  # Skip initialization
                else:
                    print("✅ Database is up to date")
                    return True  # Skip initialization
            
        except Exception as e:
            print(f"⚠️  Warning: Could not check existing database: {e}")
            response = input("Do you want to continue anyway? [y/N]: ")
            return response.lower() != 'y'
    
    return False  # Database doesn't exist, continue with initialization

def migrate_database(existing_db):
    """Migrate existing database to support three-tier deletion system."""
    print("🔄 Migrating database schema...")
    
    try:
        # Add new columns to databases table
        new_columns = [
            ("trashed_at", "TEXT"),
            ("restore_deadline", "TEXT"), 
            ("deleted_by_user_id", "TEXT")
        ]
        
        for column_name, column_type in new_columns:
            try:
                existing_db.executescript(f"ALTER TABLE databases ADD COLUMN {column_name} {column_type};")
                print(f"   ✅ Added column: databases.{column_name}")
            except Exception as e:
                if "duplicate column name" in str(e).lower():
                    print(f"   ⚪ Column already exists: databases.{column_name}")
                else:
                    print(f"   ⚠️  Warning: Could not add column {column_name}: {e}")
        
        # Add action_metadata column to activity_logs table if it doesn't exist
        try:
            existing_db.executescript("ALTER TABLE activity_logs ADD COLUMN action_metadata TEXT;")
            print(f"   ✅ Added column: activity_logs.action_metadata")
        except Exception as e:
            if "duplicate column name" in str(e).lower():
                print(f"   ⚪ Column already exists: activity_logs.action_metadata")
            else:
                print(f"   ⚠️  Warning: Could not add action_metadata column: {e}")
        
        # Create new indexes
        create_indexes(existing_db)
        
        # Log the migration
        migration_log = {
            "log_id": uuid.uuid4().hex[:20],
            "user_id": "system",
            "action": "database_migration",
            "details": "Migrated database to support three-tier deletion system",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_metadata": json.dumps({
                "migration_version": "3.0",
                "columns_added": [col[0] for col in new_columns],
                "migration_timestamp": datetime.now(timezone.utc).isoformat()
            })
        }
        
        existing_db["activity_logs"].insert(migration_log, ignore=True)
        print("   ✅ Migration completed successfully")
        
    except Exception as e:
        print(f"   ❌ Migration failed: {e}")
        raise

def main():
    """Main initialization function."""
    try:
        print("🌱 Initializing EDGI Cloud Portal Database...")
        print("   Three-tier deletion system enabled")
        print("   Trash bin with 30-day retention")
        print("   Admin override capabilities")
        print("   Enhanced audit logging")
        print()
        
        # Check if database already exists
        if check_existing_database():
            print("✅ Database initialization skipped (already exists)")
            return
        
        # Setup file structure
        setup_file_structure()
        
        print(f"🗄️  Creating portal database at: {PORTAL_DB_PATH}")
        
        # Create portal database
        portal_db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        # Create schema
        create_database_schema(portal_db)
        
        # Create indexes
        create_indexes(portal_db)
        
        # Create test users
        users = create_test_users(portal_db)
        
        # Create portal content
        create_portal_content(portal_db)
        
        # Create sample databases (optional)
        create_sample_databases(portal_db, users)
        
        # Create initial activity logs
        create_initial_activity_logs(portal_db, users)
        
        # Final setup information
        test_password = os.getenv('DEFAULT_PASSWORD', 'edgi2025!')
        
        print()
        print("✅ Database initialization complete!")
        print(f"📊 Database created at: {PORTAL_DB_PATH}")
        print()
        print("🔐 Test Login Credentials:")
        print(f"   Admin: admin / {test_password} (System Administrator)")
        print(f"   User:  researcher / {test_password} (Regular User)")
        print(f"   User:  analyst / {test_password} (Regular User)")
        print()
        print("🗂️  Directory Structure:")
        print(f"   Portal DB: {PORTAL_DB_PATH}")
        print(f"   Data Dir:  {DATA_DIR}")
        print(f"   Static Dir: {STATIC_DIR}")
        print()
        print("🚀 Features Enabled:")
        print("   ✅ Three-tier deletion system (Unpublish → Trash → Delete)")
        print("   ✅ 30-day trash retention with auto-cleanup")
        print("   ✅ Name collision prevention")
        print("   ✅ Admin override capabilities")
        print("   ✅ Enhanced audit logging with metadata")
        print("   ✅ User self-restore functionality")
        print()
        print("Next steps:")
        print("1. Start Datasette with your plugin")
        print("2. Navigate to http://localhost:8001")
        print("3. Login with the credentials above")
        print("4. Create your first environmental database!")
        
    except Exception as e:
        print(f"❌ ERROR: Database initialization failed!")
        print(f"Error details: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    main()