#!/usr/bin/env python3
"""
EDGI Cloud Portal - Database Initialization Script
Enhanced with system settings, blocked domains, and improved schema
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
DATA_DIR = os.getenv('RESETTE_DATA_DIR', "/data")
STATIC_DIR = os.getenv('RESETTE_STATIC_DIR', "/static")

def create_database_schema(portal_db):
    """Create all required database tables with complete schema."""
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
        "updated_at": str,               # ISO timestamp of last update
        "file_path": str,                # Path to SQLite database file
        
        # Three-tier deletion system fields
        "trashed_at": str,               # ISO timestamp when moved to trash
        "restore_deadline": str,         # ISO timestamp for auto-deletion
        "deleted_by_user_id": str,       # User who moved to trash
        "deleted_at": str,               # ISO timestamp of permanent deletion
        "deletion_reason": str,          # Reason for deletion (admin use)
    }, pk="db_id", if_not_exists=True)
    print("   ✅ Created databases table (with complete deletion support)")

    # System settings table - NEW
    portal_db.create_table("system_settings", {
        "setting_key": str,              # Primary key (unique setting name)
        "setting_value": str,            # Setting value (stored as string)
        "updated_at": str,               # ISO timestamp of last update
        "updated_by": str                # Username who updated the setting
    }, pk="setting_key", if_not_exists=True)
    print("   ✅ Created system_settings table")

    # Blocked domains table - NEW
    portal_db.create_table("blocked_domains", {
        "domain": str,                   # Primary key (domain name)
        "created_at": str,               # ISO timestamp when blocked
        "created_by": str                # Admin username who blocked it
    }, pk="domain", if_not_exists=True)
    print("   ✅ Created blocked_domains table")

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

def create_system_settings(portal_db):
    """Create default system settings."""
    print("⚙️ Creating system settings...")
    
    current_time = datetime.now(timezone.utc).isoformat()
    
    default_settings = [
        {
            "setting_key": "trash_retention_days",
            "setting_value": "30",
            "updated_at": current_time,
            "updated_by": "system_init"
        },
        {
            "setting_key": "max_databases_per_user",
            "setting_value": "10",
            "updated_at": current_time,
            "updated_by": "system_init"
        },
        {
            "setting_key": "max_file_size",
            "setting_value": str(50 * 1024 * 1024),  # 50MB in bytes
            "updated_at": current_time,
            "updated_by": "system_init"
        },
        {
            "setting_key": "max_img_size",
            "setting_value": str(5 * 1024 * 1024),   # 5MB in bytes
            "updated_at": current_time,
            "updated_by": "system_init"
        },
        {
            "setting_key": "allowed_extensions",
            "setting_value": ".jpg,.jpeg,.png,.csv,.xls,.xlsx,.txt,.db,.sqlite,.sqlite3",
            "updated_at": current_time,
            "updated_by": "system_init"
        },
        {
            "setting_key": "portal_version",
            "setting_value": "3.0.0",
            "updated_at": current_time,
            "updated_by": "system_init"
        },
        {
            "setting_key": "maintenance_mode",
            "setting_value": "false",
            "updated_at": current_time,
            "updated_by": "system_init"
        }
    ]
    
    for setting in default_settings:
        try:
            portal_db["system_settings"].insert(setting, ignore=True)
            print(f"   ✅ Created setting: {setting['setting_key']} = {setting['setting_value']}")
        except Exception as e:
            print(f"   ⚠️ Warning: Could not create setting {setting['setting_key']}: {e}")

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
            CREATE INDEX IF NOT EXISTS idx_databases_updated_at ON databases(updated_at);
            CREATE INDEX IF NOT EXISTS idx_databases_trashed_at ON databases(trashed_at);
            CREATE INDEX IF NOT EXISTS idx_databases_restore_deadline ON databases(restore_deadline);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_databases_name_active 
                ON databases(db_name) WHERE status IN ('Draft', 'Published', 'Unpublished', 'Trashed');
        """)
        
        # System settings indexes
        portal_db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_system_settings_updated_at ON system_settings(updated_at);
        """)
        
        # Blocked domains indexes
        portal_db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_blocked_domains_created_at ON blocked_domains(created_at);
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
        print(f"   ⚠️ Warning: Could not create some indexes: {e}")

def create_test_users(portal_db):
    """Create test users for development and testing."""
    print("👥 Creating test users...")
    
    # Test password
    test_password = os.getenv('DEFAULT_PASSWORD', 'resette2025!')
    hashed_password = bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    users = [
        {
            "user_id": uuid.uuid4().hex[:20],
            "username": "admin",
            "password_hash": hashed_password,
            "role": "system_admin",
            "email": "admin@resette.org",
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
        },
        {
            "user_id": uuid.uuid4().hex[:20],
            "username": "environmentalist",
            "password_hash": hashed_password,
            "role": "system_user",
            "email": "data@greengroup.org",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Insert users
    for user in users:
        try:
            portal_db["users"].insert(user, ignore=True)
            print(f"   ✅ Created user: {user['username']} ({user['role']}) - {user['email']}")
        except Exception as e:
            print(f"   ⚠️ Warning: Could not create user {user['username']}: {e}")
    
    return users

def create_portal_content(portal_db):
    """Create default portal homepage content."""
    print("🏠 Creating portal homepage content...")
    
    portal_content = [
        {
            "db_id": None,
            "section": "title",
            "content": json.dumps({"content": "Resette Cloud Portal"}),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": None,
            "section": "info",
            "content": json.dumps({
                "content": "The Resette Cloud Portal enables researchers, organizations, and citizens to share environmental datasets as interactive websites. Upload data files, customize your data portal, and publish environmental data for public access and collaboration.",
                "paragraphs": [
                    "The Resette Cloud Portal enables researchers, organizations, and citizens to share environmental datasets as interactive websites.",
                    "Upload data files, customize your data portal, and publish environmental data for public access and collaboration."
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
                "alt_text": "Resette Environmental Data Portal",
                "credit_text": "Environmental Data Community",
                "credit_url": ""
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
            print(f"   ⚠️ Warning: Could not create content {content['section']}: {e}")

def create_sample_databases(portal_db, users):
    """Create sample databases for demonstration (optional)."""
    print("📊 Creating sample databases...")
    
    if not users:
        print("   ⚠️ No users available, skipping sample databases")
        return
    
    # Find regular users (not admin) for sample databases
    regular_users = [u for u in users if u['role'] == 'system_user']
    if not regular_users:
        regular_users = [users[0]]  # Fallback to first user
    
    current_time = datetime.now(timezone.utc).isoformat()
    
    sample_databases = [
        {
            "db_id": uuid.uuid4().hex[:20],
            "user_id": regular_users[0]['user_id'],
            "db_name": "air-quality-monitoring",
            "website_url": "/air-quality-monitoring/",
            "status": "Published",
            "created_at": current_time,
            "updated_at": current_time,
            "file_path": f"{DATA_DIR}/{regular_users[0]['user_id']}/air-quality-monitoring.db",
            "trashed_at": None,
            "restore_deadline": None,
            "deleted_by_user_id": None,
            "deleted_at": None,
            "deletion_reason": None
        },
        {
            "db_id": uuid.uuid4().hex[:20],
            "user_id": regular_users[0]['user_id'],
            "db_name": "water_quality_sensors",
            "website_url": "/water_quality_sensors/",
            "status": "Draft",
            "created_at": current_time,
            "updated_at": current_time,
            "file_path": f"{DATA_DIR}/{regular_users[0]['user_id']}/water_quality_sensors.db",
            "trashed_at": None,
            "restore_deadline": None,
            "deleted_by_user_id": None,
            "deleted_at": None,
            "deletion_reason": None
        }
    ]
    
    # Add more sample databases if we have multiple users
    if len(regular_users) > 1:
        sample_databases.extend([
            {
                "db_id": uuid.uuid4().hex[:20],
                "user_id": regular_users[1]['user_id'],
                "db_name": "climate-data-2024",
                "website_url": "/climate-data-2024/",
                "status": "Published",
                "created_at": current_time,
                "updated_at": current_time,
                "file_path": f"{DATA_DIR}/{regular_users[1]['user_id']}/climate-data-2024.db",
                "trashed_at": None,
                "restore_deadline": None,
                "deleted_by_user_id": None,
                "deleted_at": None,
                "deletion_reason": None
            }
        ])
    
    for db_info in sample_databases:
        try:
            portal_db["databases"].insert(db_info, ignore=True)
            print(f"   ✅ Created sample database: {db_info['db_name']} ({db_info['status']})")
        except Exception as e:
            print(f"   ⚠️ Warning: Could not create database {db_info['db_name']}: {e}")

def create_initial_activity_logs(portal_db, users):
    """Create initial activity logs for system startup."""
    print("📝 Creating initial activity logs...")
    
    current_time = datetime.now(timezone.utc).isoformat()
    
    initial_logs = [
        {
            "log_id": uuid.uuid4().hex[:20],
            "user_id": "system",
            "action": "database_initialization",
            "details": "Resette Portal database initialized with complete schema",
            "timestamp": current_time,
            "action_metadata": json.dumps({
                "initialization_version": "3.0.0",
                "features_enabled": [
                    "three_tier_deletion", 
                    "trash_bin", 
                    "auto_cleanup",
                    "system_settings",
                    "blocked_domains",
                    "enhanced_validation",
                    "image_optimization"
                ],
                "user_count": len(users) if users else 0,
                "database_version": "sqlite3",
                "portal_name": "Resette Cloud Portal"
            })
        },
        {
            "log_id": uuid.uuid4().hex[:20],
            "user_id": "system",
            "action": "system_settings_created",
            "details": "Default system settings configured",
            "timestamp": current_time,
            "action_metadata": json.dumps({
                "settings_created": 7,
                "trash_retention_days": 30,
                "max_databases_per_user": 10,
                "max_file_size_mb": 50,
                "max_img_size_mb": 5
            })
        }
    ]
    
    for log_entry in initial_logs:
        try:
            portal_db["activity_logs"].insert(log_entry, ignore=True)
            print(f"   ✅ Created initial log: {log_entry['action']}")
        except Exception as e:
            print(f"   ⚠️ Warning: Could not create log: {e}")

def setup_file_structure():
    """Create necessary directory structure and default files."""
    print("📁 Setting up file structure...")
    
    # Ensure directories exist
    directories = [DATA_DIR, STATIC_DIR, os.path.dirname(PORTAL_DB_PATH)]
    for directory in directories:
        if directory:  # Skip if directory is empty
            os.makedirs(directory, exist_ok=True)
            print(f"   ✅ Ensured directory: {directory}")
    
    # Create default header image placeholder
    default_header = os.path.join(STATIC_DIR, 'default_header.jpg')
    if not os.path.exists(default_header):
        try:
            # Try to create a simple image with PIL
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new('RGB', (1680, 450), color='#2563eb')
            draw = ImageDraw.Draw(img)
            
            # Try to use a default font
            try:
                font = ImageFont.truetype("arial.ttf", 60)
                small_font = ImageFont.truetype("arial.ttf", 30)
            except:
                font = ImageFont.load_default()
                small_font = font
            
            # Main title
            title = "Resette Environmental Data Portal"
            bbox = draw.textbbox((0, 0), title, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = (1680 - text_width) // 2
            y = (450 - text_height) // 2 - 20
            
            draw.text((x, y), title, fill='white', font=font)
            
            # Subtitle
            subtitle = "Share Environmental Data • Build Interactive Portals • Collaborate"
            try:
                bbox2 = draw.textbbox((0, 0), subtitle, font=small_font)
                sub_width = bbox2[2] - bbox2[0]
                sub_x = (1680 - sub_width) // 2
                draw.text((sub_x, y + text_height + 10), subtitle, fill='#e2e8f0', font=small_font)
            except:
                pass
            
            img.save(default_header, 'JPEG', quality=95)
            print(f"   ✅ Created default header image: {default_header}")
            
        except ImportError:
            # If PIL not available, create a placeholder file
            with open(default_header, 'w') as f:
                f.write("# Resette Environmental Data Portal Header Image Placeholder\n")
                f.write("# Replace this file with an actual image (1680x450 recommended)\n")
            print(f"   ✅ Created header placeholder: {default_header}")
        except Exception as e:
            print(f"   ⚠️ Warning: Could not create header image: {e}")

def check_existing_database():
    """Check if database already exists and handle accordingly."""
    if os.path.exists(PORTAL_DB_PATH):
        print(f"📊 Database already exists at: {PORTAL_DB_PATH}")
        
        # Check if this is an old version that needs migration
        try:
            existing_db = sqlite_utils.Database(PORTAL_DB_PATH)
            tables = existing_db.table_names()
            
            # Check for new tables
            required_tables = ['system_settings', 'blocked_domains']
            missing_tables = [table for table in required_tables if table not in tables]
            
            if missing_tables:
                print(f"📄 Database needs migration for new features")
                print(f"   Missing tables: {missing_tables}")
                
                response = input("Do you want to migrate the database? [y/N]: ")
                if response.lower() == 'y':
                    migrate_database(existing_db)
                    return False  # Continue with rest of initialization
                else:
                    print("   Skipping migration. Some features may not work.")
                    return True  # Skip initialization
            
            # Check for missing columns in existing tables
            if 'databases' in tables:
                db_columns = [col.name for col in existing_db['databases'].columns]
                required_columns = ['updated_at', 'trashed_at', 'restore_deadline', 'deleted_by_user_id', 'deleted_at', 'deletion_reason']
                missing_columns = [col for col in required_columns if col not in db_columns]
                
                if missing_columns:
                    print(f"📄 Database schema needs updates")
                    print(f"   Missing columns: {missing_columns}")
                    
                    response = input("Do you want to update the database schema? [y/N]: ")
                    if response.lower() == 'y':
                        migrate_database(existing_db)
                        return False
                    else:
                        print("   Skipping schema updates. Some features may not work.")
                        return True
            
            print("✅ Database is up to date")
            return True  # Skip initialization
            
        except Exception as e:
            print(f"⚠️ Warning: Could not check existing database: {e}")
            response = input("Do you want to continue anyway? [y/N]: ")
            return response.lower() != 'y'
    
    return False  # Database doesn't exist, continue with initialization

def migrate_database(existing_db):
    """Migrate existing database to support new features."""
    print("📄 Migrating database schema...")
    
    try:
        # Create new tables if they don't exist
        tables = existing_db.table_names()
        
        if 'system_settings' not in tables:
            create_database_schema(existing_db)
            create_system_settings(existing_db)
        
        # Add new columns to databases table
        if 'databases' in tables:
            db_columns = [col.name for col in existing_db['databases'].columns]
            required_columns = [
                ("updated_at", "TEXT"),
                ("trashed_at", "TEXT"),
                ("restore_deadline", "TEXT"), 
                ("deleted_by_user_id", "TEXT"),
                ("deleted_at", "TEXT"),
                ("deletion_reason", "TEXT")
            ]
            
            for column_name, column_type in required_columns:
                if column_name not in db_columns:
                    try:
                        existing_db.executescript(f"ALTER TABLE databases ADD COLUMN {column_name} {column_type};")
                        print(f"   ✅ Added column: databases.{column_name}")
                    except Exception as e:
                        if "duplicate column name" in str(e).lower():
                            print(f"   ⚪ Column already exists: databases.{column_name}")
                        else:
                            print(f"   ⚠️ Warning: Could not add column {column_name}: {e}")
            
            # Set updated_at for existing records
            current_time = datetime.now(timezone.utc).isoformat()
            existing_db.execute("UPDATE databases SET updated_at = created_at WHERE updated_at IS NULL")
            print("   ✅ Updated existing records with timestamps")
        
        # Add action_metadata column to activity_logs table if it doesn't exist
        if 'activity_logs' in tables:
            activity_columns = [col.name for col in existing_db['activity_logs'].columns]
            if 'action_metadata' not in activity_columns:
                try:
                    existing_db.executescript("ALTER TABLE activity_logs ADD COLUMN action_metadata TEXT;")
                    print(f"   ✅ Added column: activity_logs.action_metadata")
                except Exception as e:
                    if "duplicate column name" in str(e).lower():
                        print(f"   ⚪ Column already exists: activity_logs.action_metadata")
                    else:
                        print(f"   ⚠️ Warning: Could not add action_metadata column: {e}")
        
        # Create new indexes
        create_indexes(existing_db)
        
        # Log the migration
        migration_log = {
            "log_id": uuid.uuid4().hex[:20],
            "user_id": "system",
            "action": "database_migration",
            "details": "Migrated database to support enhanced features",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_metadata": json.dumps({
                "migration_version": "3.0.0",
                "features_added": ["system_settings", "blocked_domains", "enhanced_deletion"],
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
        print("🌱 Initializing Resette Cloud Portal Database...")
        print("   Enhanced features enabled:")
        print("   • Three-tier deletion system (Draft → Trash → Delete)")
        print("   • System settings management")
        print("   • Domain blocking capabilities")
        print("   • Enhanced validation and security")
        print("   • Image optimization support")
        print("   • Comprehensive audit logging")
        print()
        
        # Check if database already exists
        if check_existing_database():
            print("✅ Database initialization skipped (already exists and up to date)")
            return
        
        # Setup file structure
        setup_file_structure()
        
        print(f"🗄️ Creating portal database at: {PORTAL_DB_PATH}")
        
        # Create portal database
        portal_db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        # Create schema
        create_database_schema(portal_db)
        
        # Create system settings
        create_system_settings(portal_db)
        
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
        test_password = os.getenv('DEFAULT_PASSWORD', 'resette2025!')
        
        print()
        print("✅ Database initialization complete!")
        print(f"📊 Database created at: {PORTAL_DB_PATH}")
        print()
        print("🔑 Test Login Credentials:")
        print(f"   Admin:          admin / {test_password}")
        print(f"   Researcher:     researcher / {test_password}")
        print(f"   Analyst:        analyst / {test_password}")
        print(f"   Environmentalist: environmentalist / {test_password}")
        print()
        print("🗂️ Directory Structure:")
        print(f"   Portal DB:  {PORTAL_DB_PATH}")
        print(f"   Data Dir:   {DATA_DIR}")
        print(f"   Static Dir: {STATIC_DIR}")
        print()
        print("🚀 Features Enabled:")
        print("   ✅ Three-tier deletion system with 30-day retention")
        print("   ✅ System settings management")
        print("   ✅ Domain blocking and security controls")
        print("   ✅ Enhanced database validation")
        print("   ✅ Image optimization and processing")
        print("   ✅ Comprehensive audit logging")
        print("   ✅ User self-service capabilities")
        print("   ✅ Admin override and management tools")
        print()
        print("📈 Database Statistics:")
        try:
            print(f"   Users created: {len(users)}")
            db_count = portal_db.execute("SELECT COUNT(*) FROM databases").fetchone()[0]
            settings_count = portal_db.execute("SELECT COUNT(*) FROM system_settings").fetchone()[0]
            print(f"   Sample databases: {db_count}")
            print(f"   System settings: {settings_count}")
        except:
            pass
        print()
        print("Next steps:")
        print("1. Start Datasette with the Resette plugin")
        print("2. Navigate to http://localhost:8001")
        print("3. Login with the credentials above")
        print("4. Create your first environmental database!")
        print("5. Customize the portal homepage (admin only)")
        
    except Exception as e:
        print(f"❌ ERROR: Database initialization failed!")
        print(f"Error details: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    main()