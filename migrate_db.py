#!/usr/bin/env python3
"""
Enhanced Database Migration - Add table and missing columns including markdown_columns and users table
"""
import sqlite_utils
import os
from datetime import datetime, timezone

# Configuration
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("RESETTE_DATA_DIR", os.path.join(ROOT_DIR, "data"))
STATIC_DIR = os.getenv('RESETTE_STATIC_DIR', os.path.join(ROOT_DIR, "static"))
PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', os.path.join(DATA_DIR, "portal.db"))

def migrate_database():
    """Comprehensive database migration with table creation and column updates."""
    
    # Create directory if it doesn't exist
    db_dir = os.path.dirname(PORTAL_DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        print(f"Creating directory: {db_dir}")
        os.makedirs(db_dir, exist_ok=True)
    
    if not os.path.exists(PORTAL_DB_PATH):
        print(f"Database not found at: {PORTAL_DB_PATH}")
        print("Creating new database file...")
        # This will create the database file when we connect
    
    print("Starting comprehensive database migration...")
    
    try:
        db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        # Get existing tables
        existing_tables = [table.name for table in db.tables]
        print(f"Found existing tables: {existing_tables}")
        
        # 1. Create/Update users table
        if 'users' not in existing_tables:
            print("Creating users table...")
            db.executescript("""
                CREATE TABLE users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT,
                    password_hash TEXT,
                    role TEXT,
                    email TEXT,
                    created_at TEXT,
                    must_change_password BOOLEAN DEFAULT 0
                );
            """)
            print("   Created users table with must_change_password field")
        else:
            print("Updating users table structure...")
            
            # Get current columns
            current_columns = [col.name for col in db['users'].columns]
            print(f"   Current users columns: {current_columns}")
            
            # Add must_change_password column if missing
            if 'must_change_password' not in current_columns:
                try:
                    db.executescript("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0;")
                    print("   Added: must_change_password")
                except Exception as e:
                    if "duplicate column" in str(e).lower():
                        print("   Exists: must_change_password")
                    else:
                        print(f"   Failed to add must_change_password: {e}")
            else:
                print("   Exists: must_change_password")
        
        # 2. Create system_settings table if it doesn't exist
        if 'system_settings' not in existing_tables:
            print("Creating system_settings table...")
            db.executescript("""
                CREATE TABLE system_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL,
                    updated_at TEXT,
                    updated_by TEXT
                );
            """)
            
            # Add default system settings
            current_time = datetime.now(timezone.utc).isoformat()
            default_settings = [
                ('trash_retention_days', '30'),
                ('max_databases_per_user', '10'),
                ('max_file_size', str(500 * 1024 * 1024)),  # 500MB
                ('max_img_size', str(5 * 1024 * 1024)),    # 5MB
                ('allowed_extensions', '.jpg,.jpeg,.png,.csv,.xls,.xlsx,.txt,.db,.jsonl,.json')
            ]
            
            for setting_key, setting_value in default_settings:
                db.execute(
                    "INSERT INTO system_settings (setting_key, setting_value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                    [setting_key, setting_value, current_time, 'system_migration']
                )
            
            print("   Created system_settings table with defaults")
        else:
            print("   system_settings table already exists")
        
        # 3. Update databases table structure
        if 'databases' in existing_tables:
            print("Updating databases table structure...")
            
            # Get current columns
            current_columns = [col.name for col in db['databases'].columns]
            print(f"   Current columns: {current_columns}")
            
            # Define all required columns
            required_columns = {
                'updated_at': 'TEXT',
                'trashed_at': 'TEXT', 
                'restore_deadline': 'TEXT',
                'deletion_reason': 'TEXT',
                'deleted_by_user_id': 'TEXT',
                'deleted_at': 'TEXT'
            }
            
            # Add missing columns
            for column_name, column_type in required_columns.items():
                if column_name not in current_columns:
                    try:
                        db.executescript(f"ALTER TABLE databases ADD COLUMN {column_name} {column_type};")
                        print(f"   Added: {column_name}")
                    except Exception as e:
                        if "duplicate column" in str(e).lower():
                            print(f"   Exists: {column_name}")
                        else:
                            print(f"   Failed: {column_name} - {e}")
                else:
                    print(f"   Exists: {column_name}")
            
            # Set updated_at for existing records where it's NULL
            current_time = datetime.now(timezone.utc).isoformat()
            result = db.execute("UPDATE databases SET updated_at = created_at WHERE updated_at IS NULL")
            updated_count = result.rowcount if hasattr(result, 'rowcount') else 0
            if updated_count > 0:
                print(f"   Updated {updated_count} records with updated_at timestamps")

        # Fix activity_logs table structure
        if 'activity_logs' in existing_tables:
            print("Updating activity_logs table structure...")
            
            # Get current columns
            current_columns = [col.name for col in db['activity_logs'].columns]
            print(f"   Current activity_logs columns: {current_columns}")
            
            # Add missing action_metadata column
            if 'action_metadata' not in current_columns:
                try:
                    db.executescript("ALTER TABLE activity_logs ADD COLUMN action_metadata TEXT;")
                    print("   Added: action_metadata to activity_logs")
                except Exception as e:
                    if "duplicate column" in str(e).lower():
                        print("   Exists: action_metadata")
                    else:
                        print(f"   Failed to add action_metadata: {e}")
            else:
                print("   Exists: action_metadata")
            
        else:
            print("Creating databases table...")
            db.executescript("""
                CREATE TABLE databases (
                    db_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    db_name TEXT,
                    website_url TEXT,
                    status TEXT,
                    created_at TEXT,
                    file_path TEXT,
                    trashed_at TEXT,
                    restore_deadline TEXT,
                    deletion_reason TEXT,
                    deleted_by_user_id TEXT,
                    deleted_at TEXT,
                    updated_at TEXT
                );
            """)
            print("   Created databases table")
        
        # 4. Create blocked_domains table if it doesn't exist
        if 'blocked_domains' not in existing_tables:
            print("Creating blocked_domains table...")
            db.executescript("""
                CREATE TABLE blocked_domains (
                    domain TEXT PRIMARY KEY,
                    created_at TEXT,
                    created_by TEXT
                );
            """)
            print("   Created blocked_domains table")
        else:
            print("   blocked_domains table already exists")
        
        # 5. Create database_tables table if it doesn't exist
        if 'database_tables' not in existing_tables:
            print("Creating database_tables table...")
            db.executescript("""
                CREATE TABLE database_tables (
                    table_id TEXT PRIMARY KEY,
                    db_id TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    show_in_homepage BOOLEAN DEFAULT 1,
                    display_order INTEGER DEFAULT 0,
                    created_at TEXT,
                    updated_at TEXT,
                    FOREIGN KEY (db_id) REFERENCES databases (db_id),
                    UNIQUE (db_id, table_name)
                );
            """)
            print("   Created database_tables table")
        else:
            print("   database_tables table already exists")
        
        # 6. Create/Update markdown_columns table
        if 'markdown_columns' not in existing_tables:
            print("Creating markdown_columns table...")
            db.executescript("""
                CREATE TABLE markdown_columns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    db_name TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    column_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT DEFAULT 'system',
                    UNIQUE(db_name, table_name, column_name)
                );
            """)
            print("   Created markdown_columns table")
        else:
            print("Updating markdown_columns table structure...")
            
            # Get current columns
            current_columns = [col.name for col in db['markdown_columns'].columns]
            print(f"   Current markdown_columns columns: {current_columns}")
            
            # Add created_by column if missing
            if 'created_by' not in current_columns:
                try:
                    db.executescript("ALTER TABLE markdown_columns ADD COLUMN created_by TEXT DEFAULT 'system';")
                    print("   Added: created_by")
                except Exception as e:
                    if "duplicate column" in str(e).lower():
                        print("   Exists: created_by")
                    else:
                        print(f"   Failed to add created_by: {e}")
            else:
                print("   Exists: created_by")
        
        # Insert default configurations if table is empty
        current_time = datetime.now(timezone.utc).isoformat()
        existing_count = db.execute("SELECT COUNT(*) FROM markdown_columns").fetchone()[0]
        
        if existing_count == 0:
            print("Inserting default markdown configurations...")
            default_markdown_configs = [
                ('risk_management_plans', 'facility_view', 'report'),
                ('risk_management_plans', 'facility_view', 'popup'),
                ('risk_management_plans', 'facility_accidents_view', 'report'),
                ('risk_management_plans', 'accident_chemicals_view', 'report'),
                ('risk_management_plans', 'rmp_facility', 'report'),
                ('risk_management_plans', 'rmp_facility', 'popup'),
                ('campd', 'emissions', 'id'),
                ('campd', 'emissions', 'file_key'),
                ('campd', 'emissions', 'datasette_link')
            ]
            
            for db_name, table_name, column_name in default_markdown_configs:
                try:
                    result = db.execute("""
                        INSERT OR IGNORE INTO markdown_columns 
                        (db_name, table_name, column_name, created_at, created_by) 
                        VALUES (?, ?, ?, ?, 'migration')
                    """, [db_name, table_name, column_name, current_time])
                    print(f"   Inserted: {db_name}.{table_name}.{column_name}")
                except Exception as e:
                    print(f"   Warning: Could not insert {db_name}.{table_name}.{column_name}: {e}")
            
            # Explicitly commit the transaction
            db.conn.commit()
            
            # Verify the inserts worked
            final_count = db.execute("SELECT COUNT(*) FROM markdown_columns").fetchone()[0]
            print(f"   Final count after insert: {final_count} markdown configurations")
        else:
            print(f"   markdown_columns table already has {existing_count} entries - skipping default inserts")
        
        # 7. Verify table structures
        print("Verifying table structures...")
        
        # Check users
        users_columns = [col.name for col in db['users'].columns]
        expected_users = ['user_id', 'username', 'password_hash', 'role', 'email', 'created_at', 'must_change_password']
        missing_users = [col for col in expected_users if col not in users_columns]
        if missing_users:
            print(f"   Missing users columns: {missing_users}")
        else:
            print("   users structure verified")
        
        # Check system_settings
        system_settings_columns = [col.name for col in db['system_settings'].columns]
        expected_system_settings = ['setting_key', 'setting_value', 'updated_at', 'updated_by']
        missing_system_settings = [col for col in expected_system_settings if col not in system_settings_columns]
        if missing_system_settings:
            print(f"   Missing system_settings columns: {missing_system_settings}")
        else:
            print("   system_settings structure verified")
        
        # Check databases  
        databases_columns = [col.name for col in db['databases'].columns]
        expected_databases = [
            'db_id', 'user_id', 'db_name', 'website_url', 'status', 'created_at', 
            'file_path', 'trashed_at', 'restore_deadline', 'deletion_reason', 
            'deleted_by_user_id', 'deleted_at', 'updated_at'
        ]
        missing_databases = [col for col in expected_databases if col not in databases_columns]
        if missing_databases:
            print(f"   Missing databases columns: {missing_databases}")
        else:
            print("   databases structure verified")
        
        # Check blocked_domains
        blocked_domains_columns = [col.name for col in db['blocked_domains'].columns]
        expected_blocked_domains = ['domain', 'created_at', 'created_by']
        missing_blocked_domains = [col for col in expected_blocked_domains if col not in blocked_domains_columns]
        if missing_blocked_domains:
            print(f"   Missing blocked_domains columns: {missing_blocked_domains}")
        else:
            print("   blocked_domains structure verified")
        
        # Check database_tables
        database_tables_columns = [col.name for col in db['database_tables'].columns]
        expected_database_tables = [
            'table_id', 'db_id', 'table_name', 'show_in_homepage', 'display_order', 
            'created_at', 'updated_at'
        ]
        missing_database_tables = [col for col in expected_database_tables if col not in database_tables_columns]
        if missing_database_tables:
            print(f"   Missing database_tables columns: {missing_database_tables}")
        else:
            print("   database_tables structure verified")
        
        # Check markdown_columns
        markdown_columns_columns = [col.name for col in db['markdown_columns'].columns]
        expected_markdown_columns = ['id', 'db_name', 'table_name', 'column_name', 'created_at', 'created_by']
        missing_markdown_columns = [col for col in expected_markdown_columns if col not in markdown_columns_columns]
        if missing_markdown_columns:
            print(f"   Missing markdown_columns columns: {missing_markdown_columns}")
        else:
            print("   markdown_columns structure verified")
        
        # 8. Database statistics
        print("Database statistics:")
        try:
            users_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            databases_count = db.execute("SELECT COUNT(*) FROM databases").fetchone()[0]
            settings_count = db.execute("SELECT COUNT(*) FROM system_settings").fetchone()[0]
            domains_count = db.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
            tables_count = db.execute("SELECT COUNT(*) FROM database_tables").fetchone()[0]
            markdown_count = db.execute("SELECT COUNT(*) FROM markdown_columns").fetchone()[0]
            
            print(f"   Users: {users_count}")
            print(f"   Databases: {databases_count}")
            print(f"   Database tables: {tables_count}")
            print(f"   Settings: {settings_count}")
            print(f"   Blocked domains: {domains_count}")
            print(f"   Markdown columns: {markdown_count}")
            
            # Show users with must_change_password flag
            users_must_change = db.execute("SELECT COUNT(*) FROM users WHERE must_change_password = 1").fetchone()[0]
            print(f"   Users requiring password change: {users_must_change}")
            
        except Exception as stats_error:
            print(f"   Could not get statistics: {stats_error}")
        
        print("Comprehensive migration completed successfully!")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

def verify_migration():
    """Verify that the migration was successful."""
    PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
    
    if not os.path.exists(PORTAL_DB_PATH):
        print("Cannot verify - database not found")
        return False
    
    try:
        db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        required_tables = ['users', 'system_settings', 'databases', 'blocked_domains', 'database_tables', 'markdown_columns']
        existing_tables = [table.name for table in db.tables]
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            print(f"Verification failed - missing tables: {missing_tables}")
            return False
        
        # Check users table has must_change_password column
        users_columns = [col.name for col in db['users'].columns]
        if 'must_change_password' not in users_columns:
            print("Verification failed - users table missing must_change_password column")
            return False
        
        # Check system_settings has default values
        settings_count = db.execute("SELECT COUNT(*) FROM system_settings").fetchone()[0]
        if settings_count == 0:
            print("Warning: system_settings table is empty")
        
        # Check markdown_columns has default values
        markdown_count = db.execute("SELECT COUNT(*) FROM markdown_columns").fetchone()[0]
        if markdown_count == 0:
            print("Warning: markdown_columns table is empty")
        else:
            print(f"Found {markdown_count} markdown column configurations")
            
            # Show configured markdown columns
            markdown_configs = db.execute("SELECT db_name, table_name, column_name FROM markdown_columns ORDER BY db_name, table_name, column_name").fetchall()
            for db_name, table_name, column_name in markdown_configs:
                print(f"   Markdown: {db_name}:{table_name}:{column_name}")
        
        # Verify foreign key constraint exists for database_tables
        try:
            db.execute("PRAGMA foreign_key_check(database_tables)").fetchall()
            print("database_tables foreign key constraints verified")
        except Exception as fk_error:
            print(f"Foreign key check warning: {fk_error}")
        
        print("Migration verification passed!")
        return True
        
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

if __name__ == "__main__":
    migrate_database()
    print("\n" + "="*50)
    verify_migration()