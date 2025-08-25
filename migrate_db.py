#!/usr/bin/env python3
"""
Simple Database Migration - Add table and missing columns
"""
import sqlite_utils
import os
from datetime import datetime, timezone

def migrate_database():
    """Comprehensive database migration with table creation and column updates."""
    PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
    
    if not os.path.exists(PORTAL_DB_PATH):
        print("❌ Database not found at:", PORTAL_DB_PATH)
        return
    
    print("📄 Starting comprehensive database migration...")
    
    try:
        db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        # Get existing tables
        existing_tables = [table.name for table in db.tables]
        print(f"📋 Found existing tables: {existing_tables}")
        
        # 1. Create system_settings table if it doesn't exist
        if 'system_settings' not in existing_tables:
            print("🔧 Creating system_settings table...")
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
                ('max_file_size', str(50 * 1024 * 1024)),  # 50MB
                ('max_img_size', str(5 * 1024 * 1024)),    # 5MB
                ('allowed_extensions', '.jpg,.jpeg,.png,.csv,.xls,.xlsx,.txt,.db,.sqlite,.sqlite3')
            ]
            
            for setting_key, setting_value in default_settings:
                db.execute(
                    "INSERT INTO system_settings (setting_key, setting_value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                    [setting_key, setting_value, current_time, 'system_migration']
                )
            
            print("   ✅ Created system_settings table with defaults")
        else:
            print("   ⚪ system_settings table already exists")
        
        # 2. Update databases table structure
        if 'databases' in existing_tables:
            print("🔧 Updating databases table structure...")
            
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
                        print(f"   ✅ Added: {column_name}")
                    except Exception as e:
                        if "duplicate column" in str(e).lower():
                            print(f"   ⚪ Exists: {column_name}")
                        else:
                            print(f"   ❌ Failed: {column_name} - {e}")
                else:
                    print(f"   ⚪ Exists: {column_name}")
            
            # Set updated_at for existing records where it's NULL
            current_time = datetime.now(timezone.utc).isoformat()
            result = db.execute("UPDATE databases SET updated_at = created_at WHERE updated_at IS NULL")
            updated_count = result.rowcount if hasattr(result, 'rowcount') else 0
            if updated_count > 0:
                print(f"   ✅ Updated {updated_count} records with updated_at timestamps")
            
        else:
            print("🔧 Creating databases table...")
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
            print("   ✅ Created databases table")
        
        # 3. Create blocked_domains table if it doesn't exist
        if 'blocked_domains' not in existing_tables:
            print("🔧 Creating blocked_domains table...")
            db.executescript("""
                CREATE TABLE blocked_domains (
                    domain TEXT PRIMARY KEY,
                    created_at TEXT,
                    created_by TEXT
                );
            """)
            print("   ✅ Created blocked_domains table")
        else:
            print("   ⚪ blocked_domains table already exists")
        
        # 4. Verify table structures
        print("🔍 Verifying table structures...")
        
        # Check system_settings
        system_settings_columns = [col.name for col in db['system_settings'].columns]
        expected_system_settings = ['setting_key', 'setting_value', 'updated_at', 'updated_by']
        missing_system_settings = [col for col in expected_system_settings if col not in system_settings_columns]
        if missing_system_settings:
            print(f"   ⚠️  Missing system_settings columns: {missing_system_settings}")
        else:
            print("   ✅ system_settings structure verified")
        
        # Check databases  
        databases_columns = [col.name for col in db['databases'].columns]
        expected_databases = [
            'db_id', 'user_id', 'db_name', 'website_url', 'status', 'created_at', 
            'file_path', 'trashed_at', 'restore_deadline', 'deletion_reason', 
            'deleted_by_user_id', 'deleted_at', 'updated_at'
        ]
        missing_databases = [col for col in expected_databases if col not in databases_columns]
        if missing_databases:
            print(f"   ⚠️  Missing databases columns: {missing_databases}")
        else:
            print("   ✅ databases structure verified")
        
        # Check blocked_domains
        blocked_domains_columns = [col.name for col in db['blocked_domains'].columns]
        expected_blocked_domains = ['domain', 'created_at', 'created_by']
        missing_blocked_domains = [col for col in expected_blocked_domains if col not in blocked_domains_columns]
        if missing_blocked_domains:
            print(f"   ⚠️  Missing blocked_domains columns: {missing_blocked_domains}")
        else:
            print("   ✅ blocked_domains structure verified")
        
        # 5. Database statistics
        print("📊 Database statistics:")
        try:
            users_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] if 'users' in existing_tables else 0
            databases_count = db.execute("SELECT COUNT(*) FROM databases").fetchone()[0]
            settings_count = db.execute("SELECT COUNT(*) FROM system_settings").fetchone()[0]
            domains_count = db.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
            
            print(f"   👥 Users: {users_count}")
            print(f"   🗄️  Databases: {databases_count}")
            print(f"   ⚙️  Settings: {settings_count}")
            print(f"   🚫 Blocked domains: {domains_count}")
        except Exception as stats_error:
            print(f"   ⚠️  Could not get statistics: {stats_error}")
        
        print("✅ Comprehensive migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

def verify_migration():
    """Verify that the migration was successful."""
    PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
    
    if not os.path.exists(PORTAL_DB_PATH):
        print("❌ Cannot verify - database not found")
        return False
    
    try:
        db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        required_tables = ['system_settings', 'databases', 'blocked_domains']
        existing_tables = [table.name for table in db.tables]
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            print(f"❌ Verification failed - missing tables: {missing_tables}")
            return False
        
        # Check system_settings has default values
        settings_count = db.execute("SELECT COUNT(*) FROM system_settings").fetchone()[0]
        if settings_count == 0:
            print("⚠️  Warning: system_settings table is empty")
        
        print("✅ Migration verification passed!")
        return True
        
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False

if __name__ == "__main__":
    migrate_database()
    print("\n" + "="*50)
    verify_migration()