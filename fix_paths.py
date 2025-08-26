#!/usr/bin/env python3
"""
Fix Database Paths - Ensure portal.db has correct file paths
Updated for /data/user_id/db_id.db structure
"""
import sqlite3
import os
import glob

def fix_database_paths():
    """Fix file paths in portal database to match actual files"""
    
    portal_db_path = os.getenv('PORTAL_DB_PATH', '/data/portal.db')
    data_dir = os.getenv('EDGI_DATA_DIR', '/data')
    
    if not os.path.exists(portal_db_path):
        print("❌ Portal database not found")
        return
    
    print("🔧 Fixing database file paths...")
    
    try:
        conn = sqlite3.connect(portal_db_path)
        cursor = conn.cursor()
        
        # Get current database entries
        cursor.execute("SELECT db_id, user_id, db_name, file_path, status FROM databases")
        databases = cursor.fetchall()
        
        print(f"📊 Found {len(databases)} database entries")
        
        # Find all actual database files in user directories
        user_dirs = [d for d in os.listdir(data_dir) if d.startswith('user_') and os.path.isdir(os.path.join(data_dir, d))]
        print(f"📁 Found {len(user_dirs)} user directories")
        
        actual_files = {}  # db_id -> file_path mapping
        for user_dir in user_dirs:
            user_path = os.path.join(data_dir, user_dir)
            db_files = glob.glob(os.path.join(user_path, "*.db"))
            for db_file in db_files:
                # Extract db_id from filename (assuming format: {db_id}.db)
                db_id = os.path.basename(db_file).replace('.db', '')
                actual_files[db_id] = db_file
        
        print(f"📄 Found {len(actual_files)} actual database files")
        
        fixed_count = 0
        missing_count = 0
        
        for db_id, user_id, db_name, file_path, status in databases:
            print(f"\n🔍 Checking: {db_name} (ID: {db_id})")
            print(f"   User ID: {user_id}")
            print(f"   Current path: {file_path}")
            print(f"   Status: {status}")
            
            # Expected path based on your structure
            expected_path = os.path.join(data_dir, f"user_{user_id}", f"{db_id}.db")
            
            # Check current path first
            if file_path and os.path.exists(file_path):
                print(f"   ✅ File exists at current path")
                continue
            
            # Check expected path
            if os.path.exists(expected_path):
                print(f"   🔧 Found at expected path: {expected_path}")
                cursor.execute(
                    "UPDATE databases SET file_path = ?, status = 'active' WHERE db_id = ?",
                    (expected_path, db_id)
                )
                fixed_count += 1
                continue
            
            # Check if file exists with this db_id anywhere
            if db_id in actual_files:
                found_path = actual_files[db_id]
                print(f"   🔧 Found file: {found_path}")
                cursor.execute(
                    "UPDATE databases SET file_path = ?, status = 'active' WHERE db_id = ?",
                    (found_path, db_id)
                )
                fixed_count += 1
                continue
            
            # File not found anywhere
            print(f"   ❌ File not found, marking as missing")
            cursor.execute(
                "UPDATE databases SET status = 'missing' WHERE db_id = ?",
                (db_id,)
            )
            missing_count += 1
        
        # Look for orphaned database files (files not in portal.db)
        registered_db_ids = {row[0] for row in databases}
        orphaned_files = {db_id: path for db_id, path in actual_files.items() if db_id not in registered_db_ids}
        
        if orphaned_files:
            print(f"\n🔍 Found {len(orphaned_files)} orphaned database files:")
            for db_id, file_path in orphaned_files.items():
                print(f"   📄 {db_id}.db at {file_path}")
                
                # Try to extract user_id from path
                parts = file_path.split(os.sep)
                user_dir = None
                for part in parts:
                    if part.startswith('user_'):
                        user_dir = part
                        break
                
                if user_dir:
                    user_id = user_dir.replace('user_', '')
                    print(f"      💡 Appears to belong to user: {user_id}")
                    print(f"      💡 Consider re-registering this database")
        
        conn.commit()
        conn.close()
        
        print(f"\n✅ Fixed {fixed_count} database paths")
        print(f"❌ {missing_count} databases marked as missing")
        if orphaned_files:
            print(f"🔍 {len(orphaned_files)} orphaned files found")
        
    except Exception as e:
        print(f"❌ Error fixing paths: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

def create_missing_directories():
    """Create missing user directories if needed"""
    
    portal_db_path = os.getenv('PORTAL_DB_PATH', '/data/portal.db')
    data_dir = os.getenv('EDGI_DATA_DIR', '/data')
    
    if not os.path.exists(portal_db_path):
        return
    
    try:
        conn = sqlite3.connect(portal_db_path)
        cursor = conn.cursor()
        
        # Get all unique user IDs
        cursor.execute("SELECT DISTINCT user_id FROM databases WHERE user_id IS NOT NULL")
        user_ids = [row[0] for row in cursor.fetchall()]
        
        print(f"🔧 Ensuring user directories exist for {len(user_ids)} users...")
        
        created_count = 0
        for user_id in user_ids:
            user_dir = os.path.join(data_dir, f"user_{user_id}")
            if not os.path.exists(user_dir):
                os.makedirs(user_dir, exist_ok=True)
                print(f"   📁 Created directory: user_{user_id}")
                created_count += 1
            else:
                print(f"   ✅ Directory exists: user_{user_id}")
        
        conn.close()
        
        if created_count > 0:
            print(f"✅ Created {created_count} user directories")
        else:
            print("✅ All user directories already exist")
            
    except Exception as e:
        print(f"❌ Error creating directories: {e}")

def validate_database_structure():
    """Validate that the database structure is correct"""
    
    portal_db_path = os.getenv('PORTAL_DB_PATH', '/data/portal.db')
    data_dir = os.getenv('EDGI_DATA_DIR', '/data')
    
    print("🔍 Validating database structure...")
    
    issues = []
    
    # Check if databases table has user_id column
    try:
        conn = sqlite3.connect(portal_db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(databases)")
        columns = [row[1] for row in cursor.fetchall()]
        
        required_columns = ['db_id', 'user_id', 'db_name', 'file_path', 'status']
        missing_columns = [col for col in required_columns if col not in columns]
        
        if missing_columns:
            issues.append(f"Missing required columns in databases table: {missing_columns}")
        else:
            print("✅ Database table structure is valid")
        
        conn.close()
        
    except Exception as e:
        issues.append(f"Cannot validate database structure: {e}")
    
    if issues:
        print("❌ Validation issues found:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    else:
        print("✅ Database structure validation passed")
        return True

if __name__ == "__main__":
    print("🔧 Starting database path maintenance...")
    
    # First validate the structure
    if validate_database_structure():
        # Create missing directories
        create_missing_directories()
        
        # Fix paths
        fix_database_paths()
    else:
        print("❌ Cannot proceed - database structure issues found")
    
    print("✅ Database path maintenance complete")