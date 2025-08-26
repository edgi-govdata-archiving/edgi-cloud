#!/usr/bin/env python3
"""
Database Diagnostic Script
Helps identify why user databases are disappearing
Updated for /data/user_id/db_id.db structure
"""
import sqlite3
import os
import json
import glob
from datetime import datetime

def diagnose_database_issues():
    """Comprehensive diagnosis of database persistence issues"""
    
    print("🔍 EDGI Cloud Portal Database Diagnostic")
    print("=" * 50)
    
    # Environment variables
    portal_db_path = os.getenv('PORTAL_DB_PATH', '/data/portal.db')
    data_dir = os.getenv('EDGI_DATA_DIR', '/data')
    
    print(f"📍 Portal DB Path: {portal_db_path}")
    print(f"📍 Data Directory: {data_dir}")
    print(f"📍 Current Working Dir: {os.getcwd()}")
    
    # Check data directory structure
    print("\n📂 Data Directory Analysis:")
    if os.path.exists(data_dir):
        print(f"✅ Data directory exists: {data_dir}")
        
        # List top-level contents
        items = os.listdir(data_dir)
        print(f"📁 Top-level contents ({len(items)} items):")
        
        user_dirs = []
        other_files = []
        
        for item in sorted(items):
            item_path = os.path.join(data_dir, item)
            if os.path.isdir(item_path) and item.startswith('user_'):
                user_dirs.append(item)
                # Count databases in this user directory
                db_files = glob.glob(os.path.join(item_path, "*.db"))
                print(f"   👤 {item}/ ({len(db_files)} databases)")
                for db_file in db_files:
                    size = os.path.getsize(db_file)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(db_file))
                    db_name = os.path.basename(db_file)
                    print(f"      📄 {db_name} ({size:,} bytes, modified: {mod_time.strftime('%Y-%m-%d %H:%M')})")
            elif os.path.isfile(item_path):
                size = os.path.getsize(item_path)
                mod_time = datetime.fromtimestamp(os.path.getmtime(item_path))
                other_files.append(item)
                print(f"   📄 {item} ({size:,} bytes, modified: {mod_time.strftime('%Y-%m-%d %H:%M')})")
            else:
                print(f"   📁 {item}/ (directory)")
        
        print(f"\n📊 Summary: {len(user_dirs)} user directories, {len(other_files)} other files")
        
    else:
        print(f"❌ Data directory does not exist: {data_dir}")
        return
    
    # Check portal database
    print("\n🗄️  Portal Database Analysis:")
    if os.path.exists(portal_db_path):
        print(f"✅ Portal database exists: {portal_db_path}")
        try:
            conn = sqlite3.connect(portal_db_path)
            cursor = conn.cursor()
            
            # Get database registrations
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            print(f"📋 Portal tables: {', '.join(tables)}")
            
            if 'databases' in tables:
                cursor.execute("""
                    SELECT db_id, user_id, db_name, file_path, status, created_at, trashed_at 
                    FROM databases 
                    ORDER BY created_at DESC
                """)
                databases = cursor.fetchall()
                print(f"\n📊 Registered Databases ({len(databases)}):")
                
                active_count = 0
                missing_count = 0
                trashed_count = 0
                
                for db_id, user_id, db_name, file_path, status, created_at, trashed_at in databases:
                    print(f"\n   🔸 {db_name} ({db_id})")
                    print(f"      User ID: {user_id}")
                    print(f"      Status: {status}")
                    print(f"      File Path: {file_path}")
                    print(f"      Created: {created_at}")
                    if trashed_at:
                        print(f"      ⚠️  Trashed: {trashed_at}")
                        trashed_count += 1
                    
                    # Expected path based on your structure
                    expected_path = os.path.join(data_dir, f"user_{user_id}", f"{db_id}.db")
                    
                    # Check both recorded path and expected path
                    file_exists = False
                    actual_path = None
                    
                    if file_path and os.path.exists(file_path):
                        file_exists = True
                        actual_path = file_path
                        size = os.path.getsize(file_path)
                        print(f"      ✅ File exists at recorded path ({size:,} bytes)")
                    elif os.path.exists(expected_path):
                        file_exists = True
                        actual_path = expected_path
                        size = os.path.getsize(expected_path)
                        print(f"      ✅ File exists at expected path ({size:,} bytes)")
                        print(f"      ⚠️  Path mismatch - should update portal.db")
                    else:
                        print(f"      ❌ File missing")
                        print(f"      Expected: {expected_path}")
                        missing_count += 1
                    
                    if file_exists and actual_path:
                        # Check database tables
                        try:
                            db_conn = sqlite3.connect(actual_path)
                            db_cursor = db_conn.cursor()
                            db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                            db_tables = [row[0] for row in db_cursor.fetchall()]
                            print(f"      📋 Tables ({len(db_tables)}): {', '.join(db_tables[:5])}{'...' if len(db_tables) > 5 else ''}")
                            
                            # Get total record count
                            total_records = 0
                            for table in db_tables:
                                try:
                                    db_cursor.execute(f"SELECT COUNT(*) FROM {table}")
                                    count = db_cursor.fetchone()[0]
                                    total_records += count
                                except:
                                    pass
                            print(f"      📊 Total records: {total_records:,}")
                            db_conn.close()
                            active_count += 1
                        except Exception as e:
                            print(f"      ❌ Error reading database: {e}")
                
                print(f"\n📈 Database Summary:")
                print(f"   ✅ Active: {active_count}")
                print(f"   ❌ Missing: {missing_count}")
                print(f"   🗑️  Trashed: {trashed_count}")
                
                # Look for orphaned database files
                print(f"\n🔍 Checking for orphaned databases...")
                registered_paths = set()
                for row in databases:
                    if row[3]:  # file_path
                        registered_paths.add(row[3])
                    # Also add expected path
                    expected = os.path.join(data_dir, f"user_{row[1]}", f"{row[0]}.db")
                    registered_paths.add(expected)
                
                # Find all actual database files
                all_db_files = []
                for user_dir in user_dirs:
                    user_path = os.path.join(data_dir, user_dir)
                    db_files = glob.glob(os.path.join(user_path, "*.db"))
                    all_db_files.extend(db_files)
                
                orphaned_files = [f for f in all_db_files if f not in registered_paths]
                if orphaned_files:
                    print(f"   🔍 Found {len(orphaned_files)} orphaned database files:")
                    for orphan in orphaned_files:
                        print(f"      📄 {orphan}")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Error reading portal database: {e}")
    else:
        print(f"❌ Portal database does not exist: {portal_db_path}")
    
    # Check container volume mounting
    print("\n🐳 Container Mount Analysis:")
    if os.path.exists('/proc/mounts'):
        with open('/proc/mounts', 'r') as f:
            mounts = f.read()
            data_mounts = [line for line in mounts.split('\n') if '/data' in line]
            if data_mounts:
                print("✅ Found /data mounts:")
                for mount in data_mounts:
                    print(f"   📌 {mount}")
            else:
                print("⚠️  No /data mounts found in /proc/mounts")
    
    # Check disk space
    print("\n💾 Disk Space Analysis:")
    import shutil
    try:
        total, used, free = shutil.disk_usage(data_dir)
        print(f"📊 Total: {total // (1024**3)} GB")
        print(f"📊 Used: {used // (1024**3)} GB")  
        print(f"📊 Free: {free // (1024**3)} GB")
        
        usage_percent = (used / total) * 100
        print(f"📊 Usage: {usage_percent:.1f}%")
        
        if free < 100 * 1024**2:  # Less than 100MB
            print("⚠️  WARNING: Low disk space!")
        elif usage_percent > 90:
            print("⚠️  WARNING: Disk usage over 90%!")
    except Exception as e:
        print(f"❌ Could not check disk usage: {e}")
    
    # Check file permissions
    print(f"\n🔐 Permission Analysis:")
    try:
        stat = os.stat(data_dir)
        uid = stat.st_uid
        gid = stat.st_gid
        print(f"📍 Data directory owner: UID={uid}, GID={gid}")
        print(f"📍 Data directory permissions: {oct(stat.st_mode)[-3:]}")
        
        # Check if we can write to data directory
        test_dir = os.path.join(data_dir, 'test_user_999')
        test_file = os.path.join(test_dir, 'test.db')
        try:
            os.makedirs(test_dir, exist_ok=True)
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            os.rmdir(test_dir)
            print("✅ Can create user directories and database files")
        except Exception as e:
            print(f"❌ Cannot create user directories/files: {e}")
            
    except Exception as e:
        print(f"⚠️  Permission check failed: {e}")
    
    # Generate recommendations
    print("\n💡 Recommendations:")
    generate_recommendations()

def generate_recommendations():
    """Generate recommendations based on findings"""
    
    recommendations = [
        "1. Ensure file paths in portal.db use format: /data/user_{user_id}/{db_id}.db",
        "2. Check that user upload process creates proper directory structure",
        "3. Verify Fly.io volume 'edgi_data_volume' is properly mounted to /data",
        "4. Check for any cleanup processes that might remove user directories",
        "5. Ensure adequate disk space and monitor usage regularly",
        "6. Verify user directory permissions allow database creation",
        "7. Consider implementing database backup/restore functionality",
        "8. Add monitoring for orphaned database files",
        "9. Implement path validation in database registration process"
    ]
    
    for rec in recommendations:
        print(f"   💡 {rec}")

def check_fly_volume_status():
    """Check Fly.io volume status if running on Fly"""
    print("\n🪂 Fly.io Volume Check:")
    
    # Check if we're running on Fly.io
    if os.getenv('FLY_APP_NAME'):
        print(f"✅ Running on Fly.io: {os.getenv('FLY_APP_NAME')}")
        print(f"📍 Region: {os.getenv('FLY_REGION', 'unknown')}")
        
        # Check volume mount
        if os.path.ismount('/data'):
            print("✅ /data is mounted as a volume")
        else:
            print("⚠️  /data is not mounted as a volume - data may not persist!")
            
        # Check if volume directory structure is intact
        data_dir = '/data'
        if os.path.exists(data_dir):
            user_dirs = [d for d in os.listdir(data_dir) if d.startswith('user_') and os.path.isdir(os.path.join(data_dir, d))]
            print(f"📊 Found {len(user_dirs)} user directories in volume")
    else:
        print("ℹ️  Not running on Fly.io (or FLY_APP_NAME not set)")

if __name__ == "__main__":
    diagnose_database_issues()
    check_fly_volume_status()
    
    print("\n" + "=" * 50)
    print("🔍 Diagnostic complete!")
    print("💡 Run this script regularly to monitor database persistence")