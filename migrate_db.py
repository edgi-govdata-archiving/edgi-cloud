#!/usr/bin/env python3
"""
Simple Database Migration - Add missing columns
"""

import sqlite_utils
import os
from datetime import datetime, timezone

def migrate_database():
    PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
    
    if not os.path.exists(PORTAL_DB_PATH):
        print("❌ Database not found")
        return
    
    print("🔄 Adding missing columns to database...")
    
    try:
        db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        # Add missing columns one by one
        missing_columns = [
            "updated_at TEXT",
            "trashed_at TEXT", 
            "restore_deadline TEXT",
            "deletion_reason TEXT",
            "deleted_by_user_id TEXT"
        ]
        
        for column in missing_columns:
            column_name = column.split()[0]
            try:
                db.executescript(f"ALTER TABLE databases ADD COLUMN {column};")
                print(f"   ✅ Added: {column_name}")
            except Exception as e:
                if "duplicate column" in str(e).lower():
                    print(f"   ⚪ Exists: {column_name}")
                else:
                    print(f"   ❌ Failed: {column_name} - {e}")
        
        # Set updated_at for existing records
        current_time = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE databases SET updated_at = created_at WHERE updated_at IS NULL")
        
        print("✅ Migration completed!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")

if __name__ == "__main__":
    migrate_database()