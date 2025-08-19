#!/usr/bin/env python3
"""
Database Migration Script - Add missing columns to portal.db
Run this on Fly.io to update existing database
"""

import sqlite_utils
import os
from datetime import datetime, timezone

def migrate_database():
    """Migrate existing database to add missing columns."""
    PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
    
    if not os.path.exists(PORTAL_DB_PATH):
        print("❌ No database found to migrate")
        return
    
    print("🔄 Migrating database schema...")
    
    try:
        db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        # Check existing columns
        existing_columns = [col.name for col in db['databases'].columns]
        print(f"📋 Existing columns: {existing_columns}")
        
        # Add missing columns
        missing_columns = [
            ("updated_at", "TEXT"),
            ("deletion_reason", "TEXT")
        ]
        
        for column_name, column_type in missing_columns:
            if column_name not in existing_columns:
                try:
                    db.executescript(f"ALTER TABLE databases ADD COLUMN {column_name} {column_type};")
                    print(f"   ✅ Added column: {column_name}")
                except Exception as e:
                    print(f"   ❌ Failed to add {column_name}: {e}")
            else:
                print(f"   ⚪ Column {column_name} already exists")
        
        # Update existing records with updated_at if NULL
        current_time = datetime.now(timezone.utc).isoformat()
        result = db.execute("UPDATE databases SET updated_at = ? WHERE updated_at IS NULL", [current_time])
        updated_count = result.rowcount if hasattr(result, 'rowcount') else 0
        print(f"   ✅ Updated {updated_count} records with timestamp")
        
        print("✅ Migration completed successfully")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise

if __name__ == "__main__":
    migrate_database()