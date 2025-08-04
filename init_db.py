#!/usr/bin/env python3
"""
EDGI Cloud Portal - Database Initialization Script (NO PANDAS)
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

def main():
    """Main initialization function."""
    try:
        print("🌱 Initializing EDGI Cloud Portal Database...")
        
        # Ensure directories exist
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(STATIC_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(PORTAL_DB_PATH), exist_ok=True)
        
        # Check if database already exists
        if os.path.exists(PORTAL_DB_PATH):
            print(f"📊 Database already exists at: {PORTAL_DB_PATH}")
            return
        
        print(f"🗄️  Creating portal database at: {PORTAL_DB_PATH}")
        
        # Create portal database
        portal_db = sqlite_utils.Database(PORTAL_DB_PATH)
        
        # Create tables
        print("Creating portal database tables...")
        
        # Users table
        portal_db.create_table("users", {
            "user_id": str,
            "username": str,
            "password_hash": str,
            "role": str,
            "email": str,
            "created_at": str
        }, pk="user_id", if_not_exists=True)

        # Databases table
        portal_db.create_table("databases", {
            "db_id": str,
            "user_id": str,
            "db_name": str,
            "website_url": str,
            "status": str,
            "created_at": str,
            "deleted_at": str,
            "file_path": str
        }, pk="db_id", if_not_exists=True)

        # Admin content table
        portal_db.create_table("admin_content", {
            "db_id": str,
            "section": str,
            "content": str,
            "updated_at": str,
            "updated_by": str
        }, pk=("db_id", "section"), if_not_exists=True)

        # Activity logs table
        portal_db.create_table("activity_logs", {
            "log_id": str,
            "user_id": str,
            "action": str,
            "details": str,
            "timestamp": str
        }, pk="log_id", if_not_exists=True)

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
            }
        ]
        
        # Insert users
        for user in users:
            portal_db["users"].insert(user, ignore=True)
            print(f"   ✅ Created user: {user['username']} ({user['role']})")
        
        # Create portal content
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
                    "content": "The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites.",
                    "paragraphs": ["The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites."]
                }),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": "system"
            },
            {
                "db_id": None,
                "section": "footer",
                "content": json.dumps({
                    "content": "Made with ❤ by EDGI and Public Environmental Data Partners.",
                    "odbl_text": "Data licensed under ODbL",
                    "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                    "paragraphs": ["Made with ❤ by EDGI and Public Environmental Data Partners."]
                }),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": "system"
            }
        ]
        
        for content in portal_content:
            portal_db["admin_content"].insert(content, ignore=True)
        
        # Create default header placeholder
        default_header = os.path.join(STATIC_DIR, 'default_header.jpg')
        if not os.path.exists(default_header):
            with open(default_header, 'w') as f:
                f.write("# EDGI Environmental Data Portal Header Image Placeholder")
        
        print("✅ Database initialization complete!")
        print(f"📊 Database created at: {PORTAL_DB_PATH}")
        print(f"🔐 Login: admin / {test_password} (System Admin)")
        print(f"🔐 Login: researcher / {test_password} (User)")
        
    except Exception as e:
        print(f"❌ ERROR: Database initialization failed!")
        print(f"Error details: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    main()