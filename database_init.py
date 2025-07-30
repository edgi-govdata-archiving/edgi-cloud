#!/usr/bin/env python3
"""
EDGI Cloud Portal - Database Initialization Script
Creates portal.db with test data and sample environmental databases
"""

import sqlite_utils
import bcrypt
import uuid
import json
import os
import pandas as pd
from datetime import datetime, timedelta
import random

# Configuration
PORTAL_DB_PATH = "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db"
DATA_DIR = "C:/MS Data Science - WMU/EDGI/edgi-cloud/data"
STATIC_DIR = "C:/MS Data Science - WMU/EDGI/edgi-cloud/static"

def init_portal_database():
    """Initialize the main portal database with test data."""
    
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

    return portal_db

def create_test_users(portal_db):
    """Create test users."""
    print("Creating test users...")
    
    # Test password
    test_password = "password123"
    hashed_password = bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    users = [
        {
            "user_id": str(uuid.uuid4()),
            "username": "admin",
            "password_hash": hashed_password,
            "role": "system_admin",
            "email": "admin@edgi.org",
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "user_id": str(uuid.uuid4()),
            "username": "researcher1",
            "password_hash": hashed_password,
            "role": "system_user",
            "email": "researcher1@university.edu",
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "user_id": str(uuid.uuid4()),
            "username": "analyst",
            "password_hash": hashed_password,
            "role": "system_user",
            "email": "analyst@environmental.org",
            "created_at": datetime.utcnow().isoformat()
        }
    ]
    
    # Insert users
    for user in users:
        portal_db["users"].insert(user, ignore=True)
        print(f"Created user: {user['username']} ({user['role']})")
    
    return users

def create_portal_content(portal_db):
    """Create portal-wide content."""
    print("Creating portal content...")
    
    portal_content = [
        {
            "db_id": None,
            "section": "title",
            "content": json.dumps({"content": "EDGI Datasette Cloud Portal"}),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": None,
            "section": "header_image",
            "content": json.dumps({
                "image_url": "/static/default_header.jpg",
                "alt_text": "EDGI Environmental Data Portal",
                "credit_text": "EDGI - Environmental Data & Governance Initiative",
                "credit_url": "https://envirodatagov.org"
            }),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": None,
            "section": "info",
            "content": json.dumps({
                "content": "The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites. Upload your data, customize your portal, and make environmental information accessible to the public.",
                "paragraphs": [
                    "The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites.",
                    "Upload your data, customize your portal, and make environmental information accessible to the public."
                ]
            }),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": None,
            "section": "footer",
            "content": json.dumps({
                "content": "Made with ❤ by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/)",
                "odbl_text": "Data licensed under ODbL",
                "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                "paragraphs": [
                    "Made with ❤ by <a href=\"https://envirodatagov.org\">EDGI</a> and <a href=\"https://screening-tools.com/\">Public Environmental Data Partners</a>"
                ]
            }),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        }
    ]
    
    for content in portal_content:
        portal_db["admin_content"].insert(content, ignore=True)

def create_sample_databases(portal_db, users):
    """Create sample databases with test data."""
    print("Creating sample databases...")
    
    # Ensure data directories exist
    os.makedirs(DATA_DIR, exist_ok=True)
    
    researcher_user = next(u for u in users if u['username'] == 'researcher1')
    analyst_user = next(u for u in users if u['username'] == 'analyst')
    
    sample_databases = [
        {
            "db_id": str(uuid.uuid4()),
            "user_id": researcher_user['user_id'],
            "db_name": "air_quality_monitoring",
            "website_url": "http://localhost:8001/air_quality_monitoring/",
            "status": "Published",
            "created_at": (datetime.utcnow() - timedelta(days=30)).isoformat(),
            "file_path": os.path.join(DATA_DIR, researcher_user['user_id'], "air_quality_monitoring.db"),
            "title": "Air Quality Monitoring Network",
            "description": "Real-time and historical air quality measurements from monitoring stations across the region. Includes PM2.5, PM10, ozone, and nitrogen dioxide concentrations."
        },
        {
            "db_id": str(uuid.uuid4()),
            "user_id": analyst_user['user_id'],
            "db_name": "water_quality_assessment",
            "website_url": "http://localhost:8001/water_quality_assessment/",
            "status": "Published",
            "created_at": (datetime.utcnow() - timedelta(days=15)).isoformat(),
            "file_path": os.path.join(DATA_DIR, analyst_user['user_id'], "water_quality_assessment.db"),
            "title": "Water Quality Assessment Database",
            "description": "Comprehensive water quality data from rivers, lakes, and groundwater sources. Includes chemical analysis, bacterial counts, and environmental indicators."
        },
        {
            "db_id": str(uuid.uuid4()),
            "user_id": researcher_user['user_id'],
            "db_name": "climate_monitoring",
            "website_url": "http://localhost:8001/climate_monitoring/",
            "status": "Draft",
            "created_at": (datetime.utcnow() - timedelta(days=7)).isoformat(),
            "file_path": os.path.join(DATA_DIR, researcher_user['user_id'], "climate_monitoring.db"),
            "title": "Regional Climate Monitoring",
            "description": "Temperature, precipitation, and weather pattern data from meteorological stations. Supporting climate change research and environmental planning."
        }
    ]
    
    for db_info in sample_databases:
        # Create user directory
        user_dir = os.path.dirname(db_info['file_path'])
        os.makedirs(user_dir, exist_ok=True)
        
        # Insert database record
        db_record = {k: v for k, v in db_info.items() if k not in ['title', 'description']}
        portal_db["databases"].insert(db_record, ignore=True)
        
        # Create database content
        create_database_content(portal_db, db_info)
        
        # Create sample data
        create_sample_data(db_info)
        
        print(f"Created database: {db_info['db_name']} ({db_info['status']})")

def create_database_content(portal_db, db_info):
    """Create content for a sample database."""
    
    content_records = [
        {
            "db_id": db_info['db_id'],
            "section": "title",
            "content": json.dumps({"content": db_info['title']}),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": db_info['db_id'],
            "section": "description",
            "content": json.dumps({
                "content": db_info['description'],
                "paragraphs": [db_info['description']]
            }),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": db_info['db_id'],
            "section": "header_image",
            "content": json.dumps({
                "image_url": f"/static/{db_info['db_id']}_header.jpg",
                "alt_text": "Environmental Data",
                "credit_text": "Environmental Data Portal",
                "credit_url": ""
            }),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": db_info['db_id'],
            "section": "footer",
            "content": json.dumps({
                "content": "Made with EDGI",
                "odbl_text": "Data licensed under ODbL",
                "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                "paragraphs": ["Made with EDGI"]
            }),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "system"
        }
    ]
    
    for content in content_records:
        portal_db["admin_content"].insert(content, ignore=True)

def create_sample_data(db_info):
    """Create sample environmental data for databases."""
    
    # Create SQLite database
    user_db = sqlite_utils.Database(db_info['file_path'])
    
    if db_info['db_name'] == 'air_quality_monitoring':
        create_air_quality_data(user_db)
    elif db_info['db_name'] == 'water_quality_assessment':
        create_water_quality_data(user_db)
    elif db_info['db_name'] == 'climate_monitoring':
        create_climate_data(user_db)

def create_air_quality_data(db):
    """Create air quality monitoring data."""
    
    # Monitoring stations
    stations = [
        {"station_id": "AQ001", "station_name": "Downtown", "latitude": 42.2917, "longitude": -85.5872, "elevation": 240},
        {"station_id": "AQ002", "station_name": "University", "latitude": 42.2808, "longitude": -85.6324, "elevation": 260},
        {"station_id": "AQ003", "station_name": "Industrial", "latitude": 42.3134, "longitude": -85.5635, "elevation": 220},
        {"station_id": "AQ004", "station_name": "Residential", "latitude": 42.2534, "longitude": -85.6142, "elevation": 280}
    ]
    
    # Air quality measurements (last 30 days)
    measurements = []
    base_date = datetime.utcnow() - timedelta(days=30)
    
    for day in range(30):
        current_date = base_date + timedelta(days=day)
        for hour in range(0, 24, 3):  # Every 3 hours
            measurement_time = current_date + timedelta(hours=hour)
            
            for station in stations:
                # Simulate realistic air quality data
                pm25 = random.normalvariate(12, 5) + (2 if station['station_name'] == 'Industrial' else 0)
                pm10 = pm25 * random.uniform(1.2, 1.8)
                ozone = random.normalvariate(45, 15)
                no2 = random.normalvariate(20, 8) + (5 if station['station_name'] == 'Industrial' else 0)
                
                measurements.append({
                    "measurement_id": str(uuid.uuid4()),
                    "station_id": station['station_id'],
                    "timestamp": measurement_time.isoformat(),
                    "pm25_ugm3": max(0, round(pm25, 1)),
                    "pm10_ugm3": max(0, round(pm10, 1)),
                    "ozone_ppb": max(0, round(ozone, 1)),
                    "no2_ppb": max(0, round(no2, 1)),
                    "temperature_c": round(random.normalvariate(18, 8), 1),
                    "humidity_percent": round(random.uniform(30, 80), 1),
                    "wind_speed_ms": round(random.uniform(0, 15), 1)
                })
    
    # Insert data
    db["monitoring_stations"].insert_all(stations)
    db["air_quality_measurements"].insert_all(measurements)
    
    print(f"  Created {len(stations)} monitoring stations and {len(measurements)} air quality measurements")

def create_water_quality_data(db):
    """Create water quality assessment data."""
    
    # Water sources
    sources = [
        {"source_id": "WQ001", "source_name": "Kalamazoo River - Downtown", "source_type": "River", "latitude": 42.2917, "longitude": -85.5872},
        {"source_id": "WQ002", "source_name": "Asylum Lake", "source_type": "Lake", "latitude": 42.2534, "longitude": -85.6142},
        {"source_id": "WQ003", "source_name": "Groundwater Station A", "source_type": "Groundwater", "latitude": 42.3134, "longitude": -85.5635},
        {"source_id": "WQ004", "source_name": "Portage Creek", "source_type": "Stream", "latitude": 42.2808, "longitude": -85.6324}
    ]
    
    # Water quality tests
    tests = []
    base_date = datetime.utcnow() - timedelta(days=90)
    
    for week in range(12):  # Weekly sampling for 12 weeks
        test_date = base_date + timedelta(weeks=week)
        
        for source in sources:
            tests.append({
                "test_id": str(uuid.uuid4()),
                "source_id": source['source_id'],
                "test_date": test_date.date().isoformat(),
                "ph": round(random.normalvariate(7.2, 0.5), 2),
                "dissolved_oxygen_mgl": round(random.normalvariate(8.5, 1.2), 2),
                "turbidity_ntu": round(random.uniform(0.5, 15), 2),
                "nitrate_mgl": round(random.uniform(0.1, 5), 2),
                "phosphate_mgl": round(random.uniform(0.01, 0.5), 3),
                "ecoli_cfu100ml": random.randint(0, 200),
                "temperature_c": round(random.normalvariate(15, 5), 1),
                "conductivity_uscm": round(random.normalvariate(350, 100), 0)
            })
    
    # Insert data
    db["water_sources"].insert_all(sources)
    db["water_quality_tests"].insert_all(tests)
    
    print(f"  Created {len(sources)} water sources and {len(tests)} quality tests")

def create_climate_data(db):
    """Create climate monitoring data."""
    
    # Weather stations
    stations = [
        {"station_id": "WX001", "station_name": "Kalamazoo Central", "latitude": 42.2917, "longitude": -85.5872, "elevation": 240},
        {"station_id": "WX002", "station_name": "Western Michigan University", "latitude": 42.2808, "longitude": -85.6324, "elevation": 260}
    ]
    
    # Daily weather data (last year)
    weather_data = []
    base_date = datetime.utcnow() - timedelta(days=365)
    
    for day in range(365):
        current_date = base_date + timedelta(days=day)
        # Simulate seasonal temperature patterns
        day_of_year = current_date.timetuple().tm_yday
        seasonal_temp = 15 + 10 * math.cos((day_of_year - 180) * 2 * math.pi / 365)
        
        for station in stations:
            temp_high = seasonal_temp + random.normalvariate(5, 3)
            temp_low = temp_high - random.uniform(5, 15)
            
            weather_data.append({
                "record_id": str(uuid.uuid4()),
                "station_id": station['station_id'],
                "date": current_date.date().isoformat(),
                "temperature_high_c": round(temp_high, 1),
                "temperature_low_c": round(temp_low, 1),
                "precipitation_mm": round(max(0, random.exponential(2)), 1),
                "humidity_percent": round(random.uniform(40, 90), 1),
                "wind_speed_kmh": round(random.uniform(5, 25), 1),
                "pressure_hpa": round(random.normalvariate(1013, 10), 1),
                "solar_radiation_mjm2": round(random.uniform(5, 25), 2)
            })
    
    # Insert data
    db["weather_stations"].insert_all(stations)
    db["daily_weather"].insert_all(weather_data)
    
    print(f"  Created {len(stations)} weather stations and {len(weather_data)} daily records")

def create_activity_logs(portal_db, users):
    """Create sample activity logs."""
    print("Creating activity logs...")
    
    activities = []
    base_date = datetime.utcnow() - timedelta(days=30)
    
    activity_types = [
        ("login", "User logged in"),
        ("create_database", "Created new database"),
        ("upload_csv", "Uploaded CSV data"),
        ("publish_database", "Published database"),
        ("edit_content", "Updated database content")
    ]
    
    for day in range(30):
        current_date = base_date + timedelta(days=day)
        # Random number of activities per day
        for _ in range(random.randint(2, 8)):
            user = random.choice(users)
            action, detail_template = random.choice(activity_types)
            
            activities.append({
                "log_id": str(uuid.uuid4()),
                "user_id": user['user_id'],
                "action": action,
                "details": f"{detail_template} - {user['username']}",
                "timestamp": current_date.isoformat()
            })
    
    portal_db["activity_logs"].insert_all(activities)
    print(f"  Created {len(activities)} activity log entries")

def main():
    """Main initialization function."""
    print("🌱 Initializing EDGI Cloud Portal Database...")
    print("=" * 50)
    
    # Initialize database
    portal_db = init_portal_database()
    
    # Create test data
    users = create_test_users(portal_db)
    create_portal_content(portal_db)
    create_sample_databases(portal_db, users)
    create_activity_logs(portal_db, users)
    
    print("\n" + "=" * 50)
    print("✅ Database initialization complete!")
    print("\n📊 Test Data Summary:")
    print(f"   👥 Users: {len(users)}")
    print(f"   🗄️  Databases: 3 (2 published, 1 draft)")
    print(f"   📈 Air Quality: ~2,400 measurements")
    print(f"   💧 Water Quality: ~48 test results")
    print(f"   🌤️  Climate: ~730 daily records")
    print("\n🔐 Test Login Credentials:")
    print("   Username: admin, Password: password123 (System Admin)")
    print("   Username: researcher1, Password: password123 (User)")
    print("   Username: analyst, Password: password123 (User)")
    print("\n🚀 Ready to start Datasette!")

if __name__ == "__main__":
    import math  # Add missing import
    main()