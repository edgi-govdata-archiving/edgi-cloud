#!/usr/bin/env python3
"""
EDGI Cloud Portal - Database Initialization Script with Sample Environmental Data
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
STATIC_DIR = os.getenv('EDGI_STATIC_DIR', "/app/static")

def create_sample_databases(portal_db, users):
    """Create sample environmental databases with test data."""
    print("📊 Creating sample environmental databases...")
    
    researcher_user = next(u for u in users if u['username'] == 'researcher')
    admin_user = next(u for u in users if u['username'] == 'admin')
    
    base_url = os.getenv('APP_URL', 'https://edgi-cloud.fly.dev')
    
    sample_databases = [
        {
            "db_id": uuid.uuid4().hex[:20],
            "user_id": researcher_user['user_id'],
            "db_name": "air_quality_monitoring",
            "website_url": f"{base_url}/air_quality_monitoring/",
            "status": "Published",
            "created_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            "file_path": os.path.join(DATA_DIR, researcher_user['user_id'], "air_quality_monitoring.db"),
            "title": "Air Quality Monitoring Network",
            "description": "Real-time and historical air quality measurements from monitoring stations across the region. Track PM2.5, PM10, ozone, and nitrogen dioxide concentrations with interactive data visualization."
        },
        {
            "db_id": uuid.uuid4().hex[:20],
            "user_id": admin_user['user_id'],
            "db_name": "water_quality_assessment",
            "website_url": f"{base_url}/water_quality_assessment/",
            "status": "Published",
            "created_at": (datetime.now(timezone.utc) - timedelta(days=15)).isoformat(),
            "file_path": os.path.join(DATA_DIR, admin_user['user_id'], "water_quality_assessment.db"),
            "title": "Water Quality Assessment Database",
            "description": "Comprehensive water quality data from rivers, lakes, and groundwater sources. Includes chemical analysis, bacterial counts, pH levels, and environmental indicators for water safety monitoring."
        },
        {
            "db_id": uuid.uuid4().hex[:20],
            "user_id": researcher_user['user_id'],
            "db_name": "climate_monitoring",
            "website_url": f"{base_url}/climate_monitoring/",
            "status": "Draft",
            "created_at": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
            "file_path": os.path.join(DATA_DIR, researcher_user['user_id'], "climate_monitoring.db"),
            "title": "Regional Climate Monitoring",
            "description": "Temperature, precipitation, and weather pattern data from meteorological stations. Supporting climate change research and environmental planning with detailed historical records."
        }
    ]
    
    for db_info in sample_databases:
        # Create user directory
        user_dir = os.path.dirname(db_info['file_path'])
        os.makedirs(user_dir, exist_ok=True)
        
        # Insert database record
        db_record = {k: v for k, v in db_info.items() if k not in ['title', 'description']}
        try:
            portal_db["databases"].insert(db_record, ignore=True)
            print(f"   ✅ Created database: {db_info['db_name']} ({db_info['status']})")
        except Exception as e:
            print(f"   ⚠️  Database {db_info['db_name']} may already exist: {e}")
        
        # Create database content
        create_database_content(portal_db, db_info)
        
        # Create sample data
        create_sample_data(db_info)

def create_database_content(portal_db, db_info):
    """Create custom content for sample databases."""
    
    content_records = [
        {
            "db_id": db_info['db_id'],
            "section": "title",
            "content": json.dumps({"content": db_info['title']}),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": db_info['db_id'],
            "section": "description",
            "content": json.dumps({
                "content": db_info['description'],
                "paragraphs": [db_info['description']]
            }),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": db_info['db_id'],
            "section": "header_image",
            "content": json.dumps({
                "image_url": "/static/default_header.jpg",
                "alt_text": "Environmental Data Portal",
                "credit_text": "EDGI Environmental Data Portal",
                "credit_url": "https://envirodatagov.org"
            }),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        },
        {
            "db_id": db_info['db_id'],
            "section": "footer",
            "content": json.dumps({
                "content": "Environmental monitoring data provided by EDGI research partners. Data licensed under ODbL for open environmental research.",
                "odbl_text": "Data licensed under ODbL",
                "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                "paragraphs": ["Environmental monitoring data provided by EDGI research partners. Data licensed under ODbL for open environmental research."]
            }),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": "system"
        }
    ]
    
    for content in content_records:
        try:
            portal_db["admin_content"].insert(content, ignore=True)
        except Exception as e:
            print(f"   ⚠️  Content for {db_info['db_name']} may already exist: {e}")

def create_sample_data(db_info):
    """Create sample environmental data for databases."""
    
    print(f"   📈 Creating sample data for {db_info['db_name']}...")
    
    # Create SQLite database
    user_db = sqlite_utils.Database(db_info['file_path'])
    
    if db_info['db_name'] == 'air_quality_monitoring':
        create_air_quality_data(user_db)
    elif db_info['db_name'] == 'water_quality_assessment':
        create_water_quality_data(user_db)
    elif db_info['db_name'] == 'climate_monitoring':
        create_climate_data(user_db)

def create_air_quality_data(db):
    """Create realistic air quality monitoring data."""
    
    # Monitoring stations
    stations = [
        {"station_id": "AQ001", "station_name": "Downtown Kalamazoo", "latitude": 42.2917, "longitude": -85.5872, "elevation": 240, "station_type": "Urban"},
        {"station_id": "AQ002", "station_name": "WMU Campus", "latitude": 42.2808, "longitude": -85.6324, "elevation": 260, "station_type": "Institutional"},
        {"station_id": "AQ003", "station_name": "Industrial District", "latitude": 42.3134, "longitude": -85.5635, "elevation": 220, "station_type": "Industrial"},
        {"station_id": "AQ004", "station_name": "Residential Area", "latitude": 42.2534, "longitude": -85.6142, "elevation": 280, "station_type": "Residential"}
    ]
    
    # Air quality measurements (last 60 days)
    measurements = []
    base_date = datetime.now(timezone.utc) - timedelta(days=60)
    
    for day in range(60):
        current_date = base_date + timedelta(days=day)
        for hour in range(0, 24, 2):  # Every 2 hours
            measurement_time = current_date + timedelta(hours=hour)
            
            for station in stations:
                # Simulate realistic air quality data with station-specific patterns
                industrial_factor = 1.5 if station['station_type'] == 'Industrial' else 1.0
                urban_factor = 1.2 if station['station_type'] == 'Urban' else 1.0
                
                pm25 = max(0, random.normalvariate(12, 5) * industrial_factor)
                pm10 = max(0, pm25 * random.uniform(1.2, 1.8))
                ozone = max(0, random.normalvariate(45, 15))
                no2 = max(0, random.normalvariate(20, 8) * urban_factor)
                
                measurements.append({
                    "measurement_id": uuid.uuid4().hex[:20],
                    "station_id": station['station_id'],
                    "timestamp": measurement_time.isoformat(),
                    "pm25_ugm3": round(pm25, 1),
                    "pm10_ugm3": round(pm10, 1),
                    "ozone_ppb": round(ozone, 1),
                    "no2_ppb": round(no2, 1),
                    "temperature_c": round(random.normalvariate(18, 8), 1),
                    "humidity_percent": round(random.uniform(30, 80), 1),
                    "wind_speed_ms": round(random.uniform(0, 15), 1),
                    "air_quality_index": min(500, max(0, round(pm25 * 4 + ozone * 0.8)))
                })
    
    # Insert data
    db["monitoring_stations"].insert_all(stations)
    db["air_quality_measurements"].insert_all(measurements)
    
    print(f"      ✅ {len(stations)} monitoring stations and {len(measurements)} air quality measurements")

def create_water_quality_data(db):
    """Create realistic water quality assessment data."""
    
    # Water sources
    sources = [
        {"source_id": "WQ001", "source_name": "Kalamazoo River - Downtown", "source_type": "River", "latitude": 42.2917, "longitude": -85.5872, "watershed": "Kalamazoo River Basin"},
        {"source_id": "WQ002", "source_name": "Asylum Lake", "source_type": "Lake", "latitude": 42.2534, "longitude": -85.6142, "watershed": "Kalamazoo River Basin"},
        {"source_id": "WQ003", "source_name": "Groundwater Station A", "source_type": "Groundwater", "latitude": 42.3134, "longitude": -85.5635, "watershed": "Kalamazoo River Basin"},
        {"source_id": "WQ004", "source_name": "Portage Creek", "source_type": "Stream", "latitude": 42.2808, "longitude": -85.6324, "watershed": "Kalamazoo River Basin"},
        {"source_id": "WQ005", "source_name": "Galesburg Reservoir", "source_type": "Reservoir", "latitude": 42.2900, "longitude": -85.4200, "watershed": "Kalamazoo River Basin"}
    ]
    
    # Water quality tests (weekly sampling for 24 weeks)
    tests = []
    base_date = datetime.now(timezone.utc) - timedelta(days=168)  # 24 weeks
    
    for week in range(24):
        test_date = base_date + timedelta(weeks=week)
        
        for source in sources:
            # Simulate seasonal and source-type variations
            season_factor = 1 + 0.3 * (week % 52 / 52.0)  # Seasonal variation
            pollution_factor = 1.2 if source['source_type'] == 'River' else 1.0
            
            tests.append({
                "test_id": uuid.uuid4().hex[:20],
                "source_id": source['source_id'],
                "test_date": test_date.date().isoformat(),
                "ph": round(random.normalvariate(7.2, 0.5), 2),
                "dissolved_oxygen_mgl": round(max(0, random.normalvariate(8.5, 1.2)), 2),
                "turbidity_ntu": round(max(0, random.uniform(0.5, 15) * pollution_factor), 2),
                "nitrate_mgl": round(max(0, random.uniform(0.1, 5) * pollution_factor), 2),
                "phosphate_mgl": round(max(0, random.uniform(0.01, 0.5) * pollution_factor), 3),
                "ecoli_cfu100ml": max(0, int(random.uniform(0, 200) * pollution_factor)),
                "temperature_c": round(random.normalvariate(15, 5) * season_factor, 1),
                "conductivity_uscm": round(max(0, random.normalvariate(350, 100)), 0),
                "chloride_mgl": round(max(0, random.uniform(5, 50)), 1),
                "sulfate_mgl": round(max(0, random.uniform(10, 100)), 1),
                "total_coliform_cfu100ml": max(0, int(random.uniform(10, 1000) * pollution_factor))
            })
    
    # Insert data
    db["water_sources"].insert_all(sources)
    db["water_quality_tests"].insert_all(tests)
    
    print(f"      ✅ {len(sources)} water sources and {len(tests)} quality tests")

def create_climate_data(db):
    """Create realistic climate monitoring data."""
    
    # Weather stations
    stations = [
        {"station_id": "WX001", "station_name": "Kalamazoo Central", "latitude": 42.2917, "longitude": -85.5872, "elevation": 240, "station_type": "Primary"},
        {"station_id": "WX002", "station_name": "Western Michigan University", "latitude": 42.2808, "longitude": -85.6324, "elevation": 260, "station_type": "Research"},
        {"station_id": "WX003", "station_name": "Portage Weather Station", "latitude": 42.2011, "longitude": -85.5800, "elevation": 270, "station_type": "Automated"}
    ]
    
    # Daily weather data (2 years of data)
    weather_data = []
    base_date = datetime.now(timezone.utc) - timedelta(days=730)
    
    for day in range(730):
        current_date = base_date + timedelta(days=day)
        # Simulate seasonal temperature patterns for Michigan
        day_of_year = current_date.timetuple().tm_yday
        seasonal_temp = 10 + 15 * (1 - abs((day_of_year - 180) / 183.0))  # Peak in summer
        
        for station in stations:
            # Add some station-specific variation
            elevation_adjust = (station['elevation'] - 250) * -0.01  # Higher elevation = cooler
            
            temp_high = seasonal_temp + random.normalvariate(5, 3) + elevation_adjust
            temp_low = temp_high - random.uniform(5, 15)
            
            # Precipitation patterns (more in spring/fall)
            precip_season_factor = 1 + 0.5 * abs((day_of_year - 180) / 183.0)
            precipitation = max(0, random.expovariate(2.0) * precip_season_factor * 10)
            
            weather_data.append({
                "record_id": uuid.uuid4().hex[:20],
                "station_id": station['station_id'],
                "date": current_date.date().isoformat(),
                "temperature_high_c": round(temp_high, 1),
                "temperature_low_c": round(temp_low, 1),
                "temperature_avg_c": round((temp_high + temp_low) / 2, 1),
                "precipitation_mm": round(precipitation, 1),
                "humidity_percent": round(random.uniform(40, 90), 1),
                "wind_speed_kmh": round(max(0, random.normalvariate(12, 5)), 1),
                "wind_direction_deg": round(random.uniform(0, 360), 0),
                "pressure_hpa": round(random.normalvariate(1013, 10), 1),
                "solar_radiation_mjm2": round(max(0, random.uniform(5, 25)), 2),
                "snow_depth_cm": round(max(0, random.normalvariate(0, 5) if temp_high < 2 else 0), 1)
            })
    
    # Insert data
    db["weather_stations"].insert_all(stations)
    db["daily_weather"].insert_all(weather_data)
    
    print(f"      ✅ {len(stations)} weather stations and {len(weather_data)} daily weather records")

def main():
    """Main initialization function."""
    try:
        print("🌱 Initializing EDGI Cloud Portal Database with Sample Environmental Data...")
        
        # Ensure directories exist
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(STATIC_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(PORTAL_DB_PATH), exist_ok=True)
        
        # Check if database already exists
        if os.path.exists(PORTAL_DB_PATH):
            print(f"📊 Database already exists at: {PORTAL_DB_PATH}")
            # Check if sample databases exist
            portal_db = sqlite_utils.Database(PORTAL_DB_PATH)
            existing_dbs = list(portal_db.execute("SELECT COUNT(*) as count FROM databases WHERE status = 'Published'"))
            if existing_dbs[0]['count'] > 0:
                print("   Sample databases already exist, skipping creation")
                return
            else:
                print("   Adding sample environmental databases...")
                users_result = list(portal_db.execute("SELECT * FROM users"))
                if len(users_result) >= 2:
                    create_sample_databases(portal_db, users_result)
                    print("✅ Sample databases added to existing portal!")
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
                "section": "header_image",
                "content": json.dumps({
                    "image_url": "/static/default_header.jpg",
                    "alt_text": "EDGI Environmental Data Portal",
                    "credit_text": "EDGI - Environmental Data & Governance Initiative",
                    "credit_url": "https://envirodatagov.org"
                }),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": "system"
            },
            {
                "db_id": None,
                "section": "info",
                "content": json.dumps({
                    "content": "The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites. Upload your data, customize your portal, and make environmental information accessible to the public.",
                    "paragraphs": ["The EDGI Datasette Cloud Portal enables researchers and organizations to share environmental datasets as interactive websites.", "Upload your data, customize your portal, and make environmental information accessible to the public."]
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
        
        # Create sample environmental databases
        create_sample_databases(portal_db, users)
        
        # Create default header placeholder
        default_header = os.path.join(STATIC_DIR, 'default_header.jpg')
        if not os.path.exists(default_header):
            with open(default_header, 'w') as f:
                f.write("# EDGI Environmental Data Portal Header Image Placeholder")
        
        print("✅ Database initialization complete!")
        print(f"📊 Database created at: {PORTAL_DB_PATH}")
        print(f"🔐 Login: admin / {test_password} (System Admin)")
        print(f"🔐 Login: researcher / {test_password} (User)")
        print("\n📈 Sample Environmental Databases:")
        print("   🌬️  Air Quality Monitoring - 1,440 measurements from 4 stations")
        print("   💧 Water Quality Assessment - 120 tests from 5 water sources")
        print("   🌡️  Climate Monitoring - 2,190 daily weather records from 3 stations")
        
    except Exception as e:
        print(f"❌ ERROR: Database initialization failed!")
        print(f"Error details: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    main()