#!/usr/bin/env python3
"""
Dynamic Metadata Generator for User Databases
Automatically creates metadata.json configuration for all registered databases
"""
import sqlite3
import json
import os
from datetime import datetime

def generate_dynamic_metadata():
    """Generate metadata.json with all registered databases"""
    
    portal_db_path = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
    metadata_path = "/app/metadata.json"
    
    # Base metadata structure
    base_metadata = {
        "license": "ODbL",
        "license_url": "https://opendatacommons.org/licenses/odbl/",
        "source": "EDGI Cloud Portal - Dynamic Databases",
        "source_url": os.getenv('APP_URL', 'https://edgi-cloud.fly.dev'),
        "databases": {},
        "plugins": {
            "datasette-cluster-map": {
                "latitude": "latitude",
                "longitude": "longitude"
            },
            "datasette-cluster-map-geojson": {
                "latitude": "latitude", 
                "longitude": "longitude",
                "geojson": True
            },
            "datasette-render-markdown": {
                "databases": {}
            },
            "datasette-auth-tokens": {
                "secret_key": os.getenv('CSRF_SECRET_KEY', 'fd93c677e08304855095d266835d86c9a2eadda209d6c2c9fe0bea65fe0941d4')
            },
            "datasette-template-sql": {},
            "settings": {
                "csrf_protect": True
            }
        }
    }
    
    if not os.path.exists(portal_db_path):
        print("⚠️  Portal database not found, using base metadata")
        with open(metadata_path, 'w') as f:
            json.dump(base_metadata, f, indent=2)
        return
    
    try:
        conn = sqlite3.connect(portal_db_path)
        cursor = conn.cursor()
        
        # Get all active databases
        cursor.execute("""
            SELECT db_name, file_path, website_url, created_at
            FROM databases 
            WHERE status = 'active' AND trashed_at IS NULL
        """)
        
        databases = cursor.fetchall()
        
        for db_name, file_path, website_url, created_at in databases:
            print(f"📊 Processing database: {db_name}")
            
            # Get database table information
            db_config = analyze_database_structure(file_path, db_name, website_url)
            
            if db_config:
                base_metadata["databases"][db_name] = db_config["database_config"]
                
                # Add render-markdown configuration if markdown columns detected
                if db_config["markdown_columns"]:
                    base_metadata["plugins"]["datasette-render-markdown"]["databases"][db_name] = {
                        "tables": db_config["markdown_columns"]
                    }
        
        # Save the generated metadata
        with open(metadata_path, 'w') as f:
            json.dump(base_metadata, f, indent=2)
        
        print(f"✅ Generated metadata for {len(databases)} databases")
        conn.close()
        
    except Exception as e:
        print(f"❌ Error generating metadata: {e}")
        # Fallback to base metadata
        with open(metadata_path, 'w') as f:
            json.dump(base_metadata, f, indent=2)

def analyze_database_structure(file_path, db_name, website_url):
    """Analyze database structure to generate metadata"""
    
    if not os.path.exists(file_path):
        print(f"⚠️  Database file not found: {file_path}")
        return None
    
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]
        
        database_config = {
            "title": db_name.replace('_', ' ').title(),
            "description": f"Data from {website_url}" if website_url else f"User uploaded database: {db_name}",
            "tables": {}
        }
        
        markdown_columns = {}
        
        for table in tables:
            print(f"   📋 Analyzing table: {table}")
            
            # Get table info
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            
            # Get row count
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = cursor.fetchone()[0]
            except:
                row_count = 0
            
            table_config = {
                "title": table.replace('_', ' ').title(),
                "description": f"Table with {row_count:,} records"
            }
            
            # Detect common column patterns for facets
            facet_columns = []
            markdown_cols = []
            
            for col_info in columns:
                col_name = col_info[1].lower()
                col_type = col_info[2].upper()
                
                # Common facet patterns
                if any(pattern in col_name for pattern in ['state', 'county', 'city', 'category', 'type', 'status', 'code']):
                    facet_columns.append(col_info[1])
                
                # Detect potential markdown columns
                if any(pattern in col_name for pattern in ['description', 'notes', 'comment', 'report', 'summary', 'detail', 'id', 'file_key', 'datasette_link']):
                    markdown_cols.append(col_info[1])
                
                # Date columns for facets
                if 'date' in col_name or col_name.endswith('_at'):
                    facet_columns.append(col_info[1])
            
            # Limit facets to reasonable number
            if facet_columns:
                table_config["facets"] = facet_columns[:5]
            
            # Set up FTS if we detect text columns
            text_columns = [col[1] for col in columns if 'TEXT' in col[2] or 'VARCHAR' in col[2]]
            if text_columns and row_count < 100000:  # Only for smaller tables
                # Check if FTS table exists
                fts_table = f"{table}_fts"
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (fts_table,))
                if cursor.fetchone():
                    table_config["fts_table"] = fts_table
                    table_config["fts_pk"] = "rowid"
            
            database_config["tables"][table] = table_config
            
            # Add markdown columns if found
            if markdown_cols:
                markdown_columns[table] = {
                    "columns": markdown_cols
                }
        
        conn.close()
        
        return {
            "database_config": database_config,
            "markdown_columns": markdown_columns
        }
        
    except Exception as e:
        print(f"❌ Error analyzing {db_name}: {e}")
        return None

def get_predefined_configs():
    """Get predefined configurations for special databases"""
    return {
        "risk_management_plans": {
            "database_config": {
                "title": "EPA Risk Management Plans",
                "description": "EPA Risk Management Plan Search Tool data",
                "tables": {
                    "facility_view": {
                        "title": "Facilities",
                        "description": "Details of facilities in the EPA Risk Management Plans, including associated chemical names and NAICS codes.",
                        "facets": ["state", "county", "naics_codes"],
                        "fts_table": "facility_fts",
                        "fts_pk": "epa_facility_id"
                    },
                    "rmp_facility": {
                        "title": "Facilities",
                        "description": "Details of facilities in the EPA Risk Management Plans, including associated chemical names and NAICS codes.",
                        "facets": ["state", "county"],
                        "fts_table": "facility_fts", 
                        "fts_pk": "epa_facility_id"
                    },
                    "facility_accidents_view": {
                        "title": "Facility Accidents",
                        "description": "Details of accidents in the EPA Risk Management Plans, including associated chemical names and NAICS codes.",
                        "facets": ["state", "county", "date_of_accident", "naics_code"],
                        "fts_table": "facility_accidents_fts",
                        "fts_pk": "rowid"
                    },
                    "accident_chemicals_view": {
                        "title": "Accident Chemicals", 
                        "description": "Details of chemicals released during accidents in the EPA Risk Management Plans.",
                        "facets": ["state", "county", "date_of_accident", "chemical_name"],
                        "fts_table": "accident_chemicals_fts",
                        "fts_pk": "accident_chemical_id"
                    },
                    "tbl_accident_details": {
                        "title": "Detailed Accidents",
                        "description": "Details of accidents in the EPA Risk Management Plans, including associated chemicals and injuries."
                    },
                    "rmp_chemical": {
                        "title": "Regulated Chemicals",
                        "description": "Regulated chemicals with their CAS numbers and classification."
                    },
                    "rmp_naics": {
                        "title": "Industry Codes",
                        "description": "NAICS industry codes and their descriptions."
                    }
                }
            },
            "markdown_columns": {
                "facility_view": {
                    "columns": ["report", "popup"]
                },
                "rmp_facility": {
                    "columns": ["report", "popup"] 
                }
            }
        }
    }

if __name__ == "__main__":
    generate_dynamic_metadata()