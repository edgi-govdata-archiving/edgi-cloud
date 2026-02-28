#!/usr/bin/env python3
"""
Enhanced metadata generation with proper tile server configuration
The dynamic plugin handles markdown configuration
"""

import json
import os
import sqlite3

# Add the plugins directory to Python path for imports
import sys
PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGINS_DIR not in sys.path:
    sys.path.insert(0, PLUGINS_DIR)
ROOT_DIR = os.path.dirname(PLUGINS_DIR)
DATA_DIR = os.getenv("RESETTE_DATA_DIR", os.path.join(ROOT_DIR, "data"))
STATIC_DIR = os.getenv('RESETTE_STATIC_DIR', os.path.join(ROOT_DIR, "static"))
PORTAL_DB_PATH = os.getenv('PORTAL_DB_PATH', os.path.join(DATA_DIR, "portal.db"))

def generate_metadata():
    """Generate metadata.json with proper tile servers - markdown handled by dynamic plugin"""

    # Base metadata structure with CartoDB tile servers to avoid OpenStreetMap blocking
    base_metadata = {
        "license": "ODbL",
        "license_url": "https://opendatacommons.org/licenses/odbl/",
        "source": "EDGI Cloud Portal",
        "source_url": "https://edgi-cloud.fly.dev/",
        "databases": {},
        "plugins": {
            "datasette-cluster-map": {
                "latitude": "latitude",
                "longitude": "longitude",
                "tile_layer": "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",
                "tile_layer_attribution": "&copy; <a href=\"https://www.openstreetmap.org/copyright\">OpenStreetMap</a> contributors &copy; <a href=\"https://carto.com/attributions\">CARTO</a>"
            },
            "datasette-cluster-map-geojson": {
                "latitude": "latitude",
                "longitude": "longitude",
                "geojson": True,
                "tile_layer": "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",
                "tile_layer_attribution": "&copy; <a href=\"https://www.openstreetmap.org/copyright\">OpenStreetMap</a> contributors &copy; <a href=\"https://carto.com/attributions\">CARTO</a>"
            },
            "datasette-auth-tokens": {
                "secret_key": "fd93c677e08304855095d266835d86c9a2eadda209d6c2c9fe0bea65fe0941d4"
            },
            "datasette-template-sql": {},
            "settings": {
                "csrf_protect": True
            },
            "datasette-block-robots": {
            "allow_only_index": True
            }
        }
    }

    portal_db_path = None
    possible_paths = [
        os.getenv('PORTAL_DB_PATH'),  # Environment variable
        "/data/portal.db",            # Docker/production
        os.path.join(ROOT_DIR, "data", "portal.db"),  # Absolute local
        os.path.join(DATA_DIR, "portal.db"),    # Data dir
        os.path.join(DATA_DIR, "..", "portal.db"),    # Parent of data dir
        "portal.db"                   # Current directory fallback
    ]

    # Find the portal database
    for path in possible_paths:
        if path and os.path.exists(path):
            portal_db_path = path
            print(f"Found portal database at: {path}")
            break

    if not portal_db_path:
        print("Portal database not found. Checked paths:")
        for path in possible_paths:
            if path:
                print(f"  - {path} {'(exists)' if os.path.exists(path) else '(not found)'}")
        print("Database registration will be skipped. Some features may not work.")
        return base_metadata

    try:
        # Connect to portal database
        conn = sqlite3.connect(portal_db_path)
        cursor = conn.cursor()

        # Get all published databases
        cursor.execute("""
            SELECT db_name, file_path, status
            FROM databases
            WHERE status IN ('Published', 'Draft', 'Unpublished')
            AND trashed_at IS NULL
        """)

        databases = cursor.fetchall()

        for db_name, file_path, status in databases:
            if file_path and os.path.exists(file_path):
                try:
                    # Get table information for metadata
                    db_conn = sqlite3.connect(file_path)
                    db_cursor = db_conn.cursor()

                    # Get tables (excluding SQLite system tables)
                    db_cursor.execute("""
                        SELECT name FROM sqlite_master
                        WHERE type='table'
                        AND name NOT LIKE 'sqlite_%'
                        AND name NOT LIKE '%_fts%'
                    """)
                    tables = db_cursor.fetchall()

                    database_config = {"tables": {}}

                    for (table_name,) in tables:
                        # Get row count for description
                        try:
                            db_cursor.execute(f"SELECT COUNT(*) FROM [{table_name}]")
                            row_count = db_cursor.fetchone()[0]
                        except:
                            row_count = 0

                        # Get column info
                        db_cursor.execute(f"PRAGMA table_info([{table_name}])")
                        columns = db_cursor.fetchall()

                        # Generate basic table config
                        table_config = {
                            "title": table_name.replace('_', ' ').title(),
                            "description": f"Data table with {row_count:,} records and {len(columns)} columns."
                        }

                        # Add text columns as potential facets (limited to avoid performance issues)
                        text_columns = []
                        geographic_columns = []

                        for col_info in columns:
                            col_name = col_info[1].lower()
                            col_type = col_info[2].lower()

                            # Check for geographic columns
                            if col_name in ['latitude', 'longitude', 'lat', 'lon', 'coords']:
                                geographic_columns.append(col_info[1])  # Use original case

                            # Add to facets if suitable text column
                            elif (col_type in ['text', 'varchar'] and
                                  col_name not in ['id', 'created_at', 'updated_at', 'description', 'notes', 'comments'] and
                                  not col_name.endswith('_id')):
                                text_columns.append(col_info[1])  # Use original case

                        # Add facets (limit to first 3 to avoid performance issues)
                        if text_columns:
                            table_config["facets"] = text_columns[:3]

                        # Add map configuration if geographic columns found
                        if 'latitude' in [col.lower() for col in geographic_columns] and 'longitude' in [col.lower() for col in geographic_columns]:
                            # Find the actual column names (case-sensitive)
                            lat_col = next((col for col in geographic_columns if col.lower() == 'latitude'), None)
                            lon_col = next((col for col in geographic_columns if col.lower() == 'longitude'), None)

                            if lat_col and lon_col:
                                table_config["plugins"] = {
                                    "datasette-cluster-map": {
                                        "latitude": lat_col,
                                        "longitude": lon_col
                                    }
                                }

                        database_config["tables"][table_name] = table_config

                    base_metadata["databases"][db_name] = database_config
                    db_conn.close()

                    print(f"   Processed {db_name}: {len(tables)} tables")

                except Exception as e:
                    print(f"Error processing database {db_name}: {e}")
                    continue

        conn.close()
        print(f"Generated metadata for {len(databases)} databases")
        print("Tile servers: CartoDB (avoids OpenStreetMap blocking)")
        print("Markdown configuration handled by dynamic plugin")

    except Exception as e:
        print(f"Error generating dynamic metadata: {e}")

    return base_metadata

def main():
    """Main function"""
    try:
        metadata = generate_metadata()

        # Write to the correct location based on environment
        metadata_paths = [
            '/app/metadata.json',  # Docker/production
            './metadata.json',     # Local development
            'metadata.json'        # Fallback
        ]

        metadata_written = False
        for path in metadata_paths:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
                with open(path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                print(f"Metadata written to: {path}")
                metadata_written = True
                break
            except (OSError, PermissionError) as e:
                print(f"Could not write to {path}: {e}")
                continue

        if not metadata_written:
            print("Failed to write metadata to any location")
            exit(1)

        print("Metadata generated successfully")
        print("Features:")
        print("  - CartoDB tile servers (no OpenStreetMap blocking)")
        print("  - Automatic geographic column detection")
        print("  - Smart facet selection")
        print("  - Markdown columns managed by dynamic render_links.py plugin")
        print("  - Robots.txt blocking non-index pages")

    except Exception as e:
        print(f"Failed to generate metadata: {e}")
        exit(1)

if __name__ == "__main__":
    main()
