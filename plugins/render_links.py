# -*- coding: utf-8 -*-
"""
Dynamic Render Links Plugin for Multi-Database Portal
Automatically creates links between related records across all registered databases
"""
import sqlite3
import os
from datasette import hookimpl
from markupsafe import Markup

def get_database_config():
    """Get database configuration from portal database"""
    portal_db_path = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
    
    if not os.path.exists(portal_db_path):
        return {}
    
    try:
        conn = sqlite3.connect(portal_db_path)
        cursor = conn.cursor()
        
        # Get all active databases
        cursor.execute("""
            SELECT db_id, db_name, file_path 
            FROM databases 
            WHERE status = 'active' AND trashed_at IS NULL
        """)
        
        databases = {}
        for db_id, db_name, file_path in cursor.fetchall():
            databases[db_name] = {
                'db_id': db_id,
                'file_path': file_path
            }
        
        conn.close()
        return databases
        
    except Exception as e:
        print(f"Error loading database config: {e}")
        return {}

def get_link_rules():
    """
    Define linking rules for different databases and tables.
    This could be extended to be configurable via the portal database.
    """
    return {
        # Risk Management Plans database rules
        "risk_management_plans": {
            "facility_accidents_view": {
                "facility_id": {
                    "target_table": "rmp_facility",
                    "url_pattern": "/{database}/rmp_facility/{value}"
                },
                "naics_code": {
                    "target_table": "rmp_naics", 
                    "url_pattern": "/{database}/rmp_naics/{value}"
                },
                "facility_accident_id": {
                    "target_table": "facility_accidents_view",
                    "url_pattern": "/{database}/facility_accidents_view/{row_id}",
                    "use_row_id": "id"
                },
                "accident_id": {
                    "target_table": "facility_accidents_view",
                    "url_pattern": "/{database}/facility_accidents_view/{row_id}",
                    "use_row_id": "id"
                }
            },
            "accident_chemicals_view": {
                "facility_id": {
                    "target_table": "rmp_facility",
                    "url_pattern": "/{database}/rmp_facility/{value}"
                }
            },
            "facility_view": {
                "epa_facility_id": {
                    "target_table": "rmp_facility",
                    "url_pattern": "/{database}/rmp_facility/{value}"
                },
                "naics_codes": {
                    "target_table": "rmp_naics",
                    "url_pattern": "/{database}/rmp_naics/{value}",
                    "multiple_values": True,
                    "separator": ","
                },
                "chemical_ids": {
                    "target_table": "rmp_facility_chemicals",
                    "url_pattern": "/{database}/rmp_facility_chemicals/{value}",
                    "multiple_values": True,
                    "separator": ","
                }
            }
        },
        
        # Generic rules that can apply to any database
        "_generic": {
            # Common patterns for ID fields
            "_patterns": {
                "facility_id": {
                    "target_table": "facilities",
                    "url_pattern": "/{database}/facilities/{value}"
                },
                "user_id": {
                    "target_table": "users", 
                    "url_pattern": "/{database}/users/{value}"
                },
                "company_id": {
                    "target_table": "companies",
                    "url_pattern": "/{database}/companies/{value}"
                }
            }
        }
    }

@hookimpl
def render_cell(datasette, value, column, table, database, row):
    """
    Dynamic cell renderer that creates links based on database configuration
    Specifically optimized for risk_management_plans database
    """
    if not value:
        return None
    
    # FIRST: FORCE MARKDOWN RENDERING for specific columns (applies to ALL databases)
    markdown_columns = ['report', 'popup', 'description', 'notes', 'comments', 'summary', 'details', 'markdown', 'id', 'file_key', 'datasette_link', 'title', 'facility_name']
    if column in markdown_columns:
        try:
            import re
            html_content = str(value)
            
            # Handle JSON-like popup content specially
            if column == 'popup' and value.startswith('{"title"'):
                try:
                    import json
                    popup_data = json.loads(value)
                    if 'link' in popup_data and 'title' in popup_data:
                        facility_name = popup_data['title']
                        link_url = popup_data['link']
                        description = popup_data.get('description', '')
                        return Markup(f'<a href="{link_url}">{facility_name}</a><br><small>{description}</small>')
                except:
                    pass  # Fall through to regular processing
            
            # Convert [text](url) to <a href="url">text</a>
            link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
            html_content = re.sub(link_pattern, r'<a href="\2">\1</a>', html_content)
            
            # Convert **bold** to <strong>bold</strong>
            html_content = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', html_content)
            
            # Convert *italic* to <em>italic</em>
            html_content = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', html_content)
            
            # Only return markup if we actually converted something
            if html_content != str(value):
                return Markup(html_content)
                
        except Exception as e:
            print(f"Markdown processing error for {column}: {e}")
            pass
    
    # SECOND: Handle risk_management_plans database specifically (exact match to original render_links.py)
    if database == "risk_management_plans":
        
        # Handle facility_id, naics_code, and id for facility_accidents_view
        if table == "facility_accidents_view":
            if column == "facility_id":
                return Markup(f'<a href="/risk_management_plans/rmp_facility/{value}">{value}</a>')
            if column == "naics_code":
                return Markup(f'<a href="/risk_management_plans/rmp_naics/{value}">{value}</a>')
            if column == "facility_accident_id":
                # Use the id (new primary key) from the same row to link
                record_id = row["id"] if "id" in row.keys() else None
                return Markup(f'<a href="/risk_management_plans/facility_accidents_view/{record_id}">{value}</a>') if record_id else None
            if column == "accident_id":
                # Use the id (new primary key) from the same row to link
                record_id = row["id"] if "id" in row.keys() else None
                return Markup(f'<a href="/risk_management_plans/facility_accidents_view/{record_id}">{value}</a>') if record_id else None

        # Handle facility_id for accident_chemicals_view
        if table == "accident_chemicals_view":
            if column == "facility_id":
                return Markup(f'<a href="/risk_management_plans/rmp_facility/{value}">{value}</a>')

        # Handle epa_facility_id in facility_view
        if table == "facility_view" and column == "epa_facility_id" and value:
            return Markup(f'<a href="/risk_management_plans/rmp_facility/{value}">{value}</a>')

        # Handle naics_codes in facility_view (comma-separated list)
        if table == "facility_view" and column == "naics_codes" and value:
            # Split the comma-separated list
            codes = [code.strip() for code in value.split(",")]
            # Create a link for each naics_code
            links = [f'<a href="/risk_management_plans/rmp_naics/{code}">{code}</a>' for code in codes]
            # Join the links with commas
            return Markup(", ".join(links))

        # Handle chemical_ids in facility_view (comma-separated list)
        if table == "facility_view" and column == "chemical_ids" and value:
            # Split the comma-separated list
            ids = [id.strip() for id in value.split(",")]
            # Create a link for each chemical_id to rmp_facility_chemicals
            links = [f'<a href="/risk_management_plans/rmp_facility_chemicals/{id}">{id}</a>' for id in ids]
            # Join the links with commas
            return Markup(", ".join(links))

        # Return None for risk_management_plans if no specific rule matched
        return None
    
    # THIRD: For other databases, use the dynamic configuration approach
    # Get active databases
    databases = get_database_config()
    
    # Skip if this database is not in our portal
    if database not in databases:
        return None
    
    # Get linking rules
    link_rules = get_link_rules()
    
    # Check for database-specific rules
    db_rules = link_rules.get(database, {})
    table_rules = db_rules.get(table, {})
    column_rules = table_rules.get(column)
    
    if column_rules:
        return create_link(column_rules, value, row, database)
    
    # Check for generic patterns
    generic_rules = link_rules.get("_generic", {}).get("_patterns", {})
    if column in generic_rules:
        return create_link(generic_rules[column], value, row, database)
    
    # Check for column patterns (e.g., columns ending with "_id")
    if column.endswith("_id"):
        # Try to infer target table name
        base_name = column[:-3]  # Remove "_id"
        target_table = f"{base_name}s"  # Pluralize
        
        return Markup(f'<a href="/{database}/{target_table}/{value}">{value}</a>')
    
    return None

def create_link(rule, value, row, database):
    """Create HTML link based on rule configuration"""
    
    # Handle multiple values (comma-separated)
    if rule.get("multiple_values"):
        separator = rule.get("separator", ",")
        values = [v.strip() for v in str(value).split(separator)]
        links = []
        
        for val in values:
            if val:
                url = rule["url_pattern"].format(
                    database=database,
                    value=val,
                    row_id=row.get(rule.get("use_row_id", "id"), val)
                )
                links.append(f'<a href="{url}">{val}</a>')
        
        return Markup(separator.join(links))
    
    # Handle single values
    else:
        if rule.get("use_row_id"):
            # Use a different field from the row as the URL parameter
            row_id = row.get(rule["use_row_id"])
            if not row_id:
                return None
            url = rule["url_pattern"].format(
                database=database,
                value=value,
                row_id=row_id
            )
        else:
            url = rule["url_pattern"].format(
                database=database,
                value=value
            )
        
        return Markup(f'<a href="{url}">{value}</a>')

@hookimpl 
def startup(datasette):
    """Initialize plugin on startup"""
    print("🔗 Dynamic Render Links plugin loaded")
    databases = get_database_config()
    print(f"🔗 Found {len(databases)} active databases for link rendering")
    
    # Log available databases and suggest configurations
    for db_name, db_info in databases.items():
        print(f"   📊 {db_name}")
        
        # Auto-generate link suggestions for new databases
        if db_name != "risk_management_plans":  # Skip the pre-configured one
            suggestions = get_table_relationships(db_info['file_path'])
            if suggestions:
                print(f"      💡 Suggested {len(suggestions)} auto-link rules")

@hookimpl
def register_output_renderer():
    """Register custom output renderers for markdown content"""
    return {
        "extension": "md",
        "render": render_markdown_content,
        "can_render": lambda: True
    }

def render_markdown_content(args, data, view_name):
    """Render markdown content in table cells"""
    # This allows markdown rendering in any column that contains markdown
    # Datasette will automatically detect and render markdown content
    return None

# Configuration management functions (for future enhancement)
def add_link_rule(database, table, column, rule):
    """
    Add a new linking rule (could be stored in portal database)
    """
    # This could write to a link_rules table in the portal database
    # for dynamic configuration
    pass

def get_table_relationships(database_path):
    """
    Analyze database schema to suggest automatic linking rules
    """
    try:
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()
        
        # Get foreign key relationships
        cursor.execute("PRAGMA foreign_key_list")
        fk_relationships = cursor.fetchall()
        
        # Get table info
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        suggested_rules = {}
        
        # Analyze each table for potential linking columns
        for table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            
            for col_info in columns:
                col_name = col_info[1]
                
                # Suggest links for ID columns
                if col_name.endswith('_id') and col_name != 'id':
                    base_name = col_name[:-3]
                    target_table = f"{base_name}s"
                    
                    if target_table in tables:
                        if table not in suggested_rules:
                            suggested_rules[table] = {}
                        
                        suggested_rules[table][col_name] = {
                            "target_table": target_table,
                            "url_pattern": f"/{database}/{target_table}/{{value}}",
                            "confidence": "high"
                        }
        
        conn.close()
        return suggested_rules
        
    except Exception as e:
        print(f"Error analyzing database relationships: {e}")
        return {}