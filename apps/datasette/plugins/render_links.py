# -*- coding: utf-8 -*-
"""
Dynamic Render Links Plugin with Built-in Markdown Support
Handles both database linking AND markdown rendering based on database configuration
"""
import sqlite3
import os
import json
import re
from datasette import hookimpl
from markupsafe import Markup
import sys

PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGINS_DIR not in sys.path:
    sys.path.insert(0, PLUGINS_DIR)

# Cache for markdown columns to avoid repeated database queries
_markdown_columns_cache = None
_cache_timestamp = 0

def get_markdown_columns_from_db():
    """Get markdown column configuration from portal database"""
    global _markdown_columns_cache, _cache_timestamp
    
    import time
    current_time = time.time()
    
    # Cache for 60 seconds to avoid too many database hits
    if _markdown_columns_cache and (current_time - _cache_timestamp) < 60:
        return _markdown_columns_cache
    
    try:
        portal_db_path = os.getenv('PORTAL_DB_PATH', '/data/portal.db')
        if not os.path.exists(portal_db_path):
            return set()
        
        conn = sqlite3.connect(portal_db_path)
        cursor = conn.cursor()
        
        # Get configured markdown columns
        try:
            cursor.execute("SELECT db_name, table_name, column_name FROM markdown_columns")
            markdown_columns = set()
            for row in cursor.fetchall():
                markdown_columns.add(f"{row[0]}:{row[1]}:{row[2]}")
            
            conn.close()
            _markdown_columns_cache = markdown_columns
            _cache_timestamp = current_time
            
            return markdown_columns
            
        except sqlite3.OperationalError:
            # Table doesn't exist yet
            conn.close()
            return set()
        
    except Exception as e:
        print(f"Error getting markdown columns from database: {e}")
        return set()

def convert_markdown_to_html(text):
    """Convert basic markdown to HTML while protecting URLs"""
    if not text:
        return text
    
    # Store all URLs and HTML tags temporarily with placeholders
    protected_content = []
    placeholder_template = "___PROTECTED_CONTENT_{}___"
    
    # First, find and protect all markdown links [text](url)
    def protect_link(match):
        full_match = match.group(0)
        link_text = match.group(1)
        url = match.group(2)
        # Convert to HTML and store
        html_link = f'<a href="{url}">{link_text}</a>'
        protected_content.append(html_link)
        return placeholder_template.format(len(protected_content) - 1)
    
    # Protect markdown links
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', protect_link, text)
    
    # Now process markdown on the remaining text
    # Convert **bold** to <strong>bold</strong>
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    
    # Convert *italic* to <em>italic</em>
    # Only match if not adjacent to underscores (which are common in URLs/identifiers)
    text = re.sub(r'(?<![_*])\*([^*_]+)\*(?![_*])', r'<em>\1</em>', text)
    
    # Convert headers
    text = re.sub(r'^# (.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^## (.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    
    # Restore protected content
    for i, content in enumerate(protected_content):
        placeholder = placeholder_template.format(i)
        text = text.replace(placeholder, content)
    
    # Convert newlines to <br>
    text = text.replace('\n\n', '<br><br>').replace('\n', '<br>')
    
    return text

@hookimpl
def render_cell(datasette, value, column, table, database, row):
    """
    Dynamic cell renderer with markdown support and database linking
    """
    if not value:
        return None
    
    # Get current markdown column configuration
    markdown_columns = get_markdown_columns_from_db()
    current_column = f"{database}:{table}:{column}"
    
    # Check if this column should get markdown treatment
    should_render_markdown = current_column in markdown_columns
    
    if should_render_markdown:
        # Handle JSON popup conversion to markdown first
        if column == 'popup' and str(value).startswith('{"'):
            try:
                popup_data = json.loads(value)
                if 'title' in popup_data:
                    facility_name = popup_data.get('title', '')
                    address = popup_data.get('description', '')
                    link_url = popup_data.get('link', '')
                    
                    # Create markdown format
                    if link_url:
                        markdown_content = f"**[{facility_name}]({link_url})**\n\n{address}"
                    else:
                        markdown_content = f"**{facility_name}**\n\n{address}"
                    
                    # Convert to HTML and return
                    return Markup(convert_markdown_to_html(markdown_content))
            except json.JSONDecodeError:
                # If not valid JSON, treat as regular text
                pass
        
        # For other markdown columns, convert markdown to HTML
        html_content = convert_markdown_to_html(str(value))
        return Markup(html_content)
    
    # Handle database linking for non-markdown columns
    if database == "risk_management_plans":
        return handle_rmp_database_links(table, column, value, row)
    
    # Generic ID linking for other databases
    if column.endswith("_id") and column != "id":
        base_name = column[:-3]
        target_table = f"{base_name}s"
        return Markup(f'<a href="/{database}/{target_table}/{value}">{value}</a>')
    
    return None

def handle_rmp_database_links(table, column, value, row):
    """Handle risk_management_plans database specific linking"""
    
    # Convert sqlite3.Row to dict for easier access
    row_dict = {}
    try:
        if hasattr(row, 'keys'):  # sqlite3.Row has keys() method
            row_dict = dict(zip(row.keys(), row))
        elif isinstance(row, dict):
            row_dict = row
    except Exception:
        pass
    
    # Handle facility_id, naics_code, and id for facility_accidents_view
    if table == "facility_accidents_view":
        if column == "facility_id":
            return Markup(f'<a href="/risk_management_plans/rmp_facility/{value}">{value}</a>')
        if column == "naics_code":
            return Markup(f'<a href="/risk_management_plans/rmp_naics/{value}">{value}</a>')
        if column == "facility_accident_id":
            record_id = row_dict.get("id")
            return Markup(f'<a href="/risk_management_plans/facility_accidents_view/{record_id}">{value}</a>') if record_id else None
        if column == "accident_id":
            record_id = row_dict.get("id")
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
        codes = [code.strip() for code in value.split(",")]
        links = [f'<a href="/risk_management_plans/rmp_naics/{code}">{code}</a>' for code in codes]
        return Markup(", ".join(links))

    # Handle chemical_ids in facility_view (comma-separated list)
    if table == "facility_view" and column == "chemical_ids" and value:
        ids = [id.strip() for id in value.split(",")]
        links = [f'<a href="/risk_management_plans/rmp_facility_chemicals/{id}">{id}</a>' for id in ids]
        return Markup(", ".join(links))

    return None

@hookimpl 
def startup(datasette):
    """Initialize plugin on startup"""
    markdown_columns = get_markdown_columns_from_db()
    print(f"Dynamic Markdown + Links plugin loaded")
    print(f"   Configured markdown columns: {len(markdown_columns)}")
    for col in sorted(markdown_columns):
        print(f"    - {col}")
    print(f"   Database linking enabled for risk_management_plans")
    print(f"   Built-in markdown rendering (no external plugins needed)")