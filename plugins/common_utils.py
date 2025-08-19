"""
Common Utilities Module for EDGI Datasette Cloud Portal
Shared functions across all backend modules to eliminate code duplication
"""

import json
import base64
import uuid
import logging
import re
import os
import bleach
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# Configuration Constants
TRASH_RETENTION_DAYS = 30
MAX_DATABASES_PER_USER = 10
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv', '.txt'}
DATA_DIR = os.getenv('EDGI_DATA_DIR', "/data")
STATIC_DIR = os.getenv('EDGI_STATIC_DIR', "/static")

def get_actor_from_request(request):
    """
    Extract actor from ds_actor cookie - centralized implementation.
    Used across all modules for authentication.
    """
    actor = request.scope.get("actor")
    if actor:
        return actor
    
    try:
        cookie_header = ""
        for name, value in request.scope.get('headers', []):
            if name == b'cookie':
                cookie_header = value.decode('utf-8')
                break
        
        if not cookie_header:
            return None
            
        cookies = {}
        for cookie in cookie_header.split('; '):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key] = value
        
        ds_actor = cookies.get("ds_actor", "")
        
        if ds_actor and ds_actor != '""' and ds_actor != "":
            if ds_actor.startswith('"') and ds_actor.endswith('"'):
                ds_actor = ds_actor[1:-1]
            
            ds_actor = ds_actor.replace('\\054', ',').replace('\\"', '"')
            
            try:
                decoded = base64.b64decode(ds_actor + '==').decode('utf-8')
                actor_data = json.loads(decoded)
                request.scope["actor"] = actor_data
                return actor_data
            except Exception as decode_error:
                logger.debug(f"Could not decode actor cookie: {decode_error}")
                return None
                
    except Exception as e:
        logger.debug(f"Error parsing cookies: {e}")
        return None
    
    return None

def set_actor_cookie(response, datasette, actor_data):
    """Set actor cookie on response - centralized implementation."""
    try:
        encoded = base64.b64encode(json.dumps(actor_data).encode('utf-8')).decode('utf-8')
        response.set_cookie("ds_actor", encoded, httponly=True, max_age=3600, samesite="lax")
    except Exception as e:
        logger.error(f"Error setting cookie: {e}")
        response.set_cookie("ds_actor", f"user_{actor_data.get('id', '')}", httponly=True, max_age=3600, samesite="lax")

async def log_user_activity(datasette, user_id, action, details, metadata=None):
    """Enhanced logging with metadata support for user actions."""
    try:
        query_db = datasette.get_database("portal")
        log_data = {
            'log_id': uuid.uuid4().hex[:20],
            'user_id': user_id,
            'action': action,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if metadata:
            log_data['action_metadata'] = json.dumps(metadata)
        
        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp, action_metadata) VALUES (?, ?, ?, ?, ?, ?)",
            [log_data['log_id'], log_data['user_id'], log_data['action'], log_data['details'], log_data['timestamp'], log_data.get('action_metadata')]
        )
    except Exception as e:
        logger.error(f"Error logging user action: {e}")

async def log_database_action(datasette, user_id, action, details, metadata=None):
    """Enhanced logging with metadata support for database actions."""
    try:
        query_db = datasette.get_database("portal")
        log_data = {
            'log_id': uuid.uuid4().hex[:20],
            'user_id': user_id,
            'action': action,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if metadata:
            log_data['action_metadata'] = json.dumps(metadata)
        
        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp, action_metadata) VALUES (?, ?, ?, ?, ?, ?)",
            [log_data['log_id'], log_data['user_id'], log_data['action'], log_data['details'], log_data['timestamp'], log_data.get('action_metadata')]
        )
    except Exception as e:
        logger.error(f"Error logging database action: {e}")

async def log_database_action_with_timestamp(datasette, user_id, action, details, metadata=None, db_name=None):
    """Enhanced logging that also updates database timestamp if db_name provided"""
    try:
        # First update the database timestamp if db_name is provided
        if db_name:
            await update_database_timestamp(datasette, db_name)
        
        # Then log the action
        await log_database_action(datasette, user_id, action, details, metadata)
        
    except Exception as e:
        logger.error(f"Error in enhanced database logging: {e}")
        # Fallback to regular logging
        await log_database_action(datasette, user_id, action, details, metadata)

async def verify_user_session(datasette, actor):
    """
    Verify user session and return user info.
    Returns tuple: (is_valid, user_data, redirect_response)
    """
    if not actor:
        return False, None, None
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT user_id, username, email, role, created_at FROM users WHERE user_id = ?", 
            [actor.get("id")]
        )
        user = result.first()
        
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            from datasette.utils.asgi import Response
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return False, None, response
        
        # Verify role matches
        if user["role"] != actor.get("role"):
            logger.warning(f"Role mismatch for user_id={actor.get('id')}: db_role={user['role']}, cookie_role={actor.get('role')}")
            from datasette.utils.asgi import Response
            response = Response.redirect("/login?error=Session invalid")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return False, None, response
        
        return True, dict(user), None
        
    except Exception as e:
        logger.error(f"Error verifying user session: {str(e)}")
        from datasette.utils.asgi import Response
        response = Response.redirect("/login?error=Authentication error")
        response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
        return False, None, response

async def get_portal_content(datasette):
    """
    Get portal content for templates - handles both portal and database-specific content.
    Returns a dictionary with all content sections.
    """
    query_db = datasette.get_database('portal')
    
    async def get_section(section_name, db_id=None):
        if db_id:
            result = await query_db.execute(
                "SELECT content FROM admin_content WHERE db_id = ? AND section = ?", 
                [db_id, section_name]
            )
        else:
            result = await query_db.execute(
                "SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", 
                [section_name]
            )
        
        row = result.first()
        if row:
            try:
                content = json.loads(row["content"])
                if section_name in ["info", "description", "footer"] and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                return content
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for section {section_name}: {str(e)}")
                return {}
        return {}

    # Default content structure
    content = {
        'title': await get_section("title") or {'content': 'EDGI Datasette Cloud Portal'},
        'header_image': await get_section("header_image") or {
            'image_url': '/static/default_header.jpg', 
            'alt_text': 'EDGI Portal Header', 
            'credit_url': '', 
            'credit_text': ''
        },
        'info': await get_section("info") or {
            'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.',
            'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')
        },
        'footer': await get_section("footer") or {
            'content': 'Made with \u2764\ufe0f by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/).',
            'odbl_text': 'Data licensed under ODbL', 
            'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 
            'paragraphs': parse_markdown_links('Made with \u2764\ufe0f by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/).')
        }
    }
    
    return content

async def get_database_content(datasette, db_name):
    """Get homepage content for a specific database with proper header image handling."""
    query_db = datasette.get_database('portal')
    content = {}
    
    try:
        db_result = await query_db.execute("SELECT db_id FROM databases WHERE db_name = ?", [db_name])
        db_row = db_result.first()
        if not db_row:
            logger.error(f"Database {db_name} not found")
            return {}
        
        db_id = db_row['db_id']
        
        result = await query_db.execute("SELECT section, content FROM admin_content WHERE db_id = ?", [db_id])
        for row in result:
            try:
                content[row['section']] = json.loads(row['content'])
            except json.JSONDecodeError:
                content[row['section']] = {'content': row['content']}
    except Exception as e:
        logger.error(f"Error loading admin content for {db_name}: {e}")
    
    # Set defaults
    if 'title' not in content:
        content['title'] = {'content': db_name.replace('_', ' ').replace('-', ' ').title()}
    
    if 'description' not in content:
        content['description'] = {'content': 'Environmental data dashboard powered by Datasette.'}
    
    # FIXED: Proper header image handling with correct paths
    if 'header_image' not in content:
        db_result = await query_db.execute("SELECT db_id FROM databases WHERE db_name = ?", [db_name])
        db_row = db_result.first()
        if db_row:
            db_id = db_row['db_id']
            # Check if custom header exists in the correct location
            custom_header_path = os.path.join(DATA_DIR, db_id, 'header.jpg')
            if os.path.exists(custom_header_path):
                content['header_image'] = {
                    'image_url': f'/data/{db_id}/header.jpg',  # Use our custom route
                    'alt_text': 'Environmental Data',
                    'credit_text': 'Environmental Data Portal',
                    'credit_url': ''
                }
            else:
                content['header_image'] = {
                    'image_url': '/static/default_header.jpg',
                    'alt_text': 'Environmental Data',
                    'credit_text': 'Environmental Data Portal',
                    'credit_url': ''
                }
    
    if 'footer' not in content:
        content['footer'] = {
            'content': 'Made with \u2764\ufe0f by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/).',
            'odbl_text': 'Data licensed under ODbL',
            'odbl_url': 'https://opendatacommons.org/licenses/odbl/',
            'paragraphs': parse_markdown_links('Made with \u2764\ufe0f by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/).')
        }
    
    # Parse markdown for description and footer
    if 'content' in content.get('description', {}):
        content['description']['paragraphs'] = parse_markdown_links(content['description']['content'])
        content['info'] = {
            'content': content['description']['content'],
            'paragraphs': content['description']['paragraphs']
        }
    
    if 'content' in content.get('footer', {}):
        content['footer']['paragraphs'] = parse_markdown_links(content['footer']['content'])
    
    return content

async def get_database_statistics(datasette, user_id=None):
    """Get enhanced database statistics for homepage with encoding safety - excludes deleted databases."""
    try:
        db = datasette.get_database("portal")
        
        # Initialize default values
        stats = {
            'total_databases': 0,
            'published_databases': 0,
            'featured_databases': [],
            'user_databases': 0,
            'user_published': 0,
            'user_trashed': 0
        }
        
        try:
            # Total active databases (not deleted or trashed) - EXCLUDE 'Deleted' status
            total_result = await db.execute(
                "SELECT COUNT(*) FROM databases WHERE status IN ('Draft', 'Published', 'Unpublished')"
            )
            stats['total_databases'] = total_result.first()[0] if total_result.first() else 0
        except Exception as e:
            logger.error(f"Error getting total databases: {e}")
        
        try:
            # Published databases - EXCLUDE 'Deleted' status
            published_result = await db.execute(
                "SELECT COUNT(*) FROM databases WHERE status = 'Published'"
            )
            stats['published_databases'] = published_result.first()[0] if published_result.first() else 0
        except Exception as e:
            logger.error(f"Error getting published databases: {e}")
        
        # User-specific statistics if user_id provided
        if user_id:
            try:
                # User active databases - EXCLUDE 'Deleted' status
                user_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished')", 
                    [user_id]
                )
                stats['user_databases'] = user_result.first()[0] if user_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user databases for {user_id}: {e}")
            
            try:
                # User published databases - EXCLUDE 'Deleted' status
                user_published_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status = 'Published'", 
                    [user_id]
                )
                stats['user_published'] = user_published_result.first()[0] if user_published_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user published databases for {user_id}: {e}")
            
            try:
                # User trashed databases - EXCLUDE 'Deleted' status
                user_trashed_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status = 'Trashed'", 
                    [user_id]
                )
                stats['user_trashed'] = user_trashed_result.first()[0] if user_trashed_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user trashed databases for {user_id}: {e}")
        
        try:
            # Featured databases for homepage - only get essential fields, EXCLUDE 'Deleted' status
            featured_result = await db.execute(
                "SELECT db_id, db_name, website_url, status FROM databases WHERE status = 'Published' ORDER BY created_at DESC LIMIT 6"
            )
            stats['featured_databases'] = []
            for row in featured_result:
                try:
                    # Safely convert each row
                    db_dict = {
                        'db_id': str(row['db_id']) if row['db_id'] else '',
                        'db_name': str(row['db_name']) if row['db_name'] else '',
                        'website_url': str(row['website_url']) if row['website_url'] else '',
                        'status': str(row['status']) if row['status'] else ''
                    }
                    stats['featured_databases'].append(db_dict)
                except Exception as row_error:
                    logger.error(f"Error processing featured database row: {row_error}")
                    continue
        except Exception as e:
            logger.error(f"Error getting featured databases: {e}")
        
        logger.debug(f"Database statistics calculated: {stats}")
        return stats
        
    except Exception as e:
        logger.error(f"Error fetching database statistics: {str(e)}")
        # Return safe defaults
        return {
            'total_databases': 0,
            'published_databases': 0,
            'featured_databases': [],
            'user_databases': 0,
            'user_published': 0,
            'user_trashed': 0
        }

async def get_detailed_database_stats(datasette, db_name, user_id):
    """Get detailed statistics for a specific database."""
    try:
        # Get database file path
        file_path = os.path.join(DATA_DIR, user_id, f"{db_name}.db")
        
        stats = {
            'table_count': 0,
            'total_records': 0,
            'file_size_kb': 0,
            'tables': []
        }
        
        if os.path.exists(file_path):
            try:
                # Get file size
                stats['file_size_kb'] = round(os.path.getsize(file_path) / 1024, 2)
                
                # Open database and get table information
                user_db = sqlite_utils.Database(file_path)
                table_names = user_db.table_names()
                stats['table_count'] = len(table_names)
                
                for table_name in table_names:
                    try:
                        table = user_db[table_name]
                        record_count = table.count
                        stats['total_records'] += record_count
                        
                        stats['tables'].append({
                            'name': table_name,
                            'records': record_count
                        })
                    except Exception as table_error:
                        logger.error(f"Error getting stats for table {table_name}: {table_error}")
                        continue
                        
            except Exception as db_error:
                logger.error(f"Error accessing database file {file_path}: {db_error}")
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting detailed database stats for {db_name}: {e}")
        return {
            'table_count': 0,
            'total_records': 0,
            'file_size_kb': 0,
            'tables': []
        }

async def get_all_published_databases(datasette):
    """Get all published databases with metadata for public listing - excludes deleted databases."""
    try:
        db = datasette.get_database("portal")
        
        # Get all published databases with user info - EXCLUDE 'Deleted' status
        all_dbs_result = await db.execute(
            """SELECT d.db_id, d.db_name, d.website_url, d.created_at, u.username, d.user_id, d.file_path
               FROM databases d 
               JOIN users u ON d.user_id = u.user_id 
               WHERE d.status = 'Published'
               ORDER BY d.created_at DESC"""
        )
        
        all_databases = []
        for row in all_dbs_result:
            # Get database content for custom titles/descriptions
            try:
                db_content = await get_database_content(datasette, row['db_name'])
            except Exception as content_error:
                logger.error(f"Error getting content for {row['db_name']}: {content_error}")
                db_content = {}
            
            # Get table count and record count for each database
            table_count = 0
            total_records = 0
            try:
                # Build file path if not available
                file_path = row.get('file_path')
                if not file_path:
                    file_path = os.path.join(DATA_DIR, row['user_id'], f"{row['db_name']}.db")
                
                if file_path and os.path.exists(file_path):
                    user_db = sqlite_utils.Database(file_path)
                    table_names = user_db.table_names()
                    table_count = len(table_names)
                    
                    for table_name in table_names:
                        try:
                            table_info = user_db[table_name]
                            total_records += table_info.count
                        except Exception:
                            continue
                    
                    user_db.close()
                else:
                    logger.warning(f"Database file not found for {row['db_name']}: {file_path}")
            except Exception as e:
                logger.error(f"Error getting stats for database {row['db_name']}: {e}")

            all_databases.append({
                'title': db_content.get('title', {}).get('content', row['db_name'].replace('_', ' ').title()),
                'description': db_content.get('description', {}).get('content', 'Environmental data dashboard'),
                'url': row['website_url'],
                'created_at': row['created_at'],
                'username': row['username'],
                'table_count': table_count,
                'total_records': total_records,
                'icon': 'ri-database-line'
            })
        
        return all_databases
        
    except Exception as e:
        logger.error(f"Error getting all published databases: {e}")
        return []
    
def sanitize_text(text):
    """Sanitize text by stripping HTML tags while preserving safe characters."""
    return bleach.clean(text, tags=[], strip=True)

def parse_markdown_links(text):
    """Enhanced markdown parser that handles links, bold, italic, and lists."""
    # Split text into blocks (separated by double newlines OR single newlines for lists)
    blocks = []
    current_block = []
    lines = text.split('\n')
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        if not line:  # Empty line
            if current_block:
                blocks.append('\n'.join(current_block))
                current_block = []
        else:
            current_block.append(line)
        i += 1
    
    # Don't forget the last block
    if current_block:
        blocks.append('\n'.join(current_block))
    
    parsed_blocks = []
    
    for block in blocks:
        if not block.strip():
            continue
            
        lines = [line.strip() for line in block.split('\n') if line.strip()]
        
        # Check if this block is a list
        bullet_lines = [line for line in lines if line.startswith(('- ', '* '))]
        numbered_lines = [line for line in lines if re.match(r'^\d+\.\s', line)]
        
        # More flexible list detection - if majority are list items, treat as list
        if len(bullet_lines) >= 2:
            # Handle as bullet list
            list_items = []
            for line in lines:
                if line.startswith(('- ', '* ')):
                    item_text = line[2:].strip()  # Remove "- " or "* "
                    item_text = apply_inline_formatting(item_text)
                    list_items.append(f'<li>{item_text}</li>')
            
            if list_items:
                parsed_blocks.append(f'<ul>{"".join(list_items)}</ul>')
            
        elif len(numbered_lines) >= 2:
            # Handle as numbered list
            list_items = []
            for line in lines:
                if re.match(r'^\d+\.\s', line):
                    item_text = re.sub(r'^\d+\.\s', '', line).strip()  # Remove "1. "
                    item_text = apply_inline_formatting(item_text)
                    list_items.append(f'<li>{item_text}</li>')
            
            if list_items:
                parsed_blocks.append(f'<ol>{"".join(list_items)}</ol>')
            
        else:
            # Handle as regular paragraph
            paragraph_text = ' '.join(lines)
            formatted_text = apply_inline_formatting(paragraph_text)
            parsed_blocks.append(formatted_text)
    
    return parsed_blocks

def apply_inline_formatting(text):
    """Apply inline formatting (links, bold, italic) to text."""
    # Handle links: [text](url)
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
    text = link_pattern.sub(lambda m: f'<a href="{sanitize_text(m.group(2))}">{sanitize_text(m.group(1))}</a>', text)
    
    # Handle bold: **text**
    bold_pattern = re.compile(r'\*\*([^*]+)\*\*')
    text = bold_pattern.sub(r'<strong>\1</strong>', text)
    
    # Handle italic: *text* (but not if it's part of **text**)
    italic_pattern = re.compile(r'(?<!\*)\*([^*]+)\*(?!\*)')
    text = italic_pattern.sub(r'<em>\1</em>', text)
    
    return text

async def check_database_name_unique(datasette, db_name, exclude_db_id=None):
    """Check if database name is globally unique, excluding deleted databases."""
    db = datasette.get_database("portal")
    if exclude_db_id:
        result = await db.execute(
            "SELECT COUNT(*) FROM databases WHERE db_name = ? AND db_id != ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed')", 
            [db_name, exclude_db_id]
        )
    else:
        result = await db.execute(
            "SELECT COUNT(*) FROM databases WHERE db_name = ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed')", 
            [db_name]
        )
    return result.first()[0] == 0

async def check_database_name_available(datasette, db_name):
    """Check if database name is available for new creation (not reserved by active/trash databases)."""
    db = datasette.get_database("portal")
    result = await db.execute(
        "SELECT COUNT(*) FROM databases WHERE db_name = ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed')", 
        [db_name]
    )
    return result.first()[0] == 0

async def user_owns_database(datasette, user_id, db_name):
    """Verify user owns the database"""
    try:     
        portal_db = datasette.get_database("portal")
        result = await portal_db.execute(
            "SELECT 1 FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, user_id]
        )     
        return len(result.rows) > 0
    except Exception as e:
        logger.error(f"Database ownership check failed: {e}")
        return False

def validate_database_name(db_name):
    """
    Validate database name format.
    Returns (is_valid, error_message)
    """
    if not db_name:
        return False, "Database name is required"
    
    if not re.match(r'^[a-z0-9_]+$', db_name):
        return False, "Database name must contain only lowercase letters, numbers, and underscores"
    
    if len(db_name) < 3:
        return False, "Database name must be at least 3 characters long"
    
    if len(db_name) > 50:
        return False, "Database name must be less than 50 characters"
    
    return True, None

def validate_email(email):
    """
    Validate email format.
    Returns (is_valid, error_message)
    """
    if not email:
        return False, "Email address is required"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Please enter a valid email address"
    
    return True, None

def validate_username(username):
    """
    Validate username format.
    Returns (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False, "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
    
    return True, None

def validate_password(password):
    """
    Validate password strength.
    Returns (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    return True, None

async def update_database_timestamp(datasette, db_name):
    """Update the updated_at timestamp for a database - add to common_utils.py"""
    try:
        query_db = datasette.get_database('portal')
        current_time = datetime.utcnow().isoformat()
        await query_db.execute_write(
            "UPDATE databases SET updated_at = ? WHERE db_name = ?",
            [current_time, db_name]
        )
        logger.debug(f"Updated timestamp for database {db_name}: {current_time}")
    except Exception as e:
        logger.error(f"Error updating timestamp for database {db_name}: {e}")

async def update_database_timestamp_by_id(datasette, db_id):
    """Update database timestamp by db_id"""
    try:
        query_db = datasette.get_database('portal')
        current_time = datetime.utcnow().isoformat()
        await query_db.execute_write(
            "UPDATE databases SET updated_at = ? WHERE db_id = ?",
            [current_time, db_id]
        )
        logger.debug(f"Updated timestamp for database id {db_id}: {current_time}")
    except Exception as e:
        logger.error(f"Error updating timestamp for database id {db_id}: {e}")

async def handle_form_errors(datasette, template_name, template_data, request, error_message):
    """
    Standard error handling for forms.
    Returns a Response with the error message.
    """
    from datasette.utils.asgi import Response
    
    template_data["error"] = error_message
    
    return Response.html(
        await datasette.render_template(
            template_name,
            template_data,
            request=request
        )
    )

async def redirect_authenticated_user(actor):
    """
    Redirect authenticated users to appropriate dashboard.
    Returns Response object.
    """
    from datasette.utils.asgi import Response
    
    if actor.get("role") == "system_admin":
        return Response.redirect("/system-admin")
    else:
        return Response.redirect("/manage-databases")

def generate_website_url(request, db_name):
    """Generate website URL for database."""
    scheme = request.scheme
    host = request.headers.get('host', 'localhost:8001')
    return f"{scheme}://{host}/db/{db_name}/homepage"

def ensure_data_directories():
    """Ensure required directories exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    logger.debug(f"Ensured data directories exist: {DATA_DIR}, {STATIC_DIR}")

def get_success_error_from_request(request):
    """Extract success and error messages from request args."""
    return {
        'success': request.args.get('success'),
        'error': request.args.get('error')
    }

def create_feature_cards_from_databases(databases, limit=6):
    """Convert database list to feature cards format."""
    feature_cards = []
    for db in databases[:limit]:
        feature_cards.append({
            'title': db['db_name'].replace('_', ' ').title(),
            'description': f"{db['status']} environmental dataset",
            'url': db['website_url'],
            'icon': 'ri-database-line'
        })
    return feature_cards

def create_statistics_data(stats):
    """Create statistics array for templates."""
    return [
        {
            "label": "Total Databases",
            "value": stats['total_databases'],
            "url": "/all-databases"
        },
        {
            "label": "Published Datasets", 
            "value": stats['published_databases'],
            "url": "/all-databases"
        },
        {
            "label": "Active Users",
            "value": "Join Today",
            "url": "/register"
        }
    ]