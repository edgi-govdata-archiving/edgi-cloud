"""
Common Utilities Module for EDGI Datasette Cloud Portal
Provides shared functionality for database management, user authentication,
content management, and utility functions used across all modules.
"""

import json
import base64
import uuid
import logging
import re
import os
import bleach
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from email.parser import BytesParser
from email.policy import default

logger = logging.getLogger(__name__)

# Constants
PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(PLUGINS_DIR)
DATA_DIR = os.getenv("RESETTE_DATA_DIR", os.path.join(ROOT_DIR, "data"))
STATIC_DIR = os.getenv('RESETTE_STATIC_DIR', os.path.join(ROOT_DIR, "static"))

import sys
if PLUGINS_DIR not in sys.path:
    sys.path.insert(0, PLUGINS_DIR)

async def get_system_settings(datasette):
    """
    Retrieve system settings from the database with fallback defaults.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        dict: System settings with keys like trash_retention_days, max_databases_per_user, etc.
    """
    try:
        query_db = datasette.get_database('portal')
        
        result = await query_db.execute("SELECT setting_key, setting_value FROM system_settings")
        
        settings = {}
        for row in result:
            row_dict = dict(row)
            settings[row_dict['setting_key']] = row_dict['setting_value']
        
        defaults = {
            'trash_retention_days': 30,
            'max_databases_per_user': 10,
            'max_file_size': 524288000,  # 500MB
            'max_img_size': 5242880,    # 5MB
            'allowed_extensions': '.jpg, .jpeg, .png, .csv, .xls, .xlsx, .txt'
        }
        
        for key, default_value in defaults.items():
            if key not in settings:
                settings[key] = default_value
            else:
                if key in ['trash_retention_days', 'max_databases_per_user', 'max_file_size', 'max_img_size']:
                    try:
                        settings[key] = int(settings[key])
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid value for {key}: {settings[key]}, using default: {default_value}")
                        settings[key] = default_value
        
        logger.debug(f"Retrieved system settings: {settings}")
        return settings
        
    except Exception as e:
        logger.error(f"Error getting system settings: {e}")
        return {
            'trash_retention_days': 30,
            'max_databases_per_user': 10,
            'max_file_size': 524288000,  # 500MB
            'max_img_size': 5242880,  # 5MB
            'allowed_extensions': '.jpg, .png, .csv, .xls, .xlsx, .txt'
        }

async def get_trash_retention_days(datasette):
    """
    Get the number of days databases are retained in trash before auto-deletion.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        int: Number of retention days (default: 30)
    """
    try:
        settings = await get_system_settings(datasette)
        return settings.get('trash_retention_days', 30)
    except Exception as e:
        logger.error(f"Error getting trash retention days: {e}")
        return 30

async def get_max_databases_per_user(datasette):
    """
    Get the maximum number of databases allowed per user.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        int: Maximum databases per user (default: 10)
    """
    try:
        settings = await get_system_settings(datasette)
        return settings.get('max_databases_per_user', 10)
    except Exception as e:
        logger.error(f"Error getting max databases per user: {e}")
        return 10

async def get_max_file_size(datasette):
    """
    Get the maximum allowed file upload size in bytes.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        int: Maximum file size in bytes (default: 500MB)
    """
    try:
        settings = await get_system_settings(datasette)
        max_file_size = settings.get('max_file_size')
        
        if isinstance(max_file_size, str):
            max_file_size = int(max_file_size)
        
        return max_file_size
    except Exception as e:
        logger.error(f"Error getting max file size: {e}")
        return 524288000  # 500MB

async def get_max_image_size(datasette):
    """
    Get the maximum allowed image upload size in bytes.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        int: Maximum image size in bytes (default: 5MB)
    """
    try:
        settings = await get_system_settings(datasette)
        max_img_size = settings.get('max_img_size')
        
        if isinstance(max_img_size, str):
            max_img_size = int(max_img_size)
        
        return max_img_size
    except Exception as e:
        logger.error(f"Error getting max image size: {e}")
        return 5242880  # 5MB
    
async def get_allowed_extensions(datasette):
    """
    Get the list of allowed file extensions for uploads.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        str: Comma-separated list of allowed extensions
    """
    try:
        settings = await get_system_settings(datasette)
        return settings.get('allowed_extensions', '.jpg,.png,.csv,.xls,.xlsx,.txt')
    except Exception as e:
        logger.error(f"Error getting allowed extensions: {e}")
        return '.jpg,.png,.csv,.xls,.xlsx,.txt'

async def get_blocked_domains(datasette):
    """
    Get list of blocked domains for URL uploads.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        list: List of blocked domain dictionaries with domain, created_at, created_by
    """
    try:
        query_db = datasette.get_database('portal')
        result = await query_db.execute("SELECT domain, created_at, created_by FROM blocked_domains ORDER BY created_at DESC")
        
        blocked_domains = []
        for row in result:
            row_dict = dict(row)
            blocked_domains.append(row_dict)
        
        return blocked_domains
        
    except Exception as e:
        logger.error(f"Error getting blocked domains: {e}")
        return []

async def is_domain_blocked(datasette, domain):
    """
    Check if a domain is blocked for URL uploads.
    
    Args:
        datasette: Datasette instance
        domain (str): Domain name to check
        
    Returns:
        bool: True if domain is blocked, False otherwise
    """
    try:
        query_db = datasette.get_database('portal')
        result = await query_db.execute("SELECT COUNT(*) FROM blocked_domains WHERE domain = ?", [domain])
        return result.first()[0] > 0
    except Exception as e:
        logger.error(f"Error checking blocked domain {domain}: {e}")
        return False

def get_actor_from_request(request):
    """
    Extract user authentication data from request cookies.
    
    Args:
        request: ASGI request object
        
    Returns:
        dict or None: Actor data with id, username, role, or None if not authenticated
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
    """
    Set authentication cookie on response with user data.
    
    Args:
        response: HTTP response object
        datasette: Datasette instance
        actor_data (dict): User data to encode in cookie
    """
    try:
        encoded = base64.b64encode(json.dumps(actor_data).encode('utf-8')).decode('utf-8')
        response.set_cookie("ds_actor", encoded, httponly=True, max_age=3600, samesite="lax")
    except Exception as e:
        logger.error(f"Error setting cookie: {e}")
        response.set_cookie("ds_actor", f"user_{actor_data.get('id', '')}", httponly=True, max_age=3600, samesite="lax")

async def log_user_activity(datasette, user_id, action, details, metadata=None):
    """
    Log user activity to the activity_logs table.
    
    Args:
        datasette: Datasette instance
        user_id (str): User identifier
        action (str): Action type
        details (str): Action description
        metadata (dict, optional): Additional metadata to log as JSON
    """
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
    """
    Log database-related actions to the activity_logs table.
    
    Args:
        datasette: Datasette instance
        user_id (str): User identifier performing the action
        action (str): Database action type (e.g., 'create_database', 'delete_database')
        details (str): Action description
        metadata (dict, optional): Additional metadata to log as JSON
    """
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

async def verify_user_session(datasette, actor):
    """
    Verify that a user session is valid by checking against the database.
    
    Args:
        datasette: Datasette instance
        actor (dict): Actor data from cookie
        
    Returns:
        tuple: (is_valid: bool, user_data: dict or None, redirect_response or None)
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
    Get portal-wide content sections (title, header_image, info, footer).
    
    Args:
        datasette: Datasette instance
        
    Returns:
        dict: Content sections with keys: title, header_image, info, footer
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

    content = {
        'title': await get_section("title") or {'content': 'Resette Cloud Portal'},
        'header_image': await get_section("header_image") or {
            'image_url': '/static/default_header.jpg', 
            'alt_text': 'Resette Header', 
            'credit_url': '',
            'credit_text': ''
        },
        'info': await get_section("info") or {
            'content': 'The Resette Cloud Portal enables users to share environmental datasets as interactive websites.',
            'paragraphs': parse_markdown_links('The Resette Cloud Portal enables users to share environmental datasets as interactive websites.')
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
    """
    Get database-specific content sections (title, description, header_image, footer).
    
    Args:
        datasette: Datasette instance
        db_name (str): Database name
        
    Returns:
        dict: Database content sections
    """
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
    
    if 'title' not in content:
        content['title'] = {'content': db_name.replace('_', ' ').replace('-', ' ').title()}
    
    if 'description' not in content:
        content['description'] = {'content': 'Environmental data dashboard powered by Datasette.'}
    
    if 'header_image' not in content:
        db_result = await query_db.execute("SELECT db_id FROM databases WHERE db_name = ?", [db_name])
        db_row = db_result.first()
        if db_row:
            db_id = db_row['db_id']
            custom_header_path = os.path.join(DATA_DIR, db_id, 'header.jpg')
            if os.path.exists(custom_header_path):
                content['header_image'] = {
                    'image_url': f'/data/{db_id}/header.jpg',
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
    """
    Get database statistics for the portal or a specific user.
    
    Args:
        datasette: Datasette instance
        user_id (str, optional): User ID to get user-specific stats
        
    Returns:
        dict: Statistics including total_databases, published_databases, featured_databases, etc.
    """
    try:
        db = datasette.get_database("portal")
        
        stats = {
            'total_databases': 0,
            'published_databases': 0,
            'featured_databases': [],
            'user_databases': 0,
            'user_published': 0,
            'user_trashed': 0
        }
        
        try:
            total_result = await db.execute(
                "SELECT COUNT(*) FROM databases WHERE status IN ('Draft', 'Published', 'Unpublished')"
            )
            stats['total_databases'] = total_result.first()[0] if total_result.first() else 0
        except Exception as e:
            logger.error(f"Error getting total databases: {e}")
        
        try:
            published_result = await db.execute(
                "SELECT COUNT(*) FROM databases WHERE status = 'Published'"
            )
            stats['published_databases'] = published_result.first()[0] if published_result.first() else 0
        except Exception as e:
            logger.error(f"Error getting published databases: {e}")
        
        if user_id:
            try:
                user_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished')", 
                    [user_id]
                )
                stats['user_databases'] = user_result.first()[0] if user_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user databases for {user_id}: {e}")
            
            try:
                user_published_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status = 'Published'", 
                    [user_id]
                )
                stats['user_published'] = user_published_result.first()[0] if user_published_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user published databases for {user_id}: {e}")
            
            try:
                user_trashed_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status = 'Trashed'", 
                    [user_id]
                )
                stats['user_trashed'] = user_trashed_result.first()[0] if user_trashed_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user trashed databases for {user_id}: {e}")
        
        try:
            featured_result = await db.execute(
                "SELECT db_id, db_name, website_url, status FROM databases WHERE status = 'Published' ORDER BY created_at DESC LIMIT 50"
            )
            stats['featured_databases'] = []
            for row in featured_result:
                try:
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
        return {
            'total_databases': 0,
            'published_databases': 0,
            'featured_databases': [],
            'user_databases': 0,
            'user_published': 0,
            'user_trashed': 0
        }

async def get_detailed_database_stats(datasette, db_name, user_id):
    """
    Get detailed statistics for a specific database.
    
    Args:
        datasette: Datasette instance
        db_name (str): Database name
        user_id (str): User ID (for file path construction)
        
    Returns:
        dict: Detailed stats including table_count, total_records, file_size_kb, tables list
    """
    try:
        file_path = os.path.join(DATA_DIR, user_id, f"{db_name}.db")
        
        stats = {
            'table_count': 0,
            'total_records': 0,
            'file_size_kb': 0,
            'tables': []
        }
        
        if os.path.exists(file_path):
            try:
                stats['file_size_kb'] = round(os.path.getsize(file_path) / 1024, 2)
                
                import sqlite_utils
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
    """
    Get all published databases with their content and statistics.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        list: List of published database dictionaries with title, description, url, etc.
    """
    try:
        db = datasette.get_database("portal")
        
        all_dbs_result = await db.execute(
            """SELECT d.db_id, d.db_name, d.website_url, d.created_at, u.username, d.user_id, d.file_path
               FROM databases d 
               JOIN users u ON d.user_id = u.user_id 
               WHERE d.status = 'Published'
               ORDER BY d.created_at DESC"""
        )
        
        all_databases = []
        for row in all_dbs_result:
            try:
                db_content = await get_database_content(datasette, row['db_name'])
            except Exception as content_error:
                logger.error(f"Error getting content for {row['db_name']}: {content_error}")
                db_content = {}
            
            table_count = 0
            total_records = 0
            try:
                file_path = row.get('file_path')
                if not file_path:
                    file_path = os.path.join(DATA_DIR, row['user_id'], f"{row['db_name']}.db")
                
                if file_path and os.path.exists(file_path):
                    import sqlite_utils
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
    """
    Remove HTML tags and potentially dangerous content from text.
    
    Args:
        text (str): Text to sanitize
        
    Returns:
        str: Sanitized text with HTML tags removed
    """
    return bleach.clean(text, tags=[], strip=True)

def parse_markdown_links(text):
    """
    Parse markdown-style text into HTML paragraphs with support for links, lists, and formatting.
    
    Args:
        text (str): Markdown-style text to parse
        
    Returns:
        list: List of HTML strings (paragraphs, lists, etc.)
    """
    blocks = []
    current_block = []
    lines = text.split('\n')
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        if not line:
            if current_block:
                blocks.append('\n'.join(current_block))
                current_block = []
        else:
            current_block.append(line)
        i += 1
    
    if current_block:
        blocks.append('\n'.join(current_block))
    
    parsed_blocks = []
    
    for block in blocks:
        if not block.strip():
            continue
            
        lines = [line.strip() for line in block.split('\n') if line.strip()]
        
        bullet_lines = [line for line in lines if line.startswith(('- ', '* '))]
        numbered_lines = [line for line in lines if re.match(r'^\d+\.\s', line)]
        
        if len(bullet_lines) >= 2:
            list_items = []
            for line in lines:
                if line.startswith(('- ', '* ')):
                    item_text = line[2:].strip()
                    item_text = apply_inline_formatting(item_text)
                    list_items.append(f'<li>{item_text}</li>')
            
            if list_items:
                parsed_blocks.append(f'<ul>{"".join(list_items)}</ul>')
            
        elif len(numbered_lines) >= 2:
            list_items = []
            for line in lines:
                if re.match(r'^\d+\.\s', line):
                    item_text = re.sub(r'^\d+\.\s', '', line).strip()
                    item_text = apply_inline_formatting(item_text)
                    list_items.append(f'<li>{item_text}</li>')
            
            if list_items:
                parsed_blocks.append(f'<ol>{"".join(list_items)}</ol>')
            
        else:
            paragraph_text = ' '.join(lines)
            formatted_text = apply_inline_formatting(paragraph_text)
            parsed_blocks.append(formatted_text)
    
    return parsed_blocks

def apply_inline_formatting(text):
    """
    Apply inline markdown formatting (links, bold, italic) to text.
    
    Args:
        text (str): Text with markdown formatting
        
    Returns:
        str: HTML-formatted text
    """
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
    text = link_pattern.sub(lambda m: f'<a href="{sanitize_text(m.group(2))}">{sanitize_text(m.group(1))}</a>', text)
    
    bold_pattern = re.compile(r'\*\*([^*]+)\*\*')
    text = bold_pattern.sub(r'<strong>\1</strong>', text)
    
    italic_pattern = re.compile(r'(?<!\*)\*([^*]+)\*(?!\*)')
    text = italic_pattern.sub(r'<em>\1</em>', text)
    
    return text

async def check_database_name_unique(datasette, db_name, exclude_db_id=None):
    """
    Check if a database name is unique in the system.
    
    Args:
        datasette: Datasette instance
        db_name (str): Database name to check
        exclude_db_id (str, optional): Database ID to exclude from check (for updates)
        
    Returns:
        bool: True if name is unique, False if already exists
    """
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
    """
    Check if a database name is available for new databases.
    
    Args:
        datasette: Datasette instance
        db_name (str): Database name to check
        
    Returns:
        bool: True if available, False if taken
    """
    db = datasette.get_database("portal")
    result = await db.execute(
        "SELECT COUNT(*) FROM databases WHERE db_name = ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed')", 
        [db_name]
    )
    return result.first()[0] == 0

async def user_owns_database(datasette, user_id, db_name):
    """
    Check if a user owns a specific database.
    
    Args:
        datasette: Datasette instance
        user_id (str): User identifier
        db_name (str): Database name
        
    Returns:
        bool: True if user owns the database, False otherwise
    """
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
    Validate database name format and constraints.
    
    Args:
        db_name (str): Database name to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not db_name:
        return False, "Database name is required"
    
    if not re.match(r'^[a-z0-9_-]+$', db_name):
        return False, "Database name must contain only lowercase letters, numbers, underscores, and hyphens"
    
    if db_name.startswith(('-', '_')) or db_name.endswith(('-', '_')):
        return False, "Database name cannot start or end with hyphen or underscore"
    
    if '--' in db_name or '__' in db_name or '-_' in db_name or '_-' in db_name:
        return False, "Database name cannot have consecutive hyphens or underscores"
    
    if len(db_name) < 3:
        return False, "Database name must be at least 3 characters long"
    
    if len(db_name) > 50:
        return False, "Database name must be less than 50 characters"
    
    return True, None

def validate_email(email):
    """
    Validate email address format.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not email:
        return False, "Email address is required"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Please enter a valid email address"
    
    return True, None

def validate_username(username):
    """
    Validate username format and constraints.
    
    Args:
        username (str): Username to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not username:
        return False, "Username is required"
    
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False, "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
    
    return True, None

def validate_password(password):
    """
    Validate password strength requirements.
    
    Args:
        password (str): Password to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    return True, None

async def update_database_timestamp(datasette, db_name):
    """
    Update the last modified timestamp for a database by name.
    
    Args:
        datasette: Datasette instance
        db_name (str): Database name to update
    """
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
    """
    Update the last modified timestamp for a database by ID.
    
    Args:
        datasette: Datasette instance
        db_id (str): Database ID to update
    """
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
    Helper function to render templates with error messages.
    
    Args:
        datasette: Datasette instance
        template_name (str): Template file name
        template_data (dict): Data to pass to template
        request: HTTP request object
        error_message (str): Error message to display
        
    Returns:
        Response: HTTP response with error template
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
    Redirect user to appropriate page based on their role.
    
    Args:
        actor (dict): User actor data
        
    Returns:
        Response: Redirect response to admin panel or user dashboard
    """
    from datasette.utils.asgi import Response
    
    if actor.get("role") == "system_admin":
        return Response.redirect("/system-admin")
    else:
        return Response.redirect("/manage-databases")

def generate_website_url(request, db_name):
    """
    Generate a full website URL for a database homepage.
    
    Args:
        request: HTTP request object
        db_name (str): Database name
        
    Returns:
        str: Full URL to database homepage
    """
    scheme = request.scheme
    host = request.headers.get('host', 'localhost:8001')
    return f"{scheme}://{host}/db/{db_name}/homepage"

def ensure_data_directories():
    """
    Ensure that required data directories exist, creating them if necessary.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    logger.debug(f"Ensured data directories exist: {DATA_DIR}, {STATIC_DIR}")

def get_success_error_from_request(request):
    """
    Extract success and error messages from request query parameters.
    
    Args:
        request: HTTP request object
        
    Returns:
        dict: Dictionary with 'success' and 'error' keys from query params
    """
    return {
        'success': request.args.get('success'),
        'error': request.args.get('error')
    }

def create_feature_cards_from_databases(databases, limit):
    """
    Create feature card data from database records for display.
    
    Args:
        databases (list): List of database records
        limit (int): Maximum number of cards to create
        
    Returns:
        list: List of feature card dictionaries
    """
    feature_cards = []
    for db in databases[:limit]:
        feature_cards.append({
            'title': db['db_name'].replace('_', ' ').title(),
            'description': f"{db['status']} dataset",
            'url': db['website_url'],
            'icon': 'ri-database-line'
        })
    return feature_cards

def create_statistics_data(stats):
    """
    Create statistics display data from statistics dictionary.
    
    Args:
        stats (dict): Statistics dictionary
        
    Returns:
        list: List of statistic display items
    """
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
            "label": "View all available databases",
            "value": "Browse All Databases",
            "url": "/all-databases"
        }
    ]

def is_system_table(table_name):
    """
    Check if a table name is a system table that should be hidden from users.
    
    Args:
        table_name (str): Table name to check
        
    Returns:
        bool: True if table is a system table, False otherwise
    """
    fts_suffixes = ['_fts', '_fts_data', '_fts_idx', '_fts_docsize', '_fts_config']
    
    for suffix in fts_suffixes:
        if table_name.endswith(suffix):
            return True
    
    system_prefixes = ['sqlite_', 'fts4aux_', 'fts5vocab_']
    for prefix in system_prefixes:
        if table_name.startswith(prefix):
            return True
    
    return False

def sanitize_url_parameter(text):
    """
    Sanitize text for use in URL parameters, removing dangerous characters.
    
    Args:
        text (str): Text to sanitize
        
    Returns:
        str: Sanitized text safe for URL parameters
    """
    if not text:
        return ""
    
    sanitized = str(text)
    sanitized = sanitized.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    sanitized = ' '.join(sanitized.split())
    
    if len(sanitized) > 200:
        sanitized = sanitized[:197] + "..."
    
    sanitized = re.sub(r'[<>"\'&]', '', sanitized)
    
    return sanitized

def create_safe_redirect_url(base_url, param_name, message, is_error=False):
    """
    Create a safe redirect URL with message parameters.
    
    Args:
        base_url (str): Base URL to redirect to
        param_name (str): Parameter name for the message
        message (str): Message to include in URL
        is_error (bool): Whether this is an error message
        
    Returns:
        str: Safe redirect URL with encoded message
    """
    try:
        clean_message = sanitize_url_parameter(message)
        encoded_message = urllib.parse.quote(clean_message)
        
        separator = '&' if '?' in base_url else '?'
        safe_url = f"{base_url}{separator}{param_name}={encoded_message}"
        
        if len(safe_url) > 2000:
            max_msg_len = 2000 - len(base_url) - len(param_name) - 20
            truncated = clean_message[:max_msg_len] + "..." if max_msg_len > 0 else "Error message too long"
            encoded_message = urllib.parse.quote(truncated)
            safe_url = f"{base_url}{separator}{param_name}={encoded_message}"
        
        return safe_url
        
    except Exception as e:
        logger.error(f"Error creating redirect URL: {e}")
        fallback_msg = "Upload completed" if not is_error else "Upload failed"
        separator = '&' if '?' in base_url else '?'
        return f"{base_url}{separator}{param_name}={fallback_msg}"

async def handle_upload_error_gracefully(datasette, error, context=None):
    """
    Handle upload errors gracefully by providing user-friendly error messages.
    
    Args:
        datasette: Datasette instance
        error (Exception): The error that occurred
        context (str, optional): Context where error occurred
        
    Returns:
        str: User-friendly error message
    """
    try:
        error_type = type(error).__name__
        error_msg = str(error)
        
        logger.error(f"Upload error in {context or 'unknown'}: {error_type}: {error_msg}")
        
        if "UnicodeDecodeError" in error_type:
            return "File encoding error. Please save your file as UTF-8 and try again."
        elif "ParserError" in error_type or "tokenizing" in error_msg.lower():
            return "CSV format error. Please check that all rows have the same number of columns."
        elif "PermissionError" in error_type:
            return "File access error. Please ensure the file is not open in another program."
        elif "MemoryError" in error_type:
            return "File too large to process in memory. Please try a smaller file."
        elif "ConnectionError" in error_type or "timeout" in error_msg.lower():
            return "Network error. Please check your connection and try again."
        elif "EmptyDataError" in error_type:
            return "The uploaded file appears to be empty."
        elif any(keyword in error_msg.lower() for keyword in ["private", "unauthorized", "403", "401"]):
            return "Access denied. Please ensure the file/URL is publicly accessible."
        elif "domain" in error_msg.lower() and "blocked" in error_msg.lower():
            return "Domain not allowed. Please contact administrator or use an approved domain."
        else:
            return f"Upload failed: {error_msg[:100]}"
            
    except Exception as e:
        logger.error(f"Error in error handler: {e}")
        return "Upload failed due to an unexpected error"

async def log_upload_activity_enhanced(datasette, user_id, upload_type, details, metadata=None, error=None):
    """
    Log upload activity with enhanced metadata and error handling.
    
    Args:
        datasette: Datasette instance
        user_id (str): User performing the upload
        upload_type (str): Type of upload (csv, url, etc.)
        details (str): Description of the upload
        metadata (dict, optional): Additional metadata
        error (Exception, optional): Error that occurred during upload
    """
    try:
        query_db = datasette.get_database("portal")
        
        log_data = {
            'log_id': uuid.uuid4().hex[:20],
            'user_id': user_id,
            'action': f'upload_{upload_type}',
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        enhanced_metadata = metadata or {}
        if error:
            enhanced_metadata['error'] = {
                'type': type(error).__name__,
                'message': str(error)[:500],
                'occurred_at': datetime.utcnow().isoformat()
            }
        
        if enhanced_metadata:
            log_data['action_metadata'] = json.dumps(enhanced_metadata)
        
        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp, action_metadata) VALUES (?, ?, ?, ?, ?, ?)",
            [log_data['log_id'], log_data['user_id'], log_data['action'], log_data['details'], 
             log_data['timestamp'], log_data.get('action_metadata')]
        )
        
        logger.debug(f"Logged upload activity for user {user_id}: {upload_type}")
        
    except Exception as e:
        logger.error(f"Error logging upload activity: {e}")

async def sync_database_tables_on_upload(datasette, db_id, table_name):
    """
    Sync database table metadata when a new table is uploaded.
    
    Args:
        datasette: Datasette instance
        db_id (str): Database ID
        table_name (str): Name of the uploaded table
    """
    try:
        portal_db = datasette.get_database('portal')
        table_id = f"{db_id}_{table_name}"
        current_time = datetime.utcnow().isoformat()
        
        existing_result = await portal_db.execute(
            "SELECT table_id FROM database_tables WHERE table_id = ?", [table_id]
        )
        
        if not existing_result.first():
            count_result = await portal_db.execute(
                "SELECT COALESCE(MAX(display_order), 99) + 1 as next_order FROM database_tables WHERE db_id = ?", [db_id]
            )
            next_order = count_result.first()['next_order']
            
            await portal_db.execute_write("""
                INSERT INTO database_tables 
                (table_id, db_id, table_name, show_in_homepage, display_order, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [table_id, db_id, table_name, True, next_order, current_time, current_time])
            
            logger.info(f"Synced table {table_name} (order: {next_order}) for database {db_id}")
        
    except Exception as e:
        logger.error(f"Error syncing database_tables for {table_name}: {e}")

def sanitize_filename_for_table(filename):
    """
    Create a safe table name from a filename.
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Sanitized table name safe for SQLite
    """
    if not filename:
        return f'table_{uuid.uuid4().hex[:8]}'
    
    base_name = os.path.splitext(filename)[0]
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', base_name)
    
    if clean_name and not clean_name[0].isalpha():
        clean_name = 'table_' + clean_name
    
    clean_name = re.sub(r'_{2,}', '_', clean_name)
    
    if len(clean_name) > 60:
        clean_name = clean_name[:60].rstrip('_')
    
    return clean_name[:64] or f'table_{uuid.uuid4().hex[:8]}'

def validate_table_name_enhanced(name):
    """
    Validate table name for SQLite compatibility and safety.
    
    Args:
        name (str): Table name to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not name:
        return False, "Table name cannot be empty"
    
    name = str(name).strip()
    
    if len(name) > 64:
        return False, "Table name too long (max 64 characters)"
    
    if not re.match(r'^[a-zA-Z]', name):
        return False, "Table name must start with a letter"
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', name):
        return False, "Table name can only contain letters, numbers, and underscores"
    
    sql_keywords = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER',
        'TABLE', 'INDEX', 'VIEW', 'DATABASE', 'FROM', 'WHERE', 'ORDER', 
        'GROUP', 'HAVING', 'UNION', 'JOIN', 'INNER', 'LEFT', 'RIGHT',
        'FULL', 'CROSS', 'ON', 'AS', 'AND', 'OR', 'NOT', 'NULL'
    }
    
    if name.upper() in sql_keywords:
        return False, f"'{name}' is a reserved SQL keyword"
    
    return True, None

def auto_fix_table_name(name):
    """
    Automatically fix common table name issues.
    
    Args:
        name (str): Table name to fix
        
    Returns:
        str: Fixed table name
    """
    if not name:
        return name
    
    name = str(name).strip()
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    
    if name and not re.match(r'^[a-zA-Z]', name):
        name = 'table_' + name
    
    name = re.sub(r'_{2,}', '_', name)
    name = name.strip('_')
    
    if len(name) > 64:
        name = name[:60]
    
    if not name:
        name = f'table_{uuid.uuid4().hex[:8]}'
    
    return name

async def handle_image_upload_robust(datasette, request, db_id, actor, max_img_size):
    """
    Handle image upload with robust error handling and processing.
    
    Args:
        datasette: Datasette instance
        request: HTTP request with multipart form data
        db_id (str): Database ID (None for portal-wide images)
        actor (dict): User performing the upload
        max_img_size (int): Maximum allowed image size in bytes
        
    Returns:
        tuple: (result_dict or None, error_message or None)
    """
    try:
        content_type = request.headers.get('content-type', '')
        if 'multipart/form-data' not in content_type.lower():
            return None, "Invalid content type for file upload"
        
        body = await request.post_body()
        
        if len(body) > max_img_size:
            size_mb = max_img_size / (1024 * 1024)
            return None, f"File too large. Maximum size: {size_mb:.0f}MB"
        
        try:
            forms, files = parse_multipart_form_data_robust(body, content_type)
        except Exception as parse_error:
            logger.error(f"Multipart parsing failed: {parse_error}")
            return None, f"Failed to parse upload data: {str(parse_error)}"
        
        if 'image' not in files or not files['image']['content']:
            return None, "No image file found in upload"
        
        file_info = files['image']
        filename = file_info['filename']
        file_content = file_info['content']
        
        allowed_extensions = ['.jpg', '.jpeg', '.png']
        ext = os.path.splitext(filename)[1].lower()
        if ext not in allowed_extensions:
            return None, f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        
        if len(file_content) > max_img_size:
            size_mb = max_img_size / (1024 * 1024)
            return None, f"Image file too large. Maximum size: {size_mb:.0f}MB"
        
        return await process_image_upload_robust(datasette, db_id, file_content, filename, forms, actor)
        
    except Exception as e:
        logger.error(f"Image upload handler error: {e}")
        return None, f"Upload failed: {str(e)}"

async def process_image_upload_robust(datasette, db_id, file_content, filename, forms, actor):
    """
    Process uploaded image with optimization and storage.
    
    Args:
        datasette: Datasette instance
        db_id (str): Database ID (None for portal images)
        file_content (bytes): Image file content
        filename (str): Original filename
        forms (dict): Form data from upload
        actor (dict): User performing upload
        
    Returns:
        tuple: (result_dict or None, error_message or None)
    """
    try:
        if db_id:
            save_dir = os.path.join(DATA_DIR, db_id)
            image_filename = 'header.jpg'
            url_path = f"/data/{db_id}/header.jpg"
            max_size = (1680, 450)
        else:
            save_dir = STATIC_DIR
            image_filename = 'portal_header.jpg'
            url_path = f"/static/portal_header.jpg"
            max_size = (1680, 450)
        
        os.makedirs(save_dir, exist_ok=True)
        
        temp_path = os.path.join(save_dir, f'temp_{image_filename}')
        final_path = os.path.join(save_dir, image_filename)
        
        with open(temp_path, 'wb') as f:
            f.write(file_content)
        
        success, optimized_size, reduction = await optimize_uploaded_image_robust(
            temp_path, final_path, max_size=max_size, quality=100
        )
        
        if os.path.exists(temp_path) and temp_path != final_path:
            os.remove(temp_path)
        
        import time
        timestamp = int(time.time())
        result = {
            'image_url': f"{url_path}?v={timestamp}",
            'alt_text': forms.get('alt_text', [''])[0] if 'alt_text' in forms else '',
            'credit_text': forms.get('credit_text', [''])[0] if 'credit_text' in forms else '',
            'credit_url': forms.get('credit_url', [''])[0] if 'credit_url' in forms else ''
        }
        
        return result, None
        
    except Exception as e:
        logger.error(f"Image processing error: {e}")
        return None, f"Failed to process image: {str(e)}"

async def optimize_uploaded_image_robust(temp_path, final_path, max_size=(1680, 450), quality=100):
    """
    Optimize uploaded image by resizing and compressing.
    
    Args:
        temp_path (str): Temporary file path
        final_path (str): Final file path
        max_size (tuple): Maximum dimensions (width, height)
        quality (int): JPEG quality (1-100)
        
    Returns:
        tuple: (success: bool, final_size: int, reduction_percent: float)
    """
    try:
        from PIL import Image
        
        original_size = os.path.getsize(temp_path)
        
        if original_size < 1024 * 1024:
            if temp_path != final_path:
                import shutil
                shutil.move(temp_path, final_path)
            return True, original_size, 0
        
        with Image.open(temp_path) as img:
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            if img.size[0] > max_size[0] or img.size[1] > max_size[1]:
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            img.save(final_path, 'JPEG', quality=quality, optimize=True)
        
        new_size = os.path.getsize(final_path)
        space_saved = max(0, original_size - new_size)
        reduction_percent = (space_saved / original_size) * 100 if original_size > 0 else 0
        
        logger.info(f"Image optimized: {original_size} → {new_size} bytes ({reduction_percent:.1f}% reduction)")
        return True, new_size, reduction_percent
        
    except ImportError:
        logger.warning("PIL/Pillow not available, using original image")
        if temp_path != final_path:
            import shutil
            shutil.move(temp_path, final_path)
        return True, os.path.getsize(final_path), 0
        
    except Exception as e:
        logger.error(f"Image optimization failed: {e}")
        if temp_path != final_path and os.path.exists(temp_path):
            import shutil
            shutil.move(temp_path, final_path)
        return False, os.path.getsize(final_path) if os.path.exists(final_path) else 0, 0

def optimize_existing_header_images(datasette):
    """
    Optimize existing header images to reduce file sizes.
    
    Args:
        datasette: Datasette instance
        
    Returns:
        tuple: (optimized_count: int, total_savings: int)
    """
    try:
        optimized_count = 0
        total_savings = 0
        
        portal_header = os.path.join(DATA_DIR, "../static/portal_header.jpg")
        if os.path.exists(portal_header):
            backup_path = portal_header + ".backup"
            thumbnail_path = portal_header + ".tmp"
            
            try:
                import shutil
                shutil.copy2(portal_header, backup_path)
                
                success, new_size, reduction = create_image_thumbnail(portal_header, thumbnail_path)
                if success:
                    shutil.move(thumbnail_path, portal_header)
                    optimized_count += 1
                    
                    original_size = os.path.getsize(backup_path)
                    total_savings += (original_size - new_size)
                    logger.info(f"Optimized portal header: {reduction:.1f}% size reduction")
                
            except Exception as e:
                logger.error(f"Error optimizing portal header: {e}")
        
        for db_dir in os.listdir(DATA_DIR):
            db_path = os.path.join(DATA_DIR, db_dir)
            if os.path.isdir(db_path):
                header_path = os.path.join(db_path, "header.jpg")
                if os.path.exists(header_path):
                    backup_path = header_path + ".backup"
                    thumbnail_path = header_path + ".tmp"
                    
                    try:
                        import shutil
                        shutil.copy2(header_path, backup_path)
                        
                        success, new_size, reduction = create_image_thumbnail(header_path, thumbnail_path)
                        if success:
                            shutil.move(thumbnail_path, header_path)
                            optimized_count += 1
                            
                            original_size = os.path.getsize(backup_path)
                            total_savings += (original_size - new_size)
                            logger.info(f"Optimized database header {db_dir}: {reduction:.1f}% reduction")
                    
                    except Exception as e:
                        logger.error(f"Error optimizing database header {db_dir}: {e}")
        
        logger.info(f"Image optimization complete: {optimized_count} images optimized, {total_savings} bytes saved")
        return optimized_count, total_savings
        
    except Exception as e:
        logger.error(f"Error during image optimization: {e}")
        return 0, 0

def create_image_thumbnail(image_path, thumbnail_path, max_size=(1680, 450), quality=100):
    """
    Create an optimized thumbnail of an image.
    
    Args:
        image_path (str): Path to source image
        thumbnail_path (str): Path for optimized image
        max_size (tuple): Maximum dimensions (width, height)
        quality (int): JPEG quality (1-100)
        
    Returns:
        tuple: (success: bool, thumbnail_size: int, reduction_percent: float)
    """
    try:
        from PIL import Image
        
        with Image.open(image_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            img.save(thumbnail_path, 'JPEG', quality=quality, optimize=True)
            
            original_size = os.path.getsize(image_path)
            thumbnail_size = os.path.getsize(thumbnail_path)
            reduction_percent = ((original_size - thumbnail_size) / original_size) * 100
            
            logger.info(f"Created thumbnail: {original_size} bytes → {thumbnail_size} bytes ({reduction_percent:.1f}% reduction)")
            return True, thumbnail_size, reduction_percent
            
    except ImportError:
        logger.warning("PIL/Pillow not available, cannot create thumbnails")
        return False, 0, 0
    except Exception as e:
        logger.error(f"Error creating thumbnail: {e}")
        return False, 0, 0

def parse_multipart_form_data_robust(body, content_type):
    """
    Parse multipart form data from request body with robust error handling.
    
    Args:
        body (bytes): Request body containing multipart data
        content_type (str): Content-Type header value
        
    Returns:
        tuple: (forms: dict, files: dict) parsed from multipart data
    """
    try:
        boundary = content_type.split('boundary=')[-1].split(';')[0].strip() if 'boundary=' in content_type else None
        if not boundary:
            return {}, {}
            
        headers = f'Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n'
        msg = BytesParser(policy=default).parsebytes(headers.encode() + body)
        
        forms = {}
        files = {}
        
        for part in msg.iter_parts():
            if not part.is_multipart():
                content_disposition = part.get('Content-Disposition', '')
                
                name_match = re.search(r'name="([^"]+)"', content_disposition)
                filename_match = re.search(r'filename="([^"]*)"', content_disposition)
                
                if name_match:
                    field_name = name_match.group(1)
                    content = part.get_payload(decode=True)
                    
                    if filename_match and filename_match.group(1):
                        files[field_name] = {
                            'filename': filename_match.group(1),
                            'content': content or b''
                        }
                    else:
                        forms[field_name] = content.decode('utf-8', errors='ignore') if content else ''
        
        return forms, files
        
    except Exception as e:
        logger.error(f"Multipart parsing failed: {e}")
        return {}, {}