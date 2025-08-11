import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.utils import tilde_encode
from datasette.database import Database
import bleach
import re
import sqlite_utils
import uuid
import os
import base64
from email.parser import BytesParser
from email.policy import default
import asyncio

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv','.txt'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_DATABASES_PER_USER = 10
STATIC_DIR = os.getenv('EDGI_STATIC_DIR', "/static")
DATA_DIR = os.getenv('EDGI_DATA_DIR', "/data")
TRASH_RETENTION_DAYS = 30

def get_actor_from_request(request):
    """Extract actor from ds_actor cookie."""
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
    """Set actor cookie on response."""
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
    """Enhanced logging with metadata support."""
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
        logger.error(f"Error logging action: {e}")

def sanitize_text(text):
    """Sanitize text by stripping HTML tags while preserving safe characters."""
    return bleach.clean(text, tags=[], strip=True)

def parse_markdown_links(text):
    """Enhanced markdown parser that handles links, bold, italic, and lists."""
    import re
    
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
    import re
    
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
    """Check if database name is globally unique, including trashed databases."""
    db = datasette.get_database("portal")
    if exclude_db_id:
        result = await db.execute(
            "SELECT COUNT(*) FROM databases WHERE db_name = ? AND db_id != ? AND status != 'Deleted'", 
            [db_name, exclude_db_id]
        )
    else:
        result = await db.execute(
            "SELECT COUNT(*) FROM databases WHERE db_name = ? AND status != 'Deleted'", 
            [db_name]
        )
    return result.first()[0] == 0

async def check_database_name_available(datasette, db_name):
    """Check if database name is available for new creation (not reserved by trash)."""
    db = datasette.get_database("portal")
    result = await db.execute(
        "SELECT COUNT(*) FROM databases WHERE db_name = ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed')", 
        [db_name]
    )
    return result.first()[0] == 0

async def get_database_content(datasette, db_name):
    """Get homepage content for a database with proper header image handling."""
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
            'content': 'Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.',
            'odbl_text': 'Data licensed under ODbL',
            'odbl_url': 'https://opendatacommons.org/licenses/odbl/',
            'paragraphs': ['Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.']
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
    """Get enhanced database statistics for homepage with encoding safety."""
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
            # Total active databases (not deleted or trashed)
            total_result = await db.execute(
                "SELECT COUNT(*) FROM databases WHERE status IN ('Draft', 'Published', 'Unpublished')"
            )
            stats['total_databases'] = total_result.first()[0] if total_result.first() else 0
        except Exception as e:
            logger.error(f"Error getting total databases: {e}")
        
        try:
            # Published databases
            published_result = await db.execute(
                "SELECT COUNT(*) FROM databases WHERE status = 'Published'"
            )
            stats['published_databases'] = published_result.first()[0] if published_result.first() else 0
        except Exception as e:
            logger.error(f"Error getting published databases: {e}")
        
        # User-specific statistics if user_id provided
        if user_id:
            try:
                # User active databases
                user_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished')", 
                    [user_id]
                )
                stats['user_databases'] = user_result.first()[0] if user_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user databases for {user_id}: {e}")
            
            try:
                # User published databases
                user_published_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status = 'Published'", 
                    [user_id]
                )
                stats['user_published'] = user_published_result.first()[0] if user_published_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user published databases for {user_id}: {e}")
            
            try:
                # User trashed databases
                user_trashed_result = await db.execute(
                    "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status = 'Trashed'", 
                    [user_id]
                )
                stats['user_trashed'] = user_trashed_result.first()[0] if user_trashed_result.first() else 0
            except Exception as e:
                logger.error(f"Error getting user trashed databases for {user_id}: {e}")
        
        try:
            # Featured databases for homepage - only get essential fields
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

async def manage_databases(datasette, request):
    """Enhanced manage databases with three-tier deletion system."""
    logger.debug(f"Manage Databases request: method={request.method}")

    actor = get_actor_from_request(request)

    if not actor:
        logger.warning(f"Unauthorized manage databases attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute("SELECT user_id, username FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
    except Exception as e:
        logger.error(f"Error verifying user in manage_databases: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    # Get filter parameter
    status_filter = request.args.get('status', 'active')
    
    # Build query based on filter
    if status_filter == 'active':
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished')"
    elif status_filter == 'trash':
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline FROM databases WHERE user_id = ? AND status = 'Trashed'"
    else:
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed')"
    
    result = await query_db.execute(query, [actor.get("id")])
    user_databases = [dict(row) for row in result]
    
    title = await query_db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'},
        'footer': {'content': 'Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': ['Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.']}
    }

    # Enhanced database processing with better error handling
    databases_with_tables = []
    for db_info in user_databases:
        db_name = db_info["db_name"]
        db_id = db_info["db_id"]
        total_size = 0
        tables = []
        table_count = 0

        # Check if database has custom homepage
        homepage_result = await query_db.execute(
            "SELECT COUNT(*) FROM admin_content WHERE db_id = ? AND section = 'title'",
            [db_id]
        )
        has_custom_homepage = homepage_result.first()[0] > 0
        try:
            db_path = db_info["file_path"]
            if db_path and os.path.exists(db_path):
                user_db = sqlite_utils.Database(db_path)
                table_names = user_db.table_names()
                table_count = len(table_names)
                
                for name in table_names:
                    try:
                        table_info = user_db[name]
                        record_count = table_info.count
                        table_size = record_count * 0.001  # Estimate size
                        total_size += table_size
                        
                        tables.append({
                            'name': name,
                            'full_name': name,
                            'preview': f"/{db_name}/{name}",
                            'size': table_size,
                            'record_count': record_count,
                            'columns': len(list(table_info.columns_dict.keys())),
                            'progress': 100
                        })
                    except Exception as table_error:
                        logger.error(f"Error processing table {name} in {db_name}: {table_error}")
                        tables.append({
                            'name': name,
                            'full_name': name,
                            'preview': f"/{db_name}/{name}",
                            'size': 0,
                            'record_count': 0,
                            'columns': 0,
                            'progress': 0,
                            'error': True
                        })
            else:
                logger.error(f"Database file not found for {db_name}: {db_path}")
        except Exception as e:
            logger.error(f"Error loading database {db_name}: {str(e)}")
            
        databases_with_tables.append({
            **db_info,
            'tables': tables,
            'table_count': table_count,
            'total_size': total_size,
            'website_url': f"/{db_name}/", # Datasette URL format
            'upload_url': f"/upload-secure/{db_name}",  # 
            'has_custom_homepage': has_custom_homepage  # Indicate if custom homepage exists
        })

    stats = await get_database_statistics(datasette, actor.get("id"))

    return Response.html(
        await datasette.render_template(
            "manage_databases.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "user_databases": databases_with_tables,
                "status_filter": status_filter,
                "stats": stats,
                "success": request.args.get('success'),
                "error": request.args.get('error'),
            },
            request=request
        )
    )

async def create_database(datasette, request):
    """Create new database."""
    logger.debug(f"Create Database request: method={request.method}")

    actor = get_actor_from_request(request)

    if not actor:
        logger.warning(f"Unauthorized create database attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute("SELECT user_id, username FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
    except Exception as e:
        logger.error(f"Error verifying user in create_database: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    title = await query_db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    if request.method == "POST":
        post_vars = await request.post_vars()
        db_name = post_vars.get("db_name", "").strip()
        
        if not db_name:
            return Response.html(
                await datasette.render_template(
                    "create_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "error": "Database name is required"
                    },
                    request=request
                )
            )

        # Validate database name format
        if not re.match(r'^[a-z0-9_]+$', db_name):
            return Response.html(
                await datasette.render_template(
                    "create_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "error": "Database name must contain only lowercase letters, numbers, and underscores"
                    },
                    request=request
                )
            )

        is_unique = await check_database_name_unique(datasette, db_name)
        if not is_unique:
            return Response.html(
                await datasette.render_template(
                    "create_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "error": f"Database name '{db_name}' already exists. Please choose a different name."
                    },
                    request=request
                )
            )

        user_id = actor.get("id")
        
        # Check database limit
        result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
        db_count = result.first()[0]
        if db_count >= MAX_DATABASES_PER_USER:
            return Response.html(
                await datasette.render_template(
                    "create_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "error": f"Maximum {MAX_DATABASES_PER_USER} databases per user reached"
                    },
                    request=request
                )
            )

        try:
            db_id = uuid.uuid4().hex[:20]
            scheme = request.scheme
            host = request.headers.get('host', 'localhost:8001')
            website_url = f"{scheme}://{host}/{db_name}/"
            
            # Create user directory and database file
            user_dir = os.path.join(DATA_DIR, user_id)
            os.makedirs(user_dir, exist_ok=True)
            db_path = os.path.join(user_dir, f"{db_name}.db")
            
            # Create new SQLite database
            user_db = sqlite_utils.Database(db_path)

            # Insert database record
            await query_db.execute_write(
                "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at, file_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [db_id, user_id, db_name, website_url, "Draft", datetime.utcnow(), db_path]
            )
            
            # CRITICAL: Register database with Datasette immediately (even for drafts)
            try:
                db_instance = Database(datasette, path=db_path, is_mutable=True)
                datasette.add_database(db_instance, name=db_name)
                logger.debug(f"Successfully registered new database: {db_name} (Draft)")
            except Exception as reg_error:
                logger.error(f"Error registering new database {db_name}: {reg_error}")

            # Log activity
            await log_database_action(
                datasette, user_id, "create_database", 
                f"Created database {db_name}",
                {
                    "db_name": db_name,
                    "db_id": db_id,
                    "website_url": website_url
                }
            )
            
            logger.debug(f"Database created: {db_name}, website_url={website_url}, file_path={db_path}")
            return Response.redirect(f"/manage-databases?success=Database '{db_name}' created successfully.")

        except Exception as e:
            logger.error(f"Create database error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "create_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "error": f"Create database error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "create_database.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
            },
            request=request
        )
    )

async def publish_database(datasette, request):
    """Publish database (make it publicly accessible)."""
    logger.debug(f"Publish Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Handle /db/{db_name}/publish path
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        if db_info['status'] == 'Published':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is already published")
        
        if db_info['status'] == 'Trashed':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is in trash. Restore it first.")
        
        # Update status to Published
        await query_db.execute_write(
            "UPDATE databases SET status = 'Published' WHERE db_name = ?",
            [db_name]
        )
        
        # Register database with Datasette
        if db_info['file_path'] and os.path.exists(db_info['file_path']):
            try:
                user_db = Database(datasette, path=db_info['file_path'], is_mutable=True)
                datasette.add_database(user_db, name=db_name)
                logger.debug(f"Successfully registered published database: {db_name}")
            except Exception as reg_error:
                logger.error(f"Error registering database {db_name}: {reg_error}")
        
        await log_database_action(
            datasette, actor.get("id"), "publish_database", 
            f"Published database {db_name}",
            {
                "db_name": db_name,
                "previous_status": db_info['status'],
                "new_status": "Published"
            }
        )
        
        return Response.redirect(f"/manage-databases?success=Database '{db_name}' published successfully! It's now publicly accessible at /{db_name}/")
        
    except Exception as e:
        logger.error(f"Error publishing database {db_name}: {str(e)}")
        return Response.text(f"Error publishing database: {str(e)}", status=500)

async def delete_table(datasette, request):
    """Delete table from database."""
    actor = get_actor_from_request(request)
    
    # Check if user is authenticated
    if not actor:
        return Response.redirect("/login")
    
    # Extract parameters from URL path
    path_parts = request.path.strip('/').split('/')
    if len(path_parts) >= 3 and path_parts[0] == 'delete-table':
        db_name = path_parts[1]
        table_name = path_parts[2]
    else:
        return Response.redirect("/manage-databases?error=Invalid URL format")
    
    logger.debug(f"Delete table request: db_name={db_name}, table_name={table_name}")
    
    # Verify user owns the database
    if not await user_owns_database(datasette, actor["id"], db_name):
        return Response(
            "Access denied: You don't have permission to delete tables from this database",
            status=403
        )
    
    # Handle POST request (actual deletion)
    if request.method == "POST":
        try:
            post_vars = await request.post_vars()
            logger.debug(f"POST vars: {list(post_vars.keys())}")

            # Get the target database
            target_db = datasette.get_database(db_name)

            # Check if table exists
            tables = await target_db.table_names()
            if table_name not in tables:
                return Response.redirect(
                    f"/manage-databases?error=Table '{table_name}' not found in database '{db_name}'"
                )
                        
            # Delete the table
            await target_db.execute_write(f"DROP TABLE [{table_name}]")
            logger.debug(f"Successfully deleted table {table_name} from {db_name}")
            
            await log_database_action(
                datasette, actor.get("id"), "delete_table", 
                f"Deleted table {table_name} from {db_name}",
                {"db_name": db_name, "table_name": table_name}
            )
            
            return Response.redirect(
                f"/manage-databases?success=Table '{table_name}' deleted successfully from '{db_name}'"
            )
            
        except Exception as e:
            logger.error(f"Error deleting table {table_name} from {db_name}: {e}")
            return Response.redirect(
                f"/manage-databases?error=Failed to delete table: {str(e)}"
            )
    
    # Handle GET request (show confirmation page)
    else:
        try:
            target_db = datasette.get_database(db_name)
            
            # Get table information
            table_info = await target_db.execute(
                f"SELECT COUNT(*) as row_count FROM [{table_name}]"
            )
            row_count = table_info.rows[0][0] if table_info.rows else 0
            
            # Get column information
            columns_info = await target_db.execute(f"PRAGMA table_info([{table_name}])")
            columns = [row[1] for row in columns_info.rows]  # column names
            
            return Response.html(
                await datasette.render_template(
                    "delete_table_confirm.html",
                    {
                        "db_name": db_name,
                        "table_name": table_name,
                        "row_count": row_count,
                        "column_count": len(columns),
                        "columns": columns[:5],  # Show first 5 columns
                    },
                    request=request
                )
            )
            
        except Exception as e:
            logger.error(f"Error accessing table information for {table_name}: {e}")
            return Response.redirect(
                f"/manage-databases?error=Error accessing table information: {str(e)}"
            )

async def delete_table_ajax(datasette, request):
    """AJAX endpoint for table deletion."""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)
    
    try:
        # Parse JSON body
        import json
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))
        
        db_name = data.get('db_name')
        table_name = data.get('table_name')
        
        if not db_name or not table_name:
            return Response.json({"error": "Missing db_name or table_name"}, status=400)
              
        # Verify ownership
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"error": "Access denied"}, status=403)
        
        # Get target database
        target_db = datasette.get_database(db_name)
        if not target_db:
            return Response.json({"error": f"Database '{db_name}' not found"}, status=404)
        
        # Check if table exists
        tables = await target_db.table_names()
        if table_name not in tables:
            return Response.json({"error": f"Table '{table_name}' not found"}, status=404)
        
        # Delete the table
        await target_db.execute_write(f"DROP TABLE [{table_name}]")
        
        # Log the deletion
        await log_database_action(
            datasette, actor["id"], "delete_table",
            f"Deleted table {table_name} from {db_name}",
            {"db_name": db_name, "table_name": table_name}
        )
        
        return Response.json({
            "success": True,
            "message": f"Table '{table_name}' deleted successfully from '{db_name}'"
        })
        
    except Exception as e:
        logger.error(f"Error in delete_table_ajax: {e}")
        return Response.json({"error": f"Failed to delete table: {str(e)}"}, status=500)

async def database_homepage(datasette, request):
    """Enhanced database homepage with better error handling."""
    logger.debug(f"Database homepage request: method={request.method}, path={request.path}")

    # Handle both /db/{db_name}/homepage and /{db_name}/ patterns
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]  # /db/{db_name}/homepage
    else:
        db_name = path_parts[0]  # /{db_name}/
    
    if not db_name:
        return Response.text("Not found", status=404)
    
    # Check if database exists and user has permission
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, db_name, status, user_id, file_path FROM databases WHERE db_name = ?",
            [db_name]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        
        # Access control: Published databases are public, drafts only for owners
        if db_info['status'] != 'Published' and (not actor or actor['id'] != db_info['user_id']):
            return Response.text("Database not found or not published", status=404)
        
        # FIXED: Check if database is registered correctly
        try:
            # Try to get the database - this will work if it's registered
            user_db = datasette.get_database(db_name)
            if not user_db:
                # Database not registered, try to register it
                if db_info['file_path'] and os.path.exists(db_info['file_path']):
                    new_db = Database(datasette, path=db_info['file_path'], is_mutable=True)
                    datasette.add_database(new_db, name=db_name)
                    user_db = datasette.get_database(db_name)
                    logger.debug(f"Successfully registered database: {db_name}")
                else:
                    return Response.text("Database file not found", status=500)
        except Exception as reg_error:
            logger.error(f"Failed to register database {db_name}: {reg_error}")
            return Response.text("Database registration failed", status=500)
        
    except Exception as e:
        logger.error(f"Error checking database {db_name}: {e}")
        return Response.text("Database error", status=500)
    
    try:
        content = await get_database_content(datasette, db_name)
        if not content:
            logger.error(f"No content found for database {db_name}")
            # Redirect to standard Datasette interface
            return Response.redirect(f"/{db_name}")
        
        # Check if content is customized
        default_title = db_name.replace('_', ' ').title()
        default_description = 'Environmental data dashboard powered by Datasette.'
        default_footer = 'Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.'
        
        has_custom_title = content.get('title', {}).get('content', '') != default_title
        has_custom_description = content.get('description', {}).get('content', '') != default_description
        has_custom_footer = content.get('footer', {}).get('content', '') != default_footer
        
        # Check for custom header image
        has_custom_image = False
        header_image = content.get('header_image', {})
        if 'image_url' in header_image:
            image_url = header_image['image_url']
            has_custom_image = not image_url.endswith('/static/default_header.jpg')
        
        is_customized = has_custom_title or has_custom_description or has_custom_footer or has_custom_image
        
        # If not customized, redirect to Datasette's default database page
        if not is_customized:
            logger.debug(f"No customization found for {db_name}, redirecting to Datasette default")
            return Response.redirect(f"/{db_name}")
        
        # Get database statistics for custom homepage
        try:
            user_db = datasette.get_database(db_name)
            if user_db:
                # Use proper async operations
                table_names_result = await user_db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                table_names = [row['name'] for row in table_names_result.rows]
                
                tables = []
                total_records = 0
                
                for table_name in table_names[:6]:  # Show max 6 featured tables
                    try:
                        count_result = await user_db.execute(f"SELECT COUNT(*) as count FROM [{table_name}]")
                        record_count = count_result.first()['count'] if count_result.first() else 0
                        total_records += record_count
                        
                        tables.append({
                            'title': table_name.replace('_', ' ').title(),
                            'description': f"Data table with {record_count:,} records",
                            'url': f"/{db_name}/{table_name}",
                            'icon': 'ri-table-line',
                            'count': record_count
                        })
                    except Exception as table_error:
                        logger.error(f"Error processing table {table_name}: {table_error}")
                        continue
                
                statistics = [
                    {
                        'label': 'Data Tables',
                        'value': len(table_names),
                        'url': f'/{db_name}'
                    },
                    {
                        'label': 'Total Records',
                        'value': f"{total_records:,}",
                        'url': f'/{db_name}'
                    },
                    {
                        'label': 'Explore Data',
                        'value': 'Browse',
                        'url': f'/{db_name}'
                    }
                ]
            else:
                tables = []
                statistics = []
        except Exception as stats_error:
            logger.error(f"Error getting database stats for {db_name}: {stats_error}")
            tables = []
            statistics = []
        
        return Response.html(
            await datasette.render_template(
                "database_homepage.html",
                {
                    "page_title": content.get('title', {}).get('content', db_name) + " | Environmental Data",
                    "content": content,
                    "header_image": content.get('header_image', {}),
                    "info": content.get('info', content.get('description', {})),
                    "feature_cards": tables,
                    "statistics": statistics,
                    "footer": content.get('footer', {}),
                    "db_name": db_name,
                    "tables": tables
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error rendering database homepage for {db_name}: {e}")
        return Response.text("Error loading database homepage", status=500)

async def create_homepage(datasette, request):
    """Create custom homepage for database."""
    logger.debug(f"Create Homepage request: method={request.method}, path={request.path}")

    # Handle /db/{db_name}/create-homepage path
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id, status FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or permission denied", status=404)
        
        db_id = db_info['db_id']
        
        # Check if homepage already exists
        homepage_result = await query_db.execute(
            "SELECT COUNT(*) FROM admin_content WHERE db_id = ? AND section = 'title'",
            [db_id]
        )
        
        if homepage_result.first()[0] > 0:
            # Homepage already exists, redirect to edit
            return Response.redirect(f"/edit-content/{db_id}")
        
        custom_title = f"Custom {db_name.replace('_', ' ').title()} Environmental Data Portal"
        custom_description = f"Welcome to the {db_name.replace('_', ' ').title()} environmental data portal. This database contains important environmental monitoring data and research findings. Explore our comprehensive datasets to understand environmental trends and patterns."
        custom_footer = f"Environmental data portal for {db_name.replace('_', ' ').title()} | Powered by EDGI and Public Environmental Data Partners"
        
        custom_content = [
            ("title", {"content": custom_title}),
            ("description", {
                "content": custom_description,
                "paragraphs": parse_markdown_links(custom_description)
            }),
            ("header_image", {
                "image_url": "/static/default_header.jpg",
                "alt_text": f"{db_name.replace('_', ' ').title()} EDGI Portal Header by J. Alex Lang",
                "credit_text": "Image by J. Alex Lang. Used by permission udated.",
                "credit_url": "https://www.flickr.com/photos/jalexlang/21359307802/"
            }),
            ("footer", {
                "content": custom_footer,
                "odbl_text": "Data licensed under ODbL",
                "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                "paragraphs": parse_markdown_links(custom_footer)
            })
        ]
        
        # Insert custom content
        for section, content_data in custom_content:
            await query_db.execute_write(
                "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                [db_id, section, json.dumps(content_data), datetime.utcnow().isoformat(), actor['username']]
            )
        
        await log_database_action(
            datasette, actor.get("id"), "create_homepage", 
            f"Created custom homepage for {db_name}",
            {"db_name": db_name, "db_id": db_id}
        )
        
        return Response.redirect(f"/edit-content/{db_id}?success=Custom homepage created! You can now customize your database portal.")
        
    except Exception as e:
        logger.error(f"Error creating homepage for {db_name}: {str(e)}")
        return Response.text(f"Error creating homepage: {str(e)}", status=500)

async def edit_content(datasette, request):
    """Edit database content and homepage."""
    logger.debug(f"Edit Content request: method={request.method}, path={request.path}")

    path_parts = request.path.strip('/').split('/')
    if len(path_parts) < 2:
        return Response.text("Invalid URL", status=400)
    
    db_id = path_parts[1]
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute("SELECT db_name, status, user_id FROM databases WHERE db_id = ?", [db_id])
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        if not actor or actor['id'] != db_info['user_id']:
            return Response.text("Permission denied", status=403)
    except Exception as e:
        logger.error(f"Error checking database for db_id {db_id}: {e}")
        return Response.text("Database error", status=500)
    
    db_name = db_info['db_name']
    db_status = db_info['status']
    
    content = await get_database_content(datasette, db_name)
    
    if request.method == "POST":
        content_type = request.headers.get('content-type', '').lower()
        if 'multipart/form-data' in content_type:
            # Handle image upload using email.parser approach
            try:
                body = await request.post_body()
                
                if len(body) > MAX_FILE_SIZE:
                    return Response.text("File too large", status=400)
                
                # Parse the content-type header to get boundary
                boundary = None
                if 'boundary=' in content_type:
                    boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
                
                if not boundary:
                    logger.error("No boundary found in Content-Type header")
                    return Response.redirect(f"{request.path}?error=Invalid form data")
                
                # Create headers for email parser
                headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
                headers['content-type'] = request.headers.get('content-type', '')
                
                # Parse using email parser
                header_bytes = b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n'
                msg = BytesParser(policy=default).parsebytes(header_bytes + body)
                
                forms = {}
                files = {}
                
                # Extract form data and files
                for part in msg.iter_parts():
                    if not part.is_multipart():
                        content_disposition = part.get('Content-Disposition', '')
                        if content_disposition:
                            disposition_params = {}
                            for param in content_disposition.split(';'):
                                param = param.strip()
                                if '=' in param:
                                    key, value = param.split('=', 1)
                                    disposition_params[key.strip()] = value.strip().strip('"')
                            
                            field_name = disposition_params.get('name')
                            filename = disposition_params.get('filename')
                            
                            if field_name:
                                if filename:
                                    files[field_name] = {
                                        'filename': filename,
                                        'content': part.get_payload(decode=True)
                                    }
                                else:
                                    forms[field_name] = [part.get_payload(decode=True).decode('utf-8')]
                
                logger.debug(f"Parsed forms: {forms}")
                logger.debug(f"Parsed files: {files}")
                
                new_content = content.get('header_image', {})
                
                # Handle image upload
                if 'image' in files and files['image']['content']:
                    file = files['image']
                    filename = file['filename']
                    ext = Path(filename).suffix.lower()
                    
                    if ext in ['.jpg', '.jpeg', '.png']:
                        # Create database-specific directory under data/db_id
                        db_data_dir = os.path.join(DATA_DIR, db_id)
                        os.makedirs(db_data_dir, exist_ok=True)
                        
                        # Save image as header.jpg in database directory
                        image_path = os.path.join(db_data_dir, 'header.jpg')
                        with open(image_path, 'wb') as f:
                            f.write(file['content'])
                        
                        # Update content with correct image URL
                        import time
                        timestamp = int(time.time())
                        new_content['image_url'] = f"/data/{db_id}/header.jpg?v={timestamp}"
                        logger.debug(f"Saved image to {image_path}, URL with cache busting: {new_content['image_url']}")
                
                # Update other fields from forms
                if 'alt_text' in forms:
                    new_content['alt_text'] = forms['alt_text'][0]
                if 'credit_text' in forms:
                    new_content['credit_text'] = forms['credit_text'][0]
                if 'credit_url' in forms:
                    new_content['credit_url'] = forms['credit_url'][0]
                
                # Save to database
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'header_image', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated header image for {db_name}",
                    {"db_name": db_name, "section": "header_image"}
                )
                
                return Response.redirect(f"{request.path}?success=Header image updated")
                
            except Exception as e:
                logger.error(f"Error handling image upload: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                return Response.redirect(f"{request.path}?error=Error uploading image: {str(e)}")
        else:
            # Handle text form data
            post_vars = await request.post_vars()
            
            if 'title' in post_vars:
                new_content = {"content": post_vars['title']}
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'title', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated title for {db_name}",
                    {"db_name": db_name, "section": "title"}
                )
                
                return Response.redirect(f"{request.path}?success=Title updated")
            
            if 'description' in post_vars:
                new_content = {
                    "content": post_vars['description'],
                    "paragraphs": parse_markdown_links(post_vars['description'])
                }
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'description', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated description for {db_name}",
                    {"db_name": db_name, "section": "description"}
                )
                
                return Response.redirect(f"{request.path}?success=Description updated")
            
            if 'footer' in post_vars:
                new_content = {
                    "content": post_vars['footer'],
                    "odbl_text": "Data licensed under ODbL",
                    "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                    "paragraphs": parse_markdown_links(post_vars['footer'])
                }
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'footer', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated footer for {db_name}",
                    {"db_name": db_name, "section": "footer"}
                )
                
                return Response.redirect(f"{request.path}?success=Footer updated")
    
    return Response.html(
        await datasette.render_template(
            "template.html",
            {
                "db_name": db_name,
                "db_status": db_status,
                "db": {"db_name": db_name, "status": db_status},
                "content": content,
                "actor": actor,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def serve_database_image(datasette, request):
    """Serve database-specific images with better cache handling."""
    try:
        # Extract db_id and filename from the URL path
        path_parts = request.path.strip('/').split('/')
        
        if len(path_parts) < 3 or path_parts[0] != 'data':
            logger.error(f"Invalid URL format: {request.path}")
            return Response.text("Not found", status=404)
        
        db_id = path_parts[1]
        filename = path_parts[2]
        
        # Remove cache busting parameter from filename
        if '?' in filename:
            filename = filename.split('?')[0]
        
        logger.debug(f"Serving image: db_id={db_id}, filename={filename}")
        
        # Security: only allow specific image files
        if filename not in ['header.jpg', 'header.png']:
            logger.error(f"Invalid filename requested: {filename}")
            return Response.text("Not found", status=404)
        
        # Check if the database exists and user has access
        query_db = datasette.get_database('portal')
        db_result = await query_db.execute("SELECT status FROM databases WHERE db_id = ?", [db_id])
        db_info = db_result.first()
        
        if not db_info:
            logger.error(f"Database not found for db_id: {db_id}")
            return Response.text("Not found", status=404)
        
        # For published databases, allow public access
        # For draft databases, check ownership
        if db_info['status'] != 'Published':
            actor = get_actor_from_request(request)
            if not actor:
                return Response.text("Not found", status=404)
            
            owner_result = await query_db.execute(
                "SELECT user_id FROM databases WHERE db_id = ? AND user_id = ?", 
                [db_id, actor.get('id')]
            )
            if not owner_result.first():
                return Response.text("Not found", status=404)
        
        # Serve the file
        file_path = os.path.join(DATA_DIR, db_id, filename)
        logger.debug(f"Looking for file at: {file_path}")
        
        if os.path.exists(file_path):
            # Get file modification time for caching
            import time
            file_mtime = os.path.getmtime(file_path)
            etag = f'"{int(file_mtime)}"'
            
            # Check if client has current version
            if_none_match = request.headers.get('if-none-match')
            if if_none_match == etag:
                return Response('', status=304)
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            content_type = 'image/jpeg' if filename.endswith('.jpg') else 'image/png'
            logger.debug(f"Serving {len(content)} bytes as {content_type} with ETag {etag}")
            
            return Response(
                content, 
                content_type=content_type,
                headers={
                    'Cache-Control': 'public, max-age=300',  # 5 minutes instead of 1 hour
                    'ETag': etag,  # Enable proper cache validation
                    'Content-Length': str(len(content)),
                    'Last-Modified': time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(file_mtime))
                }
            )
        else:
            logger.error(f"File not found: {file_path}")
            return Response.text("Not found", status=404)
            
    except Exception as e:
        logger.error(f"Error serving image: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return Response.text("Internal server error", status=500)

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

async def verify_database_structure(query_db):
    """Verify the database has the required structure."""
    try:
        # Check if required tables exist
        required_tables = ['users', 'databases', 'admin_content', 'activity_logs']
        
        result = await query_db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row['name'] for row in result.rows]
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            logger.error(f"Missing required tables: {missing_tables}")
            return False
        
        logger.info("Database structure verified successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error verifying database structure: {e}")
        return False

async def register_user_databases(datasette, query_db):
    """Register all user databases with Datasette."""
    registered_count = 0
    failed_count = 0
    
    try:
        # Get all active databases
        result = await query_db.execute(
            "SELECT db_name, file_path, status FROM databases WHERE status IN ('Draft', 'Published', 'Unpublished')"
        )
        
        for row in result:
            db_name = row['db_name']
            file_path = row['file_path']
            status = row['status']
            
            try:
                if file_path and os.path.exists(file_path):
                    # Check if already registered
                    if db_name not in datasette.databases:
                        db_instance = Database(datasette, path=file_path, is_mutable=True)
                        datasette.add_database(db_instance, name=db_name)
                        registered_count += 1
                        logger.debug(f"Registered database: {db_name} ({status})")
                    else:
                        logger.debug(f"Database already registered: {db_name}")
                else:
                    logger.warning(f"Database file not found: {file_path} for {db_name}")
                    failed_count += 1
                    
            except Exception as reg_error:
                logger.error(f"Failed to register database {db_name}: {reg_error}")
                failed_count += 1
        
        logger.info(f"Database registration complete: {registered_count} registered, {failed_count} failed")
        return registered_count, failed_count
        
    except Exception as e:
        logger.error(f"Error during database registration: {e}")
        return 0, 0

async def log_startup_success(datasette, registered_count, failed_count):
    """Log successful startup."""
    try:
        startup_details = f"Registered {registered_count} databases, {failed_count} failed"
        await log_database_action(
            datasette, "system", "startup", 
            f"EDGI Cloud Portal started successfully: {startup_details}",
            {
                "registered_databases": registered_count,
                "failed_databases": failed_count,
                "startup_time": datetime.utcnow().isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Error logging startup: {e}")

@hookimpl
def register_routes():
    """Register datasette admin panel routes."""
    return [
        (r"^/manage-databases$", manage_databases),
        (r"^/create-database$", create_database),
        (r"^/db/([^/]+)/publish$", publish_database),
        (r"^/db/([^/]+)/homepage$", database_homepage),
        (r"^/db/([^/]+)/create-homepage$", create_homepage),
        (r"^/edit-content/([^/]+)$", edit_content),
        (r"^/delete-table/(?P<db_name>[^/]+)/(?P<table_name>[^/]+)$", delete_table),
        (r"^/delete-table-ajax$", delete_table_ajax),
        (r"^/data/[^/]+/[^/]+$", serve_database_image),
    ]

@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Block insecure upload plugin."""
    if action == "upload-csvs":
        return False  # Block insecure official plugin
    return None

# Cleanup task management
_cleanup_task = None

async def periodic_auto_cleanup(datasette, interval_hours=24):
    """Periodic background task that runs auto-cleanup at specified intervals."""
    global _cleanup_task
    
    logger.info(f"Starting periodic auto-cleanup (every {interval_hours} hours)")
    
    try:
        while True:
            # Wait for the specified interval
            await asyncio.sleep(interval_hours * 3600)  # Convert hours to seconds
            
            try:
                logger.info("Running scheduled auto-cleanup of expired databases")
                
                # Import the cleanup function from delete module
                from delete_db import auto_cleanup_expired_databases
                await auto_cleanup_expired_databases(datasette)
                
                logger.info("Scheduled auto-cleanup completed successfully")
                
            except Exception as cleanup_error:
                logger.error(f"Error during scheduled auto-cleanup: {cleanup_error}")
                # Continue the loop even if cleanup fails
                
    except asyncio.CancelledError:
        logger.info("Periodic auto-cleanup task cancelled")
        raise
    except Exception as e:
        logger.error(f"Periodic auto-cleanup task failed: {e}")

async def schedule_cleanup_task(datasette):
    """Start the background cleanup task if not already running."""
    global _cleanup_task
    
    # Cancel existing task if running
    if _cleanup_task and not _cleanup_task.done():
        logger.debug("Cancelling existing cleanup task")
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
    
    # Get cleanup interval from environment (default 24 hours)
    cleanup_interval = int(os.getenv('AUTO_CLEANUP_INTERVAL_HOURS', '24'))
    
    # Start new cleanup task
    _cleanup_task = asyncio.create_task(
        periodic_auto_cleanup(datasette, cleanup_interval)
    )
    
    logger.info(f"Scheduled auto-cleanup every {cleanup_interval} hours")

@hookimpl
def startup(datasette):
    """Enhanced startup hook with proper auto-cleanup scheduling"""
    
    async def inner():
        try:
            logger.info("Starting Datasette Admin Panel Module...")
            
            # Get database path
            db_path = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
            
            # Check if portal database exists
            if not os.path.exists(db_path):
                logger.error(f"Portal database not found at: {db_path}")
                logger.error("Run init_db.py first to create the database")
                return
            
            logger.info(f"Using portal database: {db_path}")
            query_db = datasette.get_database('portal')
            
            # Verify database structure
            await verify_database_structure(query_db)
            
            # Register existing user databases
            registered_count, failed_count = await register_user_databases(datasette, query_db)
            
            # Run initial cleanup check for expired databases
            logger.info("Running initial auto-cleanup check...")
            try:
                from .delete_db import auto_cleanup_expired_databases
                await auto_cleanup_expired_databases(datasette)
                logger.info("Initial auto-cleanup completed")
            except ImportError:
                logger.warning("Could not import auto_cleanup_expired_databases - skipping initial cleanup")
            except Exception as cleanup_error:
                logger.error(f"Initial auto-cleanup failed: {cleanup_error}")
            
            # Schedule recurring auto-cleanup
            await schedule_cleanup_task(datasette)
            
            # Log startup success
            await log_startup_success(datasette, registered_count, failed_count)
            
            logger.info("Datasette Admin Panel Module startup completed successfully")
            
        except Exception as e:
            logger.error(f"Datasette Admin Panel Module startup failed: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            # Don't re-raise - let Datasette continue starting

    return inner