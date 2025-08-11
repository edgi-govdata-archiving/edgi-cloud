"""
Admin Panel Module - System administration and portal management
Handles: System admin dashboard, user management, portal homepage editing
"""

import json
import bcrypt
import logging
import uuid
import os
import base64
from pathlib import Path
from datetime import datetime, timedelta
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database
import bleach
import re
from email.parser import BytesParser
from email.policy import default

# Configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

STATIC_DIR = os.getenv('EDGI_STATIC_DIR', "/static")
DATA_DIR = os.getenv('EDGI_DATA_DIR', "/data")
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

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

def ensure_data_directories():
    """Ensure required directories exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    
    # Create default header image if it doesn't exist
    default_header = os.path.join(STATIC_DIR, 'default_header.jpg')
    if not os.path.exists(default_header):
        # Create a simple colored rectangle as default
        try:
            from PIL import Image, ImageDraw
            img = Image.new('RGB', (800, 200), color='#2563eb')
            draw = ImageDraw.Draw(img)
            draw.text((400, 100), 'Environmental Data Portal', fill='white', anchor='mm')
            img.save(default_header, 'JPEG')
        except ImportError:
            # If PIL not available, create empty file
            with open(default_header, 'wb') as f:
                f.write(b'')
    logger.info(f"Ensured data directories exist: {DATA_DIR}, {STATIC_DIR}")

async def log_admin_activity(datasette, user_id, action, details, metadata=None):
    """Enhanced logging with metadata support for admin actions."""
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
        logger.error(f"Error logging admin action: {e}")

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

async def index_page(datasette, request):
    """Enhanced index page with improved statistics and user database info."""
    logger.debug(f"Index request: {request.method}")

    db = datasette.get_database("portal")

    async def get_section(section_name):
        result = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", [section_name])
        row = result.first()
        if row:
            try:
                content = json.loads(row["content"])
                if section_name == "info" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                if section_name == "footer" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                return content
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for section {section_name}: {str(e)}")
                return {}
        else:
            logger.debug(f"No content found for section {section_name} with db_id IS NULL")
            return {}

    # Get base content
    content = {}
    content['header_image'] = await get_section("header_image") or {
        'image_url': '/static/default_header.jpg', 
        'alt_text': 'EDGI Portal Header', 
        'credit_url': '', 
        'credit_text': ''
    }
    content['info'] = await get_section("info") or {
        'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.',
        'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')
    }
    content['title'] = await get_section("title") or {'content': 'EDGI Datasette Cloud Portal'}
    content['footer'] = await get_section("footer") or {
        'content': 'Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.', 
        'odbl_text': 'Data licensed under ODbL', 
        'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 
        'paragraphs': ['Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.']
    }

    # Get actor and check authentication
    actor = get_actor_from_request(request)
    user_databases = []
    
    if actor:
        try:
            # Verify user exists and session is valid
            result = await db.execute("SELECT user_id, role, username, email FROM users WHERE user_id = ?", [actor.get("id")])
            user = result.first()
            if not user:
                logger.error(f"No user found for user_id: {actor.get('id')}")
                response = Response.redirect("/login?error=User not found")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response
            if user["role"] != actor.get("role"):
                logger.warning(f"Role mismatch for user_id={actor.get('id')}: db_role={user['role']}, cookie_role={actor.get('role')}")
                response = Response.redirect("/login?error=Session invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response
            
            # Redirect authenticated users to their dashboard
            redirect_url = "/system-admin" if actor.get("role") == "system_admin" else "/manage-databases"
            logger.debug(f"Authenticated user, redirecting to: {redirect_url}, actor: {actor}")
            return Response.redirect(redirect_url)
            
        except Exception as e:
            logger.error(f"Error verifying user in index_page: {str(e)}")
            response = Response.redirect("/login?error=Authentication error")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response

    # Get enhanced statistics for public homepage
    stats = await get_database_statistics(datasette)
    
    # Format featured databases as cards (limit to 6)
    feature_cards = []
    for db in stats['featured_databases'][:6]:  # Only show first 6
        feature_cards.append({
            'title': db['db_name'].replace('_', ' ').title(),
            'description': f"{db['status']} environmental dataset",
            'url': db['website_url'],
            'icon': 'ri-database-line'
        })
    
    # Statistics for the cards section - Link to all databases page
    statistics_data = [
        {
            "label": "Total Databases",
            "value": stats['total_databases'],
            "url": "/all-databases"  # Link to custom all databases page
        },
        {
            "label": "Published Datasets",
            "value": stats['published_databases'],
            "url": "/all-databases"  # Link to custom all databases page
        },
        {
            "label": "Active Users",
            "value": "Join Today",
            "url": "/register"  # Keep this as register
        }
    ]

    logger.debug(f"Rendering public index with statistics: {stats}")

    return Response.html(
        await datasette.render_template(
            "index.html",
            {
                "page_title": content['title'].get('content', "EDGI Datasette Cloud Portal") + " | EDGI",
                "header_image": content['header_image'],
                "info": content['info'],
                "feature_cards": feature_cards,
                "total_published": stats['published_databases'],  # Add total count for template
                "statistics": statistics_data,
                "content": content,
                "actor": actor,
                "user_databases": user_databases,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def all_databases_page(datasette, request):
    """Show all published databases - custom page."""
    logger.debug(f"All Databases request: method={request.method}")

    db = datasette.get_database("portal")

    async def get_section(section_name):
        result = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", [section_name])
        row = result.first()
        if row:
            try:
                content = json.loads(row["content"])
                if section_name == "info" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                if section_name == "footer" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                return content
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for section {section_name}: {str(e)}")
                return {}
        else:
            return {}

    # Get base content
    content = {}
    content['header_image'] = await get_section("header_image") or {
        'image_url': '/static/default_header.jpg', 
        'alt_text': 'EDGI Portal Header', 
        'credit_url': '', 
        'credit_text': ''
    }
    content['title'] = await get_section("title") or {'content': 'EDGI Datasette Cloud Portal'}
    content['footer'] = await get_section("footer") or {
        'content': 'Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.', 
        'odbl_text': 'Data licensed under ODbL', 
        'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 
        'paragraphs': ['Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.']
    }

    actor = get_actor_from_request(request)

    try:
        # Get all published databases
        all_dbs_result = await db.execute(
            """SELECT d.db_id, d.db_name, d.website_url, d.created_at, u.username
               FROM databases d 
               JOIN users u ON d.user_id = u.user_id 
               WHERE d.status = 'Published' 
               ORDER BY d.created_at DESC"""
        )
        
        all_databases = []
        for row in all_dbs_result:
            # Get database content for custom titles/descriptions
            try:
                # Import from datasette_admin_panel module  
                from datasette_admin_panel import get_database_content
                db_content = await get_database_content(datasette, row['db_name'])
            except ImportError:
                # Fallback if datasette_admin_panel not available
                db_content = {}
            
            # Get table count and record count for each database
            table_count = 0
            total_records = 0
            try:
                user_db = datasette.get_database(row['db_name'])
                if user_db:
                    table_names_result = await user_db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    table_names = [t['name'] for t in table_names_result.rows]
                    table_count = len(table_names)
                    
                    for table_name in table_names:
                        try:
                            count_result = await user_db.execute(f"SELECT COUNT(*) as count FROM [{table_name}]")
                            record_count = count_result.first()['count'] if count_result.first() else 0
                            total_records += record_count
                        except Exception:
                            continue
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
        
        return Response.html(
            await datasette.render_template(
                "all_databases.html",
                {
                    "page_title": "All Environmental Datasets | EDGI",
                    "content": content,
                    "databases": all_databases,
                    "total_count": len(all_databases),
                    "actor": actor,
                    "success": request.args.get('success'),
                    "error": request.args.get('error')
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error in all_databases_page: {str(e)}")
        return Response.html(
            await datasette.render_template(
                "all_databases.html",
                {
                    "page_title": "All Environmental Datasets | EDGI",
                    "content": content,
                    "databases": [],
                    "total_count": 0,
                    "actor": actor,
                    "error": f"Error loading databases: {str(e)}"
                },
                request=request
            )
        )

async def system_admin_page(datasette, request):
    """System administration page - admin users only."""
    logger.debug(f"System Admin request: method={request.method}")

    actor = get_actor_from_request(request)

    if not actor:
        logger.warning(f"Unauthorized system admin access attempt: actor=None")
        response = Response.redirect("/login?error=Session expired or invalid")
        response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
        return response

    db = datasette.get_database('portal')
    try:
        result = await db.execute("SELECT user_id, role FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
        if user["role"] != "system_admin":
            logger.warning(f"Invalid role for user_id={actor.get('id')}: role={user['role']}")
            response = Response.redirect("/login?error=Unauthorized access")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
    except Exception as e:
        logger.error(f"Error verifying user in system_admin_page: {str(e)}")
        response = Response.redirect("/login?error=Authentication error")
        response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
        return response

    title = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    try:
        users = await db.execute("SELECT user_id, username, email, role, created_at FROM users")
        users_list = [dict(row) for row in users]
        databases = await db.execute("SELECT d.db_id, d.db_name, d.website_url, d.status, d.created_at, u.username FROM databases d JOIN users u ON d.user_id = u.user_id WHERE d.status != 'Deleted'")
        databases_list = [dict(row) for row in databases]
        logs = await db.execute("SELECT log_id, user_id, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC LIMIT 100")
        logs_list = [dict(row) for row in logs]
    except Exception as e:
        logger.error(f"System admin query error: {str(e)}")
        return Response.html(
            await datasette.render_template(
                'system_admin.html',
                {
                    'content': content,
                    'metadata': datasette.metadata(),
                    'actor': actor,
                    'users': [],
                    'databases': [],
                    'activity_logs': [],
                    'error': f"Error loading system admin data: {str(e)}"
                },
                request=request
            )
        )

    return Response.html(
        await datasette.render_template(
            'system_admin.html',
            {
                'content': content,
                'metadata': datasette.metadata(),
                'actor': actor,
                'users': users_list,
                'databases': databases_list,
                'activity_logs': logs_list,
                'success': request.args.get('success'),
                'error': request.args.get('error')
            },
            request=request
        )
    )

async def edit_user_role(datasette, request):
    """Admin function to edit user roles."""
    logger.debug(f"Edit User Role request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.redirect("/login?error=Admin access required")

    if request.method == "POST":
        post_vars = await request.post_vars()
        user_id = post_vars.get("user_id")
        new_role = post_vars.get("role")
        
        if not user_id or not new_role:
            return Response.redirect("/system-admin?error=Missing user ID or role")
        
        if new_role not in ["system_user", "system_admin"]:
            return Response.redirect("/system-admin?error=Invalid role")
        
        try:
            db = datasette.get_database("portal")
            
            # Get user details
            user_result = await db.execute("SELECT username, role FROM users WHERE user_id = ?", [user_id])
            user = user_result.first()
            if not user:
                return Response.redirect("/system-admin?error=User not found")
            
            # Prevent admin from changing their own role
            if user_id == actor.get("id"):
                return Response.redirect("/system-admin?error=Cannot change your own role")
            
            # Update user role
            await db.execute_write(
                "UPDATE users SET role = ? WHERE user_id = ?",
                [new_role, user_id]
            )
            
            await log_admin_activity(
                datasette, actor.get("id"), "edit_user_role",
                f"Changed role of user {user['username']} from {user['role']} to {new_role}",
                {"target_user_id": user_id, "old_role": user['role'], "new_role": new_role}
            )
            
            return Response.redirect(f"/system-admin?success=Successfully changed {user['username']}'s role to {new_role.replace('_', ' ').title()}")
            
        except Exception as e:
            logger.error(f"Error updating user role: {str(e)}")
            return Response.redirect(f"/system-admin?error=Failed to update user role: {str(e)}")
    
    return Response.redirect("/system-admin")

async def delete_user(datasette, request):
    """Admin function to delete users."""
    logger.debug(f"Delete User request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.redirect("/login?error=Admin access required")

    if request.method == "POST":
        post_vars = await request.post_vars()
        user_id = post_vars.get("user_id")
        
        if not user_id:
            return Response.redirect("/system-admin?error=Missing user ID")
        
        try:
            db = datasette.get_database("portal")
            
            # Get user details
            user_result = await db.execute("SELECT username FROM users WHERE user_id = ?", [user_id])
            user = user_result.first()
            if not user:
                return Response.redirect("/system-admin?error=User not found")
            
            # Prevent admin from deleting themselves
            if user_id == actor.get("id"):
                return Response.redirect("/system-admin?error=Cannot delete your own account")
            
            # Check if user has databases
            db_result = await db.execute("SELECT COUNT(*) as count FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
            db_count = db_result.first()['count']
            
            if db_count > 0:
                return Response.redirect(f"/system-admin?error=Cannot delete user {user['username']} - they have {db_count} active databases")
            
            # Delete user
            await db.execute_write("DELETE FROM users WHERE user_id = ?", [user_id])
            
            await log_admin_activity(
                datasette, actor.get("id"), "delete_user",
                f"Deleted user {user['username']}",
                {"deleted_user_id": user_id, "deleted_username": user['username']}
            )
            
            return Response.redirect(f"/system-admin?success=Successfully deleted user {user['username']}")
            
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            return Response.redirect(f"/system-admin?error=Failed to delete user: {str(e)}")
    
    return Response.redirect("/system-admin")

async def edit_portal_homepage(datasette, request):
    """Edit portal homepage content - System Admin only."""
    logger.debug(f"Edit Portal Homepage request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        logger.warning(f"Unauthorized portal edit attempt: actor={actor}")
        return Response.redirect("/login?error=System admin access required")

    query_db = datasette.get_database('portal')
    
    # Verify admin role in database
    try:
        result = await query_db.execute("SELECT role FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user or user["role"] != "system_admin":
            logger.warning(f"Invalid role for portal edit: user_id={actor.get('id')}")
            return Response.redirect("/login?error=Unauthorized access")
    except Exception as e:
        logger.error(f"Error verifying admin role: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    # Get current portal content
    async def get_portal_section(section_name):
        result = await query_db.execute(
            "SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", 
            [section_name]
        )
        row = result.first()
        if row:
            try:
                content = json.loads(row["content"])
                if section_name in ["info", "footer"] and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                return content
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for portal section {section_name}: {str(e)}")
                return {}
        return {}

    content = {}
    content['title'] = await get_portal_section("title") or {'content': 'EDGI Datasette Cloud Portal'}
    content['header_image'] = await get_portal_section("header_image") or {
        'image_url': '/static/default_header.jpg', 
        'alt_text': 'EDGI Portal Header', 
        'credit_url': '', 
        'credit_text': ''
    }
    content['info'] = await get_portal_section("info") or {
        'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.',
        'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')
    }
    content['footer'] = await get_portal_section("footer") or {
        'content': 'Made with \u2764\ufe0f by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/).',
        'paragraphs': parse_markdown_links('Made with \u2764\ufe0f by [EDGI](https://envirodatagov.org) and [Public Environmental Data Partners](https://screening-tools.com/).')
    }

    if request.method == "POST":
        content_type = request.headers.get('content-type', '').lower()
        
        if 'multipart/form-data' in content_type:
            # Handle image upload (similar to database header image upload)
            try:
                body = await request.post_body()
                
                if len(body) > MAX_FILE_SIZE:
                    return Response.redirect(f"{request.path}?error=File too large")
                
                # Parse multipart form data (reuse the email parser approach)
                boundary = None
                if 'boundary=' in content_type:
                    boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
                
                if not boundary:
                    logger.error("No boundary found in Content-Type header")
                    return Response.redirect(f"{request.path}?error=Invalid form data")
                
                headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
                headers['content-type'] = request.headers.get('content-type', '')
                
                header_bytes = b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n'
                msg = BytesParser(policy=default).parsebytes(header_bytes + body)
                
                forms = {}
                files = {}
                
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
                
                new_content = content.get('header_image', {})
                
                # Handle image upload for portal
                if 'image' in files and files['image']['content']:
                    file = files['image']
                    filename = file['filename']
                    ext = Path(filename).suffix.lower()
                    
                    if ext in ['.jpg', '.jpeg', '.png']:
                        # Save portal header image in static directory
                        portal_header_path = os.path.join(STATIC_DIR, 'portal_header.jpg')
                        with open(portal_header_path, 'wb') as f:
                            f.write(file['content'])
                        
                        # Update content with timestamp for cache busting
                        import time
                        timestamp = int(time.time())
                        new_content['image_url'] = f"/static/portal_header.jpg?v={timestamp}"
                        logger.debug(f"Saved portal header to {portal_header_path}")
                
                # Update other fields
                if 'alt_text' in forms:
                    new_content['alt_text'] = forms['alt_text'][0]
                if 'credit_text' in forms:
                    new_content['credit_text'] = forms['credit_text'][0]
                if 'credit_url' in forms:
                    new_content['credit_url'] = forms['credit_url'][0]
                
                # Save to database - Handle NULL db_id properly
                # First delete existing record for this section with NULL db_id
                await query_db.execute_write(
                    "DELETE FROM admin_content WHERE db_id IS NULL AND section = ?",
                    ['header_image']
                )
                # Then insert new record
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, 'header_image', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_admin_activity(
                    datasette, actor.get("id"), "edit_portal_homepage", 
                    f"Updated portal header image"
                )
                
                return Response.redirect(f"{request.path}?success=Portal header image updated")
                
            except Exception as e:
                logger.error(f"Error handling portal image upload: {e}")
                return Response.redirect(f"{request.path}?error=Error uploading image: {str(e)}")
        else:
            # Handle text form data
            post_vars = await request.post_vars()
            
            if 'title' in post_vars:
                new_content = {"content": post_vars['title']}
                # Handle NULL db_id properly for title
                await query_db.execute_write(
                    "DELETE FROM admin_content WHERE db_id IS NULL AND section = ?",
                    ['title']
                )
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, 'title', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_admin_activity(
                    datasette, actor.get("id"), "edit_portal_homepage", 
                    f"Updated portal title"
                )
                
                return Response.redirect(f"{request.path}?success=Portal title updated")
            
            if 'description' in post_vars:
                new_content = {
                    "content": post_vars['description'],
                    "paragraphs": parse_markdown_links(post_vars['description'])
                }
                # Handle NULL db_id properly for info
                await query_db.execute_write(
                    "DELETE FROM admin_content WHERE db_id IS NULL AND section = ?",
                    ['info']
                )
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, 'info', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_admin_activity(
                    datasette, actor.get("id"), "edit_portal_homepage", 
                    f"Updated portal description"
                )
                
                return Response.redirect(f"{request.path}?success=Portal description updated")
            
            if 'footer' in post_vars:
                new_content = {
                    "content": post_vars['footer'],
                    "odbl_text": "Data licensed under ODbL",
                    "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                    "paragraphs": parse_markdown_links(post_vars['footer'])
                }
                # Handle NULL db_id properly for footer
                await query_db.execute_write(
                    "DELETE FROM admin_content WHERE db_id IS NULL AND section = ?",
                    ['footer']
                )
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, 'footer', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_admin_activity(
                    datasette, actor.get("id"), "edit_portal_homepage", 
                    f"Updated portal footer"
                )
                
                return Response.redirect(f"{request.path}?success=Portal footer updated")
    
    return Response.html(
        await datasette.render_template(
            "portal_homepage_editor.html",
            {
                "content": content,
                "actor": actor,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

@hookimpl
def register_routes():
    """Register admin panel routes."""
    return [
        (r"^/$", index_page),
        (r"^/all-databases$", all_databases_page),
        (r"^/system-admin$", system_admin_page),
        (r"^/edit-user-role$", edit_user_role),
        (r"^/delete-user$", delete_user),
        (r"^/edit-portal-homepage$", edit_portal_homepage),
    ]

@hookimpl
def startup(datasette):
    """Admin Panel module startup."""
    
    async def inner():
        try:
            logger.info("Starting Admin Panel Module...")
            
            # Ensure directories exist
            ensure_data_directories()
            
            # Get database path
            db_path = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
            
            # Check if portal database exists
            if not os.path.exists(db_path):
                logger.error(f"Portal database not found at: {db_path}")
                logger.error("Run init_db.py first to create the database")
                return
            
            logger.info(f"Using portal database: {db_path}")
            
            logger.info("Admin Panel Module startup completed successfully")
            
        except Exception as e:
            logger.error(f"Admin Panel Module startup failed: {str(e)}")

    return inner