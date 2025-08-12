import io
import json
import bcrypt
import logging
from pathlib import Path
from datetime import datetime
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

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv','.txt'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_DATABASES_PER_USER = 5
STATIC_DIR = os.getenv('EDGI_STATIC_DIR', "/static")
DATA_DIR = os.getenv('EDGI_DATA_DIR', "/data")

def sanitize_text(text):
    """Sanitize text by stripping HTML tags while preserving safe characters."""
    return bleach.clean(text, tags=[], strip=True)

def parse_markdown_links(text):
    """Parse markdown-like links [text](url) into HTML <a> tags and split into paragraphs."""
    paragraphs = [p.strip() for p in text.split('\n') if p.strip()]
    parsed_paragraphs = []
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
    for paragraph in paragraphs:
        parsed = link_pattern.sub(lambda m: f'<a href="{sanitize_text(m.group(2))}">{sanitize_text(m.group(1))}</a>', paragraph)
        parsed_paragraphs.append(parsed)
    return parsed_paragraphs

async def check_database_name_unique(datasette, db_name, exclude_db_id=None):
    """Check if database name is globally unique."""
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

async def verify_csrf_token(request, datasette):
    """Verify CSRF token for POST requests."""
    if request.method != "POST":
        return True

    # Get CSRF token from form data
    try:
        post_vars = await request.post_vars()
        submitted_token = post_vars.get("csrftoken", "")
    except:
        submitted_token = ""

    # Generate expected token using Datasette's method
    actor = get_actor_from_request(request)
    if not actor:
        return False

    # Use Datasette's CSRF token generation
    expected_token = datasette._send_signed_token(
        {"a": actor.get("id", "")},
        max_age=3600
    )

    return submitted_token == expected_token

def generate_csrf_token(datasette, actor):
    """Generate CSRF token for forms."""
    if not actor:
        return ""

    return datasette._send_signed_token(
        {"a": actor.get("id", "")},
        max_age=3600
    )

async def csrf_protect(func):
    """Decorator to add CSRF protection to views."""
    async def wrapper(datasette, request):
        # Skip CSRF for GET requests
        if request.method == "GET":
            return await func(datasette, request)

        # Verify CSRF token for POST requests
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch for {request.path}")
            return Response.html(
                "<h1>CSRF Token Invalid</h1><p>Please refresh the page and try again.</p>",
                status=403
            )

        return await func(datasette, request)
    return wrapper

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
            'content': 'Made with love by EDGI and Public Environmental Data Partners.',
            'odbl_text': 'Data licensed under ODbL',
            'odbl_url': 'https://opendatacommons.org/licenses/odbl/',
            'paragraphs': ['Made with love by EDGI and Public Environmental Data Partners.']
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
    """Get enhanced database statistics for homepage."""
    db = datasette.get_database("portal")

    try:
        # Total databases
        total_result = await db.execute("SELECT COUNT(*) FROM databases WHERE status != 'Deleted'")
        total_count = total_result.first()[0]

        # Published databases
        published_result = await db.execute("SELECT COUNT(*) FROM databases WHERE status = 'Published'")
        published_count = published_result.first()[0]

        # User-specific statistics if user_id provided
        user_stats = {}
        if user_id:
            user_result = await db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
            user_stats['user_databases'] = user_result.first()[0]

            user_published_result = await db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status = 'Published'", [user_id])
            user_stats['user_published'] = user_published_result.first()[0]

        # Featured databases for homepage
        featured_result = await db.execute(
            "SELECT db_id, db_name, website_url, status FROM databases WHERE status = 'Published' ORDER BY created_at DESC LIMIT 6"
        )
        featured_databases = [dict(row) for row in featured_result]

        return {
            'total_databases': total_count,
            'published_databases': published_count,
            'featured_databases': featured_databases,
            **user_stats
        }
    except Exception as e:
        logger.error(f"Error fetching statistics: {str(e)}")
        return {
            'total_databases': 0,
            'published_databases': 0,
            'featured_databases': [],
            'user_databases': 0,
            'user_published': 0
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
            db_content = await get_database_content(datasette, row['db_name'])

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

# Apply CSRF protection to login page
async def login_page(datasette, request):
    logger.debug(f"Login request: method={request.method}")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    actor = get_actor_from_request(request)

    if request.method == "POST":
        # CSRF protection for login
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch in login for {request.path}")
            return Response.html(
                await datasette.render_template(
                    "login.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Security token invalid. Please try again.",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

        post_vars = await request.post_vars()
        logger.debug(f"POST vars keys: {list(post_vars.keys())}")
        username = post_vars.get("username")
        password = post_vars.get("password")

        if not username or not password:
            logger.warning("Missing username or password")
            return Response.html(
                await datasette.render_template(
                    "login.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Username and password are required",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )
        try:
            db = datasette.get_database("portal")
            result = await db.execute("SELECT user_id, username, password_hash, role FROM users WHERE username = ?", [username])
            user = result.first()
            if user:
                logger.debug(f"User found: user_id={user['user_id']}, username={user['username']}, role={user['role']}")
                try:
                    if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                        logger.debug(f"Login successful for user: {username}, role: {user['role']}")
                        redirect_url = "/system-admin" if user["role"] == "system_admin" else "/manage-databases"
                        actor_data = {"id": user["user_id"], "name": f"User {username}", "role": user["role"], "username": username}

                        response = Response.redirect(redirect_url)
                        set_actor_cookie(response, datasette, actor_data)
                        request.scope["actor"] = actor_data

                        logger.debug(f"Redirecting to: {redirect_url}")
                        return response
                    else:
                        logger.warning(f"Invalid password for user: {username}")
                        return Response.html(
                            await datasette.render_template(
                                "login.html",
                                {
                                    "metadata": datasette.metadata(),
                                    "content": content,
                                    "error": "Invalid username or password",
                                    "csrf_token": generate_csrf_token(datasette, actor)
                                },
                                request=request
                            )
                        )
                except ValueError as ve:
                    logger.error(f"Invalid password hash for user: {username}, error: {str(ve)}")
                    return Response.html(
                        await datasette.render_template(
                            "login.html",
                            {
                                "metadata": datasette.metadata(),
                                "content": content,
                                "error": "Invalid password hash. Please contact the administrator.",
                                "csrf_token": generate_csrf_token(datasette, actor)
                            },
                            request=request
                        )
                    )
            else:
                logger.warning(f"No user found for username: {username}")
                return Response.html(
                    await datasette.render_template(
                        "login.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Invalid username or password",
                            "csrf_token": generate_csrf_token(datasette, actor)
                        },
                        request=request
                    )
                )
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "login.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": f"Login error: {str(e)}",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "login.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "csrf_token": generate_csrf_token(datasette, actor)
            },
            request=request
        )
    )

async def register_page(datasette, request):
    logger.debug(f"Register request: method={request.method}")

    actor = get_actor_from_request(request)

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    # Determine available roles based on who is accessing the page
    is_admin = actor and actor.get("role") == "system_admin"
    available_roles = ["system_user"]
    if is_admin:
        available_roles.append("system_admin")

    if request.method == "POST":
        # CSRF protection for registration
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch in registration for {request.path}")
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Security token invalid. Please try again.",
                        "csrf_token": generate_csrf_token(datasette, actor),
                        "actor": actor,
                        "is_admin": is_admin,
                        "available_roles": available_roles
                    },
                    request=request
                )
            )

        post_vars = await request.post_vars()
        logger.debug(f"Register POST vars keys: {list(post_vars.keys())}")
        username = post_vars.get("username")
        password = post_vars.get("password")
        email = post_vars.get("email")
        role = post_vars.get("role")

        if not username or not password or not email or not role:
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Username, password, email, and role are required",
                        "csrf_token": generate_csrf_token(datasette, actor),
                        "actor": actor,
                        "is_admin": is_admin,
                        "available_roles": available_roles
                    },
                    request=request
                )
            )

        # Role validation based on who is registering
        if role not in available_roles:
            error_msg = "Invalid role selected"
            if role == "system_admin" and not is_admin:
                error_msg = "Only system administrators can create admin accounts"

            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": error_msg,
                        "csrf_token": generate_csrf_token(datasette, actor),
                        "actor": actor,
                        "is_admin": is_admin,
                        "available_roles": available_roles
                    },
                    request=request
                )
            )

        try:
            db = datasette.get_database("portal")

            # Check if username already exists
            existing_user = await db.execute("SELECT username FROM users WHERE username = ?", [username])
            if existing_user.first():
                return Response.html(
                    await datasette.render_template(
                        "register.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Username already exists. Please choose a different username.",
                            "csrf_token": generate_csrf_token(datasette, actor),
                            "actor": actor,
                            "is_admin": is_admin,
                            "available_roles": available_roles
                        },
                        request=request
                    )
                )

            # Check if email already exists
            existing_email = await db.execute("SELECT email FROM users WHERE email = ?", [email])
            if existing_email.first():
                return Response.html(
                    await datasette.render_template(
                        "register.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Email already registered. Please use a different email address.",
                            "csrf_token": generate_csrf_token(datasette, actor),
                            "actor": actor,
                            "is_admin": is_admin,
                            "available_roles": available_roles
                        },
                        request=request
                    )
                )

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user_id = uuid.uuid4().hex[:20]
            logger.debug(f"Generated user_id: {user_id} for username: {username}")

            await db.execute_write(
                "INSERT INTO users (user_id, username, password_hash, role, email, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [user_id, username, hashed_password, role, email, datetime.utcnow()]
            )
            await db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [uuid.uuid4().hex[:20], user_id, "register", f"User {username} registered with role {role}", datetime.utcnow()]
            )

            # Log who created the user (if admin is creating)
            if is_admin:
                await db.execute_write(
                    "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                    [uuid.uuid4().hex[:20], actor.get("id"), "create_user", f"Admin {actor.get('username')} created user {username} with role {role}", datetime.utcnow()]
                )

            logger.debug("User registered: %s with role: %s, user_id: %s", username, role, user_id)

            # Redirect based on who created the account
            if is_admin:
                return Response.redirect("/system-admin?success=User account created successfully")
            else:
                return Response.redirect("/login?success=Registration successful")

        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": f"Registration error: {str(e)}",
                        "csrf_token": generate_csrf_token(datasette, actor),
                        "actor": actor,
                        "is_admin": is_admin,
                        "available_roles": available_roles
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "register.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "csrf_token": generate_csrf_token(datasette, actor),
                "is_admin": is_admin,
                "available_roles": available_roles
            },
            request=request
        )
    )

async def logout_page(datasette, request):
    logger.debug(f"Logout request: method={request.method}")

    response = Response.redirect("/")
    response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
    logger.debug("Cleared ds_actor cookie")
    return response

async def change_password_page(datasette, request):
    logger.debug(f"Change Password request: method={request.method}")

    actor = get_actor_from_request(request)

    if not actor:
        logger.warning(f"Unauthorized change password attempt: actor={actor}")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    if request.method == "POST":
        # CSRF protection for password change
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch in change password for {request.path}")
            return Response.html(
                await datasette.render_template(
                    "change_password.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Security token invalid. Please try again.",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

        post_vars = await request.post_vars()
        logger.debug(f"Change password POST vars keys: {list(post_vars.keys())}")
        current_password = post_vars.get("current_password")
        new_password = post_vars.get("new_password")
        confirm_password = post_vars.get("confirm_password")
        username = actor.get("username")
        if not current_password or not new_password or new_password != confirm_password:
            return Response.html(
                await datasette.render_template(
                    "change_password.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "All fields are required and new passwords must match",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

        try:
            db = datasette.get_database("portal")
            result = await db.execute("SELECT password_hash FROM users WHERE username = ?", [username])
            user = result.first()
            if user and bcrypt.checkpw(current_password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                await db.execute_write(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    [hashed_password, username]
                )
                await db.execute_write(
                    "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                    [uuid.uuid4().hex[:20], actor.get("id"), "change_password", f"User {username} changed password", datetime.utcnow()]
                )
                logger.debug("Password changed for user: %s", username)
                return Response.redirect("/manage-databases?success=Password changed successfully")
            else:
                logger.warning("Invalid current password for user: %s", username)
                return Response.html(
                    await datasette.render_template(
                        "change_password.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Invalid current password",
                            "csrf_token": generate_csrf_token(datasette, actor)
                        },
                        request=request
                    )
                )
        except Exception as e:
            logger.error(f"Password change error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "change_password.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": f"Password change error: {str(e)}",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "change_password.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "csrf_token": generate_csrf_token(datasette, actor)
            },
            request=request
        )
    )

async def manage_databases(datasette, request):
    """Enhanced manage databases with better table information."""
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

    result = await query_db.execute("SELECT db_id, db_name, status, website_url, file_path FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published')", [actor.get("id")])
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
            'upload_url': f"/upload-secure/{db_name}",  # CSRF-protected upload URL
            'has_custom_homepage': has_custom_homepage  # Indicate if custom homepage exists
        })

    return Response.html(
        await datasette.render_template(
            "manage_databases.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "user_databases": databases_with_tables,
                "success": request.args.get('success'),
                "error": request.args.get('error'),
                "csrf_token": generate_csrf_token(datasette, actor)
            },
            request=request
        )
    )

async def create_database(datasette, request):
    """Simplified database creation with CSRF protection."""
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
        # CSRF protection for database creation
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch in create database for {request.path}")
            return Response.html(
                await datasette.render_template(
                    "create_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "error": "Security token invalid. Please try again.",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

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
                        "error": "Database name is required",
                        "csrf_token": generate_csrf_token(datasette, actor)
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
                        "error": "Database name must contain only lowercase letters, numbers, and underscores",
                        "csrf_token": generate_csrf_token(datasette, actor)
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
                        "error": f"Database name '{db_name}' already exists. Please choose a different name.",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

        username = actor.get("username")
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
                        "error": f"Maximum {MAX_DATABASES_PER_USER} databases per user reached",
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

        try:
            db_id = uuid.uuid4().hex[:20]
            scheme = request.scheme
            host = get_dynamic_host(request)
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
            await query_db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [uuid.uuid4().hex[:20], user_id, "create_database", f"Created database {db_name}", datetime.utcnow()]
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
                        "error": f"Create database error: {str(e)}",
                        "csrf_token": generate_csrf_token(datasette, actor)
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
                "csrf_token": generate_csrf_token(datasette, actor)
            },
            request=request
        )
    )

async def delete_table(request, datasette):
    #Delete a table from user's database with CSRF protection
    actor = request.actor

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
        # CSRF protection for table deletion
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch in delete table for {request.path}")
            return Response.redirect(
                f"/manage-databases?error=Security token invalid. Please try again."
            )

        try:
            # Get form data to check for CSRF token
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
                        "csrf_token": generate_csrf_token(datasette, actor)
                    },
                    request=request
                )
            )

        except Exception as e:
            logger.error(f"Error accessing table information for {table_name}: {e}")
            return Response.redirect(
                f"/manage-databases?error=Error accessing table information: {str(e)}"
            )

async def delete_table_ajax(request, datasette):
    """AJAX endpoint for table deletion with CSRF protection"""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)

    actor = request.actor
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)

    try:
        # Parse JSON body
        import json
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))

        db_name = data.get('db_name')
        table_name = data.get('table_name')
        csrf_token = data.get('csrf_token')

        if not db_name or not table_name:
            return Response.json({"error": "Missing db_name or table_name"}, status=400)

        # CSRF protection for AJAX requests
        expected_token = generate_csrf_token(datasette, actor)
        if csrf_token != expected_token:
            return Response.json({"error": "CSRF token invalid"}, status=403)

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
        portal_db = datasette.get_database("portal")
        await portal_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [
                uuid.uuid4().hex[:20],
                actor["id"],
                "delete_table",
                f"Deleted table {table_name} from {db_name}",
                datetime.utcnow().isoformat()
            ]
        )

        return Response.json({
            "success": True,
            "message": f"Table '{table_name}' deleted successfully from '{db_name}'"
        })

    except Exception as e:
        logger.error(f"Error in delete_table_ajax: {e}")
        return Response.json({"error": f"Failed to delete table: {str(e)}"}, status=500)

async def system_admin_page(datasette, request):
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
                    'error': f"Error loading system admin data: {str(e)}",
                    "csrf_token": generate_csrf_token(datasette, actor)
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
                'error': request.args.get('error'),
                "csrf_token": generate_csrf_token(datasette, actor)
            },
            request=request
        )
    )

async def publish_database(datasette, request):
    """Publish database with CSRF protection."""
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

    # CSRF protection for publishing
    if request.method == "POST" and not await verify_csrf_token(request, datasette):
        logger.warning(f"CSRF token mismatch in publish database for {request.path}")
        return Response.redirect(f"/manage-databases?error=Security token invalid. Please try again.")

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

        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [uuid.uuid4().hex[:20], actor.get("id"), "publish_database", f"Published database {db_name}", datetime.utcnow()]
        )

        return Response.redirect(f"/manage-databases?success=Database '{db_name}' published successfully! It's now publicly accessible at /{db_name}/")

    except Exception as e:
        logger.error(f"Error publishing database {db_name}: {str(e)}")
        return Response.text(f"Error publishing database: {str(e)}", status=500)

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
        default_footer = 'Made with love by EDGI and Public Environmental Data Partners.'

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
    """Create/enable custom homepage for a database with CSRF protection."""
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

    # CSRF protection for homepage creation
    if request.method == "POST" and not await verify_csrf_token(request, datasette):
        logger.warning(f"CSRF token mismatch in create homepage for {request.path}")
        return Response.redirect(f"/manage-databases?error=Security token invalid. Please try again.")

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

        # Create CLEARLY customized content (not defaults)
        custom_title = f"Custom {db_name.replace('_', ' ').title()} Environmental Data Portal"
        custom_description = f"Welcome to the {db_name.replace('_', ' ').title()} environmental data portal. This database contains important environmental monitoring data and research findings. Explore our comprehensive datasets to understand environmental trends and patterns."
        custom_footer = f"Environmental data portal for {db_name.replace('_', ' ').title()} | Powered by EDGI and Public Environmental Data Partners"

        # FIXED: Set proper default header image path
        custom_content = [
            ("title", {"content": custom_title}),
            ("description", {
                "content": custom_description,
                "paragraphs": parse_markdown_links(custom_description)
            }),
            ("header_image", {
                "image_url": "/static/default_header.jpg",  # Default to static header
                "alt_text": f"{db_name.replace('_', ' ').title()} Environmental Data Portal",
                "credit_text": "Environmental Data Portal",
                "credit_url": ""
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

        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [uuid.uuid4().hex[:20], actor.get("id"), "create_homepage", f"Created custom homepage for {db_name}", datetime.utcnow()]
        )

        return Response.redirect(f"/edit-content/{db_id}?success=Custom homepage created! You can now customize your database portal.")

    except Exception as e:
        logger.error(f"Error creating homepage for {db_name}: {str(e)}")
        return Response.text(f"Error creating homepage: {str(e)}", status=500)

async def edit_content(datasette, request):
    """Enhanced content editor with proper image handling and CSRF protection."""
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
        # CSRF protection for content editing
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch in edit content for {request.path}")
            return Response.redirect(f"{request.path}?error=Security token invalid. Please try again.")

        content_type = request.headers.get('content-type', '').lower()
        if 'multipart/form-data' in content_type:
            # Handle image upload using email.parser approach (like in CAMPD project)
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
                return Response.redirect(f"{request.path}?success=Footer updated")

    return Response.html(
        await datasette.render_template(
            "template.html",
            {
                "db_name": db_name,
                "db_status": db_status,
                "db": {"db_name": db_name, "status": db_status},  # Add db object for temp
                "content": content,
                "actor": actor,
                "success": request.args.get('success'),
                "error": request.args.get('error'),
                "csrf_token": generate_csrf_token(datasette, actor)
            },
            request=request
        )
    )

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

async def diagnose_database_structure(datasette):
    """Diagnose the current database structure"""
    try:
        print("=== DATABASE STRUCTURE DIAGNOSIS ===")

        # Check available databases
        print(f"Available databases: {list(datasette.databases.keys())}")

        # Check portal.db structure
        if "portal" in datasette.databases:
            portal_db = datasette.get_database("portal")
            tables = await portal_db.table_names()
            print(f"Portal.db tables: {tables}")

            # Check users table
            if 'users' in tables:
                users_result = await portal_db.execute("SELECT COUNT(*) FROM users")
                print(f"Users count: {users_result.rows[0][0]}")

                # Show sample users
                sample_users = await portal_db.execute("SELECT user_id, username, role FROM users LIMIT 3")
                print(f"Sample users: {sample_users.rows}")

            # Check databases table
            if 'databases' in tables:
                db_result = await portal_db.execute("SELECT COUNT(*) FROM databases")
                print(f"Databases count: {db_result.rows[0][0]}")

                # Show sample databases
                sample_dbs = await portal_db.execute("SELECT db_name, user_id, status FROM databases LIMIT 5")
                print(f"Sample databases: {sample_dbs.rows}")
            else:
                print("WARNING: No 'databases' table found in portal.db")

        print("=== END DIAGNOSIS ===")

    except Exception as e:
        print(f"ERROR in diagnosis: {e}")
        import traceback
        print(f"TRACEBACK: {traceback.format_exc()}")

async def user_owns_database(datasette, user_id, db_name):
    """Check if a user owns a specific database using portal.db"""
    try:
        logger.debug(f"Checking ownership for user_id={user_id}, db_name={db_name}")

        # Use portal.db (the main database)
        portal_db = datasette.get_database("portal")
        logger.debug(f"Successfully got portal database")

        # Execute the ownership query
        result = await portal_db.execute(
            "SELECT 1 FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, user_id]
        )
        logger.debug(f"Ownership query result: {result.rows}")

        return len(result.rows) > 0

    except Exception as e:
        logger.error(f"Database ownership check failed: {e}")
        return False

@hookimpl
def register_routes():
    """Register routes including static file serving for database images."""

    return [
        # System routes
        (r"^/$", index_page),
        (r"^/login$", login_page),
        (r"^/register$", register_page),
        (r"^/logout$", logout_page),
        (r"^/change-password$", change_password_page),
        (r"^/manage-databases$", manage_databases),
        (r"^/create-database$", create_database),
        (r"^/system-admin$", system_admin_page),
        (r"^/all-databases$", all_databases_page),

        # Database management with /db/ prefix
        (r"^/edit-content/([^/]+)$", edit_content),
        (r"^/delete-table/([^/]+)/([^/]+)$", delete_table),
        (r"^/delete-table-ajax$", delete_table_ajax),
        (r"^/data/[^/]+/[^/]+$", serve_database_image),
        (r"^/db/([^/]+)/publish$", publish_database),
        (r"^/db/([^/]+)/create-homepage$", create_homepage),
        (r"^/db/([^/]+)/homepage$", database_homepage),
    ]

@hookimpl
def actor_from_request(datasette, request):
    """Convert cookie-based authentication to Datasette actor."""
    actor = get_actor_from_request(request)
    if actor:
        # Return the actor in the format Datasette expects
        return {
            "id": actor.get("id"),
            "username": actor.get("username"),
            "role": actor.get("role")
        }
    return None

@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Grant permissions and control database access."""

    # Handle CSV upload permissions
    if action == "upload-csvs":
        if actor and actor.get("id"):
            logger.debug(f"Granting upload-csvs permission to actor: {actor}")
            return True
        else:
            logger.debug(f"Denying upload-csvs permission - no actor or no actor ID: {actor}")
            return False

    # Handle database view permissions for draft databases
    if action == "view-database" and resource:
        # Allow access to portal database for everyone
        if resource == "portal":
            return True

        # For other databases, just return None to let Datasette handle it
        # Don't try to run async code here as it causes "event loop already running" errors
        return None

    # Let other plugins handle other permissions
    return None

def get_dynamic_host(request):
    """Get the dynamic host for URL generation."""
    host = request.headers.get('host')
    if not host:
        # Fallback to environment variable or localhost
        app_name = os.getenv('FLY_APP_NAME')
        if app_name:
            host = f"{app_name}.fly.dev"
        else:
            host = 'localhost:8001'
    return host

@hookimpl
def startup(datasette):
    async def run_diagnosis():
        await diagnose_database_structure(datasette)
    import asyncio
    asyncio.create_task(run_diagnosis())

    async def inner():
        ensure_data_directories()
        db_path = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
        portal_db = sqlite_utils.Database(db_path)
        query_db = datasette.get_database('portal')

        # Create tables
        portal_db.create_table("users", {
            "user_id": str,
            "username": str,
            "password_hash": str,
            "role": str,
            "email": str,
            "created_at": str
        }, pk="user_id", if_not_exists=True)

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

        portal_db.create_table("admin_content", {
            "db_id": str,
            "section": str,
            "content": str,
            "updated_at": str,
            "updated_by": str
        }, pk=("db_id", "section"), if_not_exists=True)

        portal_db.create_table("activity_logs", {
            "log_id": str,
            "user_id": str,
            "action": str,
            "details": str,
            "timestamp": str
        }, pk="log_id", if_not_exists=True)

        # Add missing columns
        try:
            # Check if column exists before adding
            result = await query_db.execute("PRAGMA table_info(databases)")
            columns = [row['name'] for row in result]

            if 'deleted_at' not in columns:
                await query_db.execute("ALTER TABLE databases ADD COLUMN deleted_at TEXT")
            if 'file_path' not in columns:
                await query_db.execute("ALTER TABLE databases ADD COLUMN file_path TEXT")
        except Exception as e:
            logger.debug(f"Column addition error (likely already exists): {e}")

        try:
            # Initialize portal-wide content
            result = await query_db.execute("SELECT COUNT(*) FROM admin_content WHERE db_id IS NULL")
            if result.first()[0] == 0:
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, "title", json.dumps({"content": "EDGI Datasette Cloud Portal"}), datetime.utcnow().isoformat(), "system"]
                )
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, "header_image", json.dumps({"image_url": "/static/default_header.jpg", "alt_text": "EDGI Portal Header", "credit_url": "", "credit_text": ""}), datetime.utcnow().isoformat(), "system"]
                )
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, "info", json.dumps({"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites."}), datetime.utcnow().isoformat(), "system"]
                )
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [None, "footer", json.dumps({"content": "Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners."]}), datetime.utcnow().isoformat(), "system"]
                )

            # Register all published databases with Datasette
            result = await query_db.execute("SELECT db_name, file_path, status FROM databases WHERE status IN ('Published', 'Draft')")
            registered_count = 0
            for row in result:
                if row['file_path'] and os.path.exists(row['file_path']):
                    try:
                        user_db = Database(datasette, path=row['file_path'], is_mutable=True)
                        datasette.add_database(user_db, name=row['db_name'])
                        registered_count += 1
                        logger.debug(f"Registered database: {row['db_name']} (status: {row['status']})")
                    except Exception as reg_error:
                        logger.error(f"Error registering database {row['db_name']}: {reg_error}")

            logger.info(f"Startup complete: Registered {registered_count} databases with Datasette")

        except Exception as e:
            logger.error(f"Error during startup initialization: {str(e)}")

    return inner
