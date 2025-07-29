import io
import json
import bcrypt
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
import bleach
import re
import sqlite_utils
import uuid
import pandas as pd
import os
import base64
from multipart import parse_form_data

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_DATABASES_PER_USER = 5
MAX_TABLES_PER_DATABASE = 10
STATIC_DIR = "C:/MS Data Science - WMU/EDGI/edgi-cloud/static"

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

def generate_unique_db_name(base_name, existing_names):
    """Generate a unique database name by appending numbers if needed."""
    if base_name not in existing_names:
        return base_name
    
    counter = 1
    while f"{base_name}_{counter}" in existing_names:
        counter += 1
    return f"{base_name}_{counter}"

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

async def get_database_content(datasette, db_name):
    """Get homepage content for a database using unified admin_content table."""
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
        content['header_image'] = {
            'image_url': '/static/default_header.jpg',
            'alt_text': 'Environmental Data',
            'credit_text': 'Environmental Data Portal',
            'credit_url': ''
        }
    
    if 'footer' not in content:
        content['footer'] = {
            'content': 'Made with EDGI',
            'odbl_text': 'Data licensed under ODbL',
            'odbl_url': 'https://opendatacommons.org/licenses/odbl/',
            'paragraphs': ['Made with EDGI']
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

async def get_database_tables(datasette, db_name):
    """Get list of tables for a database."""
    db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
    portal_db = sqlite_utils.Database(db_path)
    
    tables = []
    prefix = f"{db_name}_"
    
    for table_name in portal_db.table_names():
        if table_name.startswith(prefix):
            display_name = table_name[len(prefix):]
            table_info = portal_db[table_name]
            
            tables.append({
                'name': display_name,
                'full_name': table_name,
                'url': f"/{db_name}/{display_name}",
                'count': table_info.count,
                'columns': list(table_info.columns_dict.keys())[:5],
                'description': f"Data table with {table_info.count} records"
            })
    
    return tables

async def index_page(datasette, request):
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

    content = {}
    content['header_image'] = await get_section("header_image") or {'image_url': '/static/default_header.jpg', 'alt_text': '', 'credit_url': '', 'credit_text': ''}
    content['info'] = await get_section("info") or {'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.', 'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')}
    content['title'] = await get_section("title") or {'content': 'EDGI Datasette Cloud Portal'}
    content['footer'] = await get_section("footer") or {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': ['Made with EDGI']}

    try:
        result = await db.execute("SELECT db_id, db_name, website_url, status FROM databases WHERE status = 'Published' ORDER BY created_at DESC LIMIT 6")
        content['feature_cards'] = [
            {
                'db_id': row['db_id'],
                'db_name': row['db_name'],
                'website_url': row['website_url'],
                'status': row['status']
            } for row in result
        ]
    except Exception as e:
        logger.error(f"Error fetching user databases for feature_cards: {str(e)}")
        content['feature_cards'] = []

    actor = get_actor_from_request(request)
    user_databases = []
    if actor:
        try:
            result = await db.execute("SELECT db_id, db_name, website_url, status FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published')", [actor.get("id")])
            user_databases = [dict(row) for row in result]
        except Exception as e:
            logger.error(f"Error fetching user databases: {str(e)}")

    statistics_data = []
    try:
        total_result = await db.execute("SELECT COUNT(*) FROM databases WHERE status != 'Deleted'")
        total_count = total_result.first()[0]
        published_result = await db.execute("SELECT COUNT(*) FROM databases WHERE status = 'Published'")
        published_count = published_result.first()[0]
        statistics_data = [
            {"label": "Total User Databases", "value": total_count, "url": "/databases"},
            {"label": "Published Databases", "value": published_count, "url": "/databases?status=Published"}
        ]
    except Exception as e:
        logger.error(f"Error fetching statistics: {str(e)}")
        statistics_data = [
            {"label": "Total User Databases", "value": "Error", "url": ""},
            {"label": "Published Databases", "value": "Error", "url": ""}
        ]

    if actor:
        try:
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
            redirect_url = "/system-admin" if actor.get("role") == "system_admin" else "/manage-databases"
            logger.debug(f"Authenticated user, redirecting to: {redirect_url}, actor: {actor}")
            return Response.redirect(redirect_url)
        except Exception as e:
            logger.error(f"Error verifying user in index_page: {str(e)}")
            response = Response.redirect("/login?error=Authentication error")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response

    logger.debug(f"Rendering index with data: content={content}, statistics_data={statistics_data}")

    return Response.html(
        await datasette.render_template(
            "index.html",
            {
                "page_title": content['title'].get('content', "EDGI Datasette Cloud Portal") + " | EDGI",
                "header_image": content['header_image'],
                "info": content['info'],
                "feature_cards": content['feature_cards'],
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

async def login_page(datasette, request):
    logger.debug(f"Login request: method={request.method}")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    if request.method == "POST":
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
                        "error": "Username and password are required"
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
                                    "error": "Invalid username or password"
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
                                "error": "Invalid password hash. Please contact the administrator."
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
                            "error": "Invalid username or password"
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
                        "error": f"Login error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "login.html",
            {
                "metadata": datasette.metadata(),
                "content": content
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

    if request.method == "POST":
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
                        "error": "Username, password, email, and role are required"
                    },
                    request=request
                )
            )
        try:
            db = datasette.get_database("portal")
            if role not in ["system_admin", "system_user"]:
                return Response.html(
                    await datasette.render_template(
                        "register.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Invalid role"
                        },
                        request=request
                    )
                )
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user_id = str(uuid.uuid4())
            logger.debug(f"Generated user_id: {user_id} for username: {username}")
            await db.execute_write(
                "INSERT INTO users (user_id, username, password_hash, role, email, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [user_id, username, hashed_password, role, email, datetime.utcnow()]
            )
            await db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), user_id, "register", f"User {username} registered", datetime.utcnow()]
            )
            logger.debug("User registered: %s with role: %s, user_id: %s", username, role, user_id)
            return Response.redirect("/login?success=Registration successful")
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": f"Registration error: {str(e)}"
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
                "actor": actor
            },
            request=request
        )
    )

async def logout_page(datasette, request):
    logger.debug(f"Logout request: method={request.method}")
    
    response = Response.redirect("/login")
    response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
    logger.debug("Cleared ds_actor cookie")
    return response

async def change_password_page(datasette, request):
    logger.debug(f"Change Password request: {request.method}")

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
                        "error": "All fields are required and new passwords must match"
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
                    [str(uuid.uuid4()), actor.get("id"), "change_password", f"User {username} changed password", datetime.utcnow()]
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
                            "error": "Invalid current password"
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
                        "error": f"Password change error: {str(e)}"
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
                "actor": actor
            },
            request=request
        )
    )

async def manage_databases(datasette, request):
    logger.debug(f"Manage Databases request: method={request.method}")

    actor = get_actor_from_request(request)

    if not actor:
        logger.warning(f"Unauthorized manage databases attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    query_db = datasette.get_database('portal')
    db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
    portal_db = sqlite_utils.Database(db_path)
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

    result = await query_db.execute("SELECT db_id, db_name, status, website_url FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published')", [actor.get("id")])
    user_databases = [dict(row) for row in result]
    
    title = await query_db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'},
        'footer': {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': ['Made with EDGI']}
    }

    databases_with_tables = []
    for db_info in user_databases:
        db_name = db_info["db_name"]
        total_size = 0
        tables = []
        try:
            prefix = f"{db_name}_"
            for name in portal_db.table_names():
                if name.startswith(prefix):
                    table_size = portal_db[name].count * 0.001
                    total_size += table_size
                    display_name = name[len(prefix):]
                    tables.append({
                        'name': display_name, 
                        'full_name': name, 
                        'preview': f"/{db_name}/{display_name}", 
                        'size': table_size, 
                        'md5': 'md5-placeholder', 
                        'progress': 100
                    })
        except Exception as e:
            logger.error(f"Error loading tables for database {db_name}: {str(e)}")
            
        databases_with_tables.append({
            **db_info,
            'tables': tables,
            'total_size': total_size,
            'website_url': f"/{db_name}/"
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
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def create_database(datasette, request):
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
        content_type = request.headers.get('content-type', '').lower()
        db_name = None
        table_name = None
        csv_file = None
        
        if 'multipart/form-data' in content_type:
            boundary = content_type.split('boundary=')[1]
            body = await request.body()
            if len(body) > MAX_FILE_SIZE:
                return Response.text("File too large", status=400)
            form_data = parse_form_data(body, boundary=boundary.encode())
            
            db_name = form_data.get('db_name').value if 'db_name' in form_data else None
            table_name = form_data.get('table_name').value if 'table_name' in form_data else None
            csv_file = form_data.get('csv_file') if 'csv_file' in form_data else None
        else:
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

        username = actor.get("username")
        user_id = actor.get("id")
        
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
            db_id = str(uuid.uuid4())
            scheme = request.scheme
            host = request.headers.get('host', 'localhost:8001')
            website_url = f"{scheme}://{host}/{db_name}/"
            
            await query_db.execute_write(
                "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [db_id, user_id, db_name, website_url, "Draft", datetime.utcnow()]
            )
            
            default_content = [
                ("title", {"content": db_name}),
                ("description", {"content": "Environmental data dashboard powered by Datasette."}),
                ("header_image", {
                    "image_url": f"/static/{db_id}_header.jpg",
                    "alt_text": "Environmental Data",
                    "credit_text": "Environmental Data Portal",
                    "credit_url": ""
                }),
                ("footer", {
                    "content": "Made with EDGI",
                    "odbl_text": "Data licensed under ODbL",
                    "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                    "paragraphs": ["Made with EDGI"]
                })
            ]
            
            # Copy default_header.jpg to db-specific header
            default_header_path = os.path.join(STATIC_DIR, "default_header.jpg")
            db_header_path = os.path.join(STATIC_DIR, f"{db_id}_header.jpg")
            if os.path.exists(default_header_path):
                with open(default_header_path, 'rb') as src, open(db_header_path, 'wb') as dst:
                    dst.write(src.read())
            
            for section, content_data in default_content:
                await query_db.execute_write(
                    "INSERT INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, section, json.dumps(content_data), datetime.utcnow().isoformat(), username]
                )

            if table_name and csv_file and csv_file.filename.endswith('.csv'):
                db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
                portal_db = sqlite_utils.Database(db_path)
                full_table_name = f"{db_name}_{table_name}"
                
                if full_table_name in portal_db.table_names():
                    await query_db.execute_write(
                        "DELETE FROM databases WHERE db_id = ?",
                        [db_id]
                    )
                    return Response.html(
                        await datasette.render_template(
                            "create_database.html",
                            {
                                "metadata": datasette.metadata(),
                                "content": content,
                                "actor": actor,
                                "error": f"Table {table_name} already exists"
                            },
                            request=request
                        )
                    )
                
                df = pd.read_csv(io.BytesIO(csv_file.value))
                portal_db[full_table_name].insert_all(df.to_dict('records'), replace=True)
                
                await query_db.execute_write(
                    "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                    [str(uuid.uuid4()), user_id, "upload_csv", f"Uploaded CSV to table {table_name} in {db_name}", datetime.utcnow()]
                )

            await query_db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), user_id, "create_database", f"Created database {db_name}", datetime.utcnow()]
            )
            
            logger.debug(f"Database created: {db_name}, website_url={website_url}")
            return Response.redirect(f"/manage-databases?success=Database '{db_name}' created successfully. You can now add tables to it.")
            
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
                "actor": actor
            },
            request=request
        )
    )

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

async def publish_database(datasette, request):
    logger.debug(f"Publish Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized publish database attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    path_parts = request.path.strip('/').split('/')
    db_name = path_parts[0]
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        await query_db.execute_write(
            "UPDATE databases SET status = 'Published' WHERE db_name = ?",
            [db_name]
        )
        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [str(uuid.uuid4()), actor.get("id"), "publish_database", f"Published database {db_name}", datetime.utcnow()]
        )
        
        return Response.redirect(f"/manage-databases?success=Database '{db_name}' published successfully")
    except Exception as e:
        logger.error(f"Error publishing database {db_name}: {str(e)}")
        return Response.text(f"Error publishing database: {str(e)}", status=500)

async def database_homepage(datasette, request):
    logger.debug(f"Database homepage request: method={request.method}, path={request.path}")

    path_parts = request.path.strip('/').split('/')
    if not path_parts or not path_parts[0]:
        return Response.text("Not found", status=404)
    
    db_name = path_parts[0]
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, db_name, status, user_id FROM databases WHERE db_name = ?",
            [db_name]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        if db_info['status'] != 'Published' and (not actor or actor['id'] != db_info['user_id']):
            return Response.text("Database not found or not published", status=404)
    except Exception as e:
        logger.error(f"Error checking database {db_name}: {e}")
        return Response.text("Database error", status=500)
    
    try:
        content = await get_database_content(datasette, db_name)
        tables = await get_database_tables(datasette, db_name)
        
        if content['title']['content'] == db_name and content['description']['content'] == 'Environmental data dashboard powered by Datasette.':
            return Response.html(
                await datasette.render_template(
                    "database.html",
                    {
                        "database": db_name,
                        "tables": tables,
                        "metadata": datasette.metadata(db_name)
                    },
                    request=request
                )
            )
        
        feature_cards = [
            {
                'title': table['name'].replace('_', ' ').title(),
                'description': table['description'],
                'url': table['url'],
                'icon': 'ri-table-line'
            } for table in tables[:6]
        ]
        
        statistics = [
            {
                'label': 'Data Tables',
                'value': len(tables),
                'url': f'/{db_name}/tables'
            },
            {
                'label': 'Total Records',
                'value': sum(table['count'] for table in tables),
                'url': f'/{db_name}/tables'
            },
            {
                'label': 'Data Fields',
                'value': sum(len(table['columns']) for table in tables),
                'url': f'/{db_name}/tables'
            }
        ]
        
        return Response.html(
            await datasette.render_template(
                "database_homepage.html",
                {
                    "page_title": content['title']['content'] + " | Environmental Data",
                    "content": content,
                    "header_image": content['header_image'],
                    "info": content['info'],
                    "feature_cards": feature_cards,
                    "statistics": statistics,
                    "footer": content['footer'],
                    "db_name": db_name,
                    "tables": tables
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error rendering database homepage for {db_name}: {e}")
        return Response.text("Error loading database homepage", status=500)

async def database_tables_view(datasette, request):
    logger.debug(f"Database tables view request: method={request.method}, path={request.path}")

    path_parts = request.path.strip('/').split('/')
    if len(path_parts) < 2 or path_parts[1] != 'tables':
        return Response.text("Not found", status=404)
    
    db_name = path_parts[0]
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_name, status, user_id FROM databases WHERE db_name = ?",
            [db_name]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        if db_info['status'] != 'Published' and (not actor or actor['id'] != db_info['user_id']):
            return Response.text("Database not found or not published", status=404)
    except Exception as e:
        logger.error(f"Error checking database {db_name}: {e}")
        return Response.text("Database error", status=500)
    
    try:
        content = await get_database_content(datasette, db_name)
        tables = await get_database_tables(datasette, db_name)
        
        return Response.html(
            await datasette.render_template(
                "database_tables.html",
                {
                    "page_title": f"Tables - {content['title']['content']}",
                    "content": content,
                    "db_name": db_name,
                    "tables": tables,
                    "footer": content['footer']
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error rendering tables view for {db_name}: {e}")
        return Response.text("Error loading tables view", status=500)

async def database_table_view(datasette, request):
    logger.debug(f"Database table view request: method={request.method}, path={request.path}")

    path_parts = request.path.strip('/').split('/')
    if len(path_parts) < 2:
        return Response.text("Not found", status=404)
    
    db_name = path_parts[0]
    table_name = path_parts[1]
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_name, status, user_id FROM databases WHERE db_name = ?",
            [db_name]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        if db_info['status'] != 'Published' and (not actor or actor['id'] != db_info['user_id']):
            return Response.text("Database not found or not published", status=404)
    except Exception as e:
        logger.error(f"Error checking database {db_name}: {e}")
        return Response.text("Database error", status=500)
    
    db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
    portal_db = sqlite_utils.Database(db_path)
    full_table_name = f"{db_name}_{table_name}"
    
    if full_table_name not in portal_db.table_names():
        return Response.text("Table not found", status=404)
    
    try:
        page = int(request.args.get('_page', 1))
        page_size = int(request.args.get('_size', 100))
        offset = (page - 1) * page_size
        
        total_count = portal_db[full_table_name].count
        
        search_query = request.args.get('_search', '')
        where_clause = None
        params = []
        
        if search_query:
            columns = list(portal_db[full_table_name].columns_dict.keys())
            text_conditions = []
            for col in columns:
                text_conditions.append(f"CAST([{col}] AS TEXT) LIKE ?")
                params.append(f"%{search_query}%")
            where_clause = f"({' OR '.join(text_conditions)})"
        
        if where_clause:
            rows = list(portal_db.query(
                f"SELECT * FROM [{full_table_name}] WHERE {where_clause} LIMIT ? OFFSET ?",
                params + [page_size, offset]
            ))
            count_result = portal_db.query(
                f"SELECT COUNT(*) as count FROM [{full_table_name}] WHERE {where_clause}",
                params
            )
            total_count = list(count_result)[0]['count']
        else:
            rows = list(portal_db[full_table_name].rows_where(limit=page_size, offset=offset))
        
        columns = list(portal_db[full_table_name].columns_dict.keys())
        
        total_pages = (total_count + page_size - 1) // page_size
        has_previous = page > 1
        has_next = page < total_pages
        
        content = await get_database_content(datasette, db_name)
        
        return Response.html(
            await datasette.render_template(
                "table.html",
                {
                    "database": db_name,
                    "table": table_name,
                    "full_table_name": full_table_name,
                    "columns": columns,
                    "rows": rows,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": total_pages,
                    "has_previous": has_previous,
                    "has_next": has_next,
                    "previous_page": page - 1 if has_previous else None,
                    "next_page": page + 1 if has_next else None,
                    "search_query": search_query,
                    "metadata": datasette.metadata(db_name),
                    "content": content
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error rendering table {table_name} for database {db_name}: {str(e)}")
        return Response.text(f"Error loading table: {str(e)}", status=500)

async def edit_content(datasette, request):
    logger.debug(f"Edit Content request: method={request.method}, path={request.path}")

    path_parts = request.path.strip('/').split('/')
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
            boundary = content_type.split('boundary=')[1]
            body = await request.body()
            if len(body) > MAX_FILE_SIZE:
                return Response.text("File too large", status=400)
            form_data = parse_form_data(body, boundary=boundary.encode())
            
            new_content = content.get('header_image', {})
            
            if 'image' in form_data and form_data['image'].filename:
                filename = form_data['image'].filename
                ext = Path(filename).suffix.lower()
                if ext in ALLOWED_EXTENSIONS:
                    image_filename = f"{db_id}_header{ext}"
                    os.makedirs(STATIC_DIR, exist_ok=True)
                    with open(os.path.join(STATIC_DIR, image_filename), 'wb') as f:
                        f.write(form_data['image'].value)
                    new_content['image_url'] = f"/static/{image_filename}"
            
            if 'alt_text' in form_data:
                new_content['alt_text'] = form_data['alt_text'].value
            if 'credit_text' in form_data:
                new_content['credit_text'] = form_data['credit_text'].value
            if 'credit_url' in form_data:
                new_content['credit_url'] = form_data['credit_url'].value
            
            await query_db.execute_write(
                "UPDATE admin_content SET content = ?, updated_at = ?, updated_by = ? WHERE db_id = ? AND section = 'header_image'",
                [json.dumps(new_content), datetime.utcnow().isoformat(), actor['username'], db_id]
            )
            return Response.redirect(f"{request.path}?success=Header image updated")
        else:
            post_vars = await request.post_vars()
            
            if 'title' in post_vars:
                new_content = {"content": post_vars['title']}
                await query_db.execute_write(
                    "UPDATE admin_content SET content = ?, updated_at = ?, updated_by = ? WHERE db_id = ? AND section = 'title'",
                    [json.dumps(new_content), datetime.utcnow().isoformat(), actor['username'], db_id]
                )
                return Response.redirect(f"{request.path}?success=Title updated")
            
            if 'description' in post_vars:
                new_content = {
                    "content": post_vars['description'],
                    "paragraphs": parse_markdown_links(post_vars['description'])
                }
                await query_db.execute_write(
                    "UPDATE admin_content SET content = ?, updated_at = ?, updated_by = ? WHERE db_id = ? AND section = 'description'",
                    [json.dumps(new_content), datetime.utcnow().isoformat(), actor['username'], db_id]
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
                    "UPDATE admin_content SET content = ?, updated_at = ?, updated_by = ? WHERE db_id = ? AND section = 'footer'",
                    [json.dumps(new_content), datetime.utcnow().isoformat(), actor['username'], db_id]
                )
                return Response.redirect(f"{request.path}?success=Footer updated")
    
    return Response.html(
        await datasette.render_template(
            "template.html",
            {
                "db_name": db_name,
                "db_status": db_status,
                "content": content,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def upload_csv(datasette, request):
    logger.debug(f"Upload CSV request: method={request.method}, path={request.path}")

    path_parts = request.path.strip('/').split('/')
    db_name = path_parts[0]
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id FROM databases WHERE db_name = ?",
            [db_name]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        if not actor or actor['id'] != db_info['user_id']:
            return Response.text("Permission denied", status=403)
    except Exception as e:
        logger.error(f"Error checking database {db_name}: {e}")
        return Response.text("Database error", status=500)
    
    if request.method == "POST":
        content_type = request.headers.get('content-type', '').lower()
        if 'multipart/form-data' in content_type:
            boundary = content_type.split('boundary=')[1]
            body = await request.body()
            if len(body) > MAX_FILE_SIZE:
                return Response.text("File too large", status=400)
            form_data = parse_form_data(body, boundary=boundary.encode())
            
            table_name = form_data.get('table_name').value if 'table_name' in form_data else None
            csv_file = form_data.get('csv_file') if 'csv_file' in form_data else None
            
            if table_name and csv_file and csv_file.filename.endswith('.csv'):
                db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
                portal_db = sqlite_utils.Database(db_path)
                full_table_name = f"{db_name}_{table_name}"
                
                if full_table_name in portal_db.table_names():
                    return Response.text(f"Table {table_name} already exists", status=400)
                
                table_count = sum(1 for name in portal_db.table_names() if name.startswith(f"{db_name}_"))
                if table_count >= MAX_TABLES_PER_DATABASE:
                    return Response.text(f"Maximum {MAX_TABLES_PER_DATABASE} tables per database reached", status=400)
                
                df = pd.read_csv(io.BytesIO(csv_file.value))
                portal_db[full_table_name].insert_all(df.to_dict('records'), replace=True)
                
                await query_db.execute_write(
                    "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                    [str(uuid.uuid4()), actor['id'], "upload_csv", f"Uploaded CSV to table {table_name} in {db_name}", datetime.utcnow()]
                )
                
                return Response.redirect(f"/manage-databases?success=CSV uploaded successfully as table {table_name}")
            else:
                return Response.text("Invalid table name or CSV file", status=400)
    
    return Response.html(
        await datasette.render_template(
            "upload_csv.html",
            {
                "db_name": db_name
            },
            request=request
        )
    )

@hookimpl
def register_routes():
    return [
        (r'^/$', index_page),
        (r'^/login$', login_page),
        (r'^/register$', register_page),
        (r'^/logout$', logout_page),
        (r'^/change-password$', change_password_page),
        (r'^/create-database$', create_database),
        (r'^/manage-databases$', manage_databases),
        (r'^/system-admin$', system_admin_page),
        (r'^/([^/]+)$', database_homepage),
        (r'^/([^/]+)/tables$', database_tables_view),
        (r'^/([^/]+)/([^/]+)$', database_table_view),
        (r'^/edit-content/(.+)$', edit_content),
        (r'^/([^/]+)/upload-csv$', upload_csv),
        (r'^/([^/]+)/publish$', publish_database),
    ]

@hookimpl
def startup(datasette):
    async def inner():
        db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
        portal_db = sqlite_utils.Database(db_path)
        query_db = datasette.get_database('portal')
        
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
            "deleted_at": str
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

        try:
            await query_db.execute("ALTER TABLE databases ADD COLUMN deleted_at TEXT")
        except:
            pass

        try:
            await query_db.execute_write(
                "INSERT OR IGNORE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                [None, "title", json.dumps({"content": "EDGI Datasette Cloud Portal"}), datetime.utcnow().isoformat(), "system"]
            )
            await query_db.execute_write(
                "INSERT OR IGNORE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                [None, "header_image", json.dumps({"image_url": "/static/default_header.jpg", "alt_text": "", "credit_url": "", "credit_text": ""}), datetime.utcnow().isoformat(), "system"]
            )
            await query_db.execute_write(
                "INSERT OR IGNORE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                [None, "info", json.dumps({"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites."}), datetime.utcnow().isoformat(), "system"]
            )
            await query_db.execute_write(
                "INSERT OR IGNORE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                [None, "footer", json.dumps({"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}), datetime.utcnow().isoformat(), "system"]
            )
        except Exception as e:
            logger.error(f"Error initializing admin_content: {str(e)}")

    return inner