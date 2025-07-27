import io
import json
import bcrypt
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from email.parser import BytesParser
from email.policy import default
import bleach
import re
import sqlite_utils
import uuid
import pandas as pd
import os

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_DATABASES_PER_USER = 5
MAX_TABLES_PER_DATABASE = 10

class CookieDebugger:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            cookies = headers.get(b"cookie", b"").decode()
            logger.debug(f"Incoming cookies: {cookies}")
        
        await self.app(scope, receive, send)

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

async def index_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Index Cookies: {cookies}")

    db = datasette.get_database("portal")

    async def get_section(section_name):
        result = await db.execute("SELECT content FROM admin_content WHERE section = ?", [section_name])
        row = result.first()
        if row:
            try:
                content = json.loads(row["content"])
                if section_name == "info" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                return content
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for section {section_name}: {str(e)}")
                return {}
        else:
            return {}

    content = {}
    content['header_image'] = await get_section("header_image") or {'image_url': 'static/header.jpg', 'alt_text': '', 'credit_url': '', 'credit_text': ''}
    content['info'] = await get_section("info") or {'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.', 'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')}
    content['title'] = await get_section("title") or {'content': 'EDGI Datasette Cloud Portal'}
    content['description'] = {'content': 'Environmental data dashboard.'}

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

    statistics_data = []
    try:
        total_result = await db.execute("SELECT COUNT(*) FROM databases")
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

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

    if actor:
        try:
            result = await db.execute("SELECT user_id, role FROM users WHERE user_id = ?", [actor.get("id")])
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
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def login_page(datasette, request):
    logger.debug(f"Login request: method={request.method}, scope={request.scope}")
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Login Cookies: {cookies}")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"POST vars: {post_vars}")
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
                        signed_actor = datasette.sign(actor_data, "actor")
                        response = Response.redirect(redirect_url)
                        response.set_cookie("ds_actor", signed_actor, httponly=True, max_age=3600, samesite="lax")
                        request.scope["actor"] = actor_data
                        logger.debug(f"Set signed cookie ds_actor: {signed_actor}")
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
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Register Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        ds_actor_cookie = cookies.get("ds_actor")
        if ds_actor_cookie:
            try:
                actor = datasette.unsign(ds_actor_cookie, namespace="actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {str(e)}, cookie value: {ds_actor_cookie}")
                actor = None

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
               'description': {'content': 'Environmental data dashboard.'}}

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"Register POST vars: {post_vars}")
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

async def profile_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Profile Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning("Unauthorized profile access attempt")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    try:
        user = await db.execute("SELECT user_id, username, email FROM users WHERE user_id = ?", [actor.get("id")])
        user_row = user.first()
        if user_row:
            user_info = dict(user_row)
            logger.debug(f"User profile found: user_id={user_info['user_id']}, username={user_info['username']}")
        else:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            return Response.html(
                await datasette.render_template(
                    "profile.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "user_info": {},
                        "error": "User profile not found"
                    },
                    request=request
                )
            )
    except Exception as e:
        logger.error(f"Profile query error: {str(e)}")
        return Response.html(
            await datasette.render_template(
                "profile.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "user_info": {},
                    "error": f"Error loading profile: {str(e)}"
                },
                request=request
            )
        )

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"Profile POST vars: {post_vars}")
        username = post_vars.get("username")
        email = post_vars.get("email")
        if not username or not email:
            return Response.html(
                await datasette.render_template(
                    "profile.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "user_info": user_info,
                        "error": "Username and email are required"
                    },
                    request=request
                )
            )
        try:
            db = datasette.get_database("portal")
            await db.execute_write(
                "UPDATE users SET username = ?, email = ? WHERE user_id = ?",
                [username, email, actor.get("id")]
            )
            actor_data = {"id": actor.get("id"), "name": f"User {username}", "role": actor.get("role"), "username": username}
            response = Response.redirect("/manage-databases?success=Profile updated successfully")
            response.set_cookie("ds_actor", datasette.sign(actor_data, "actor"), httponly=True, max_age=3600)
            request.scope["actor"] = actor_data
            await db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), actor.get("id"), "update_profile", f"User {username} updated profile", datetime.utcnow()]
            )
            logger.debug("Profile updated for user: %s, user_id: %s", username, actor.get("id"))
            return response
        except Exception as e:
            logger.error(f"Profile update error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "profile.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "user_info": user_info,
                        "error": f"Profile update error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "profile.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "user_info": user_info,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def dashboard_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Dashboard Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning(f"Unauthorized dashboard access attempt: actor=None")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    try:
        result = await db.execute("SELECT user_id, username, email FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            return Response.redirect("/login?error=Authentication error")
    except Exception as e:
        logger.error(f"Error verifying user in dashboard_page: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    user_databases = []
    user_info = {}
    try:
        result = await db.execute("SELECT db_id, db_name, website_url, status FROM databases WHERE user_id = ?", [actor.get("id")])
        user_databases = [{"db_id": row["db_id"], "db_name": row["db_name"], "website_url": row["website_url"], "status": row["status"]} for row in result]
        user_result = await db.execute("SELECT username, email FROM users WHERE user_id = ?", [actor.get("id")])
        user_row = user_result.first()
        if user_row:
            user_info = dict(user_row)
            logger.debug(f"User profile found: user_id={actor.get('id')}, username={user_info['username']}")
        else:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            return Response.html(
                await datasette.render_template(
                    "dashboard.html",
                    {
                        "page_title": content['title'].get('content', "EDGI Datasette Cloud Portal") + " | Dashboard",
                        "content": content,
                        "actor": actor,
                        "user_databases": user_databases,
                        "user_info": {},
                        "error": "User profile not found"
                    },
                    request=request
                )
            )
    except Exception as e:
        logger.error(f"Dashboard query error: {str(e)}")
        return Response.html(
            await datasette.render_template(
                "dashboard.html",
                {
                    "page_title": content['title'].get('content', "EDGI Datasette Cloud Portal") + " | Dashboard",
                    "content": content,
                    "actor": actor,
                    "user_databases": user_databases,
                    "user_info": {},
                    "error": f"Error loading dashboard: {str(e)}"
                },
                request=request
            )
        )

    logger.debug(f"Rendering dashboard with data: content={content}, user_databases={user_databases}")

    return Response.html(
        await datasette.render_template(
            "dashboard.html",
            {
                "page_title": content['title'].get('content', "EDGI Datasette Cloud Portal") + " | Dashboard",
                "content": content,
                "actor": actor,
                "user_databases": user_databases,
                "user_info": user_info,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def system_admin_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"System Admin Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

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

    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    try:
        users = await db.execute("SELECT user_id, username, email, role, created_at FROM users")
        users_list = [dict(row) for row in users]
        databases = await db.execute("SELECT d.db_id, d.db_name, d.website_url, d.status, d.created_at, u.username FROM databases d JOIN users u ON d.user_id = u.user_id")
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

async def change_password_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Change Password Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        ds_actor_cookie = cookies.get("ds_actor")
        if ds_actor_cookie:
            try:
                actor = datasette.unsign(ds_actor_cookie, namespace="actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {str(e)}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning(f"Unauthorized change password attempt: actor={actor}")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"Change password POST vars: {post_vars}")
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

async def logout_page(datasette, request):
    logger.debug(f"Logout request: method={request.method}, scope={request.scope}")
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Logout Cookies: {cookies}")
    
    response = Response.redirect("/login")
    response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
    logger.debug("Cleared ds_actor cookie")
    return response

async def manage_databases(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Manage Databases Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

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

    result = await query_db.execute("SELECT db_id, db_name, status, website_url FROM databases WHERE user_id = ?", [actor.get("id")])
    user_databases = [dict(row) for row in result]
    if not user_databases:
        db_id = str(uuid.uuid4())
        db_name = "my_database"
        username = actor.get("username")
        website_url = f"{username}-{db_name}.datasette-portal.fly.dev"
        await query_db.execute_write(
            "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            [db_id, actor.get("id"), db_name, website_url, "Draft", datetime.utcnow()]
        )
        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [str(uuid.uuid4()), actor.get("id"), "create_database", f"Created default database {db_name}", datetime.utcnow()]
        )
        user_databases = [{"db_id": db_id, "db_name": db_name, "status": "Draft", "website_url": website_url}]
    else:
        db_id = user_databases[0]['db_id']
        db_name = user_databases[0]['db_name']
        db_status = user_databases[0]['status']
        website_url = user_databases[0]['website_url']

    total_size = 0
    tables = []
    try:
        username = actor.get("username")
        prefix = f"{username}_{db_name}_"
        for name in portal_db.table_names():
            if name.startswith(prefix) and name != f"{prefix}admin_content":
                table_size = portal_db[name].count * 0.001  # Use .count instead of len(.rows)
                total_size += table_size
                display_name = name[len(prefix):]
                tables.append({'name': display_name, 'full_name': name, 'preview': f"/{db_name}/{display_name}", 'size': table_size, 'md5': 'md5-placeholder', 'progress': 100})
    except Exception as e:
        logger.error(f"Error loading tables: {str(e)}")
        return Response.html(
            await datasette.render_template(
                "manage_databases.html",
                {
                    "metadata": datasette.metadata(),
                    "content": {"title": {"content": "EDGI Datasette Cloud Portal"}, "description": {"content": "Environmental data dashboard."}},
                    "actor": actor,
                    "user_databases": user_databases,
                    "tables": tables,
                    "total_size": total_size,
                    "error": f"Error loading tables: {str(e)}"
                },
                request=request
            )
        )

    title = await query_db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'},
        'footer': {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': ['Made with EDGI']}
    }

    if db_status == "Published":
        try:
            desc_result = await query_db.execute("SELECT content FROM web_content WHERE db_id = ? AND section = ?", [db_id, "description"])
            desc_row = desc_result.first()
            if desc_row:
                content['description'] = json.loads(desc_row["content"])
        except Exception as e:
            logger.error(f"Error loading description from web_content: {str(e)}")

    return Response.html(
        await datasette.render_template(
            "manage_databases.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "user_databases": user_databases,
                "tables": tables,
                "total_size": total_size,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def add_table(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Add Table Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

    if not actor:
        logger.warning(f"Unauthorized add table attempt: actor=None")
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
        logger.error(f"Error verifying user in add_table: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    post_vars = await request.post_vars()
    db_id = post_vars.get("db_id")
    result = await query_db.execute("SELECT db_name, status FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info or db_info["status"] != "Draft":
        return Response.redirect("/manage-databases?error=Invalid or non-Draft database")

    db_name = db_info["db_name"]
    username = actor.get("username")
    try:
        body = await request.post_body()
        content_type = request.headers.get('content-type', '')
        boundary = None
        if 'boundary=' in content_type.lower():
            boundary = content_type.split('boundary=')[-1].split(';')[0].strip().encode('utf-8')
        if not boundary:
            logger.error("No boundary found in Content-Type header")
            return Response.json({'error': 'Invalid multipart form data: missing boundary'}, status=400)

        headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
        headers['content-type'] = content_type
        msg = BytesParser(policy=default).parsebytes(b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n' + body)
        
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

        if files.get('dataset'):
            file = files['dataset']
            if len(file['content']) > MAX_FILE_SIZE:
                logger.error("File exceeds 50MB limit")
                return Response.redirect("/manage-databases?error=File exceeds 50MB limit")

            ext = Path(file['filename']).suffix.lower()
            if ext != '.csv':
                logger.error(f"Invalid file extension: {ext}")
                return Response.redirect("/manage-databases?error=Only .csv files allowed")

            table_count = sum(1 for name in portal_db.table_names() if name.startswith(f"{username}_{db_name}_") and name != f"{username}_{db_name}_admin_content")
            if table_count >= MAX_TABLES_PER_DATABASE:
                logger.error(f"Maximum {MAX_TABLES_PER_DATABASE} tables per database reached")
                return Response.redirect(f"/manage-databases?error=Maximum {MAX_TABLES_PER_DATABASE} tables per database reached")

            table_name = f"{username}_{db_name}_{Path(file['filename']).stem.lower().replace(' ', '_')}"
            df = pd.read_csv(io.BytesIO(file['content']))
            columns = {col: str for col in df.columns}
            portal_db.create_table(table_name, columns, if_not_exists=True)
            portal_db[table_name].insert_all(df.to_dict('records'), ignore=True)
            await query_db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), actor.get("id"), "add_table", f"Added table {Path(file['filename']).stem} to database {db_name}", datetime.utcnow()]
            )
            return Response.redirect("/manage-databases?success=Table added successfully")
        return Response.redirect("/manage-databases?error=No file uploaded")
    except Exception as e:
        logger.error(f"Add table error: {str(e)}")
        return Response.redirect(f"/manage-databases?error=Add table error: {str(e)}")

async def delete_table(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Delete Table Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        ds_actor_cookie = cookies.get("ds_actor")
        if ds_actor_cookie:
            try:
                actor = datasette.unsign(ds_actor_cookie, namespace="actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {str(e)}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning(f"Unauthorized delete table attempt: actor={actor}")
        return Response.redirect("/login")

    query_db = datasette.get_database('portal')
    db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
    portal_db = sqlite_utils.Database(db_path)
    post_vars = await request.post_vars()
    db_id = post_vars.get("db_id")
    table_name = post_vars.get("table_name")
    if not db_id or not table_name:
        return Response.redirect("/manage-databases?error=Missing database ID or table name")

    result = await query_db.execute("SELECT db_name, status FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        return Response.redirect("/manage-databases?error=Invalid or unauthorized database")
    if db_info["status"] != "Draft":
        return Response.redirect(f"/manage-databases?error=Can only delete tables in Draft databases")

    username = actor.get("username")
    full_table_name = f"{username}_{db_info['db_name']}_{table_name}"
    try:
        if full_table_name in portal_db.table_names():
            portal_db[full_table_name].drop()
            await query_db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), actor.get("id"), "delete_table", f"Deleted table {table_name} from database {db_info['db_name']}", datetime.utcnow()]
            )
            logger.debug(f"Table {full_table_name} deleted from db_id: {db_id}")
            return Response.redirect(f"/manage-databases?success=Table deleted successfully")
        else:
            return Response.redirect(f"/manage-databases?error=Table not found")
    except Exception as e:
        logger.error(f"Delete table error: {str(e)}")
        return Response.redirect(f"/manage-databases?error=Delete table error: {str(e)}")

async def publish_database(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Publish Database Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        ds_actor_cookie = cookies.get("ds_actor")
        if ds_actor_cookie:
            try:
                actor = datasette.unsign(ds_actor_cookie, namespace="actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {str(e)}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning(f"Unauthorized publish database attempt: actor={actor}")
        return Response.redirect("/login")

    query_db = datasette.get_database('portal')
    db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
    portal_db = sqlite_utils.Database(db_path)
    post_vars = await request.post_vars()
    db_id = post_vars.get("db_id")
    if not db_id:
        return Response.redirect("/manage-databases?error=Missing database ID")

    result = await query_db.execute("SELECT db_name, status, website_url FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        return Response.redirect("/manage-databases?error=Invalid or unauthorized database")
    if db_info["status"] != "Draft":
        return Response.redirect(f"/manage-databases?error=Database already published or not in Draft status")

    username = actor.get("username")
    try:
        portal_db["web_content"].insert(
            {"db_id": db_id, "section": "title", "content": json.dumps({"content": db_info["db_name"]}), "updated_at": datetime.utcnow().isoformat(), "updated_by": username},
            pk=("db_id", "section"), ignore=True
        )
        portal_db["web_content"].insert(
            {"db_id": db_id, "section": "description", "content": json.dumps({"content": "Environmental data dashboard."}), "updated_at": datetime.utcnow().isoformat(), "updated_by": username},
            pk=("db_id", "section"), ignore=True
        )
        portal_db["web_content"].insert(
            {"db_id": db_id, "section": "footer", "content": json.dumps({"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}), "updated_at": datetime.utcnow().isoformat(), "updated_by": username},
            pk=("db_id", "section"), ignore=True
        )
        await query_db.execute_write(
            "UPDATE databases SET status = 'Published' WHERE db_id = ?",
            [db_id]
        )
        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [str(uuid.uuid4()), actor.get("id"), "publish_database", f"Published database {db_info['db_name']}", datetime.utcnow()]
        )
        logger.debug(f"Database published: db_id={db_id}, url={db_info['website_url']}")
        return Response.redirect(f"/manage-databases?success=Database published successfully")
    except Exception as e:
        logger.error(f"Publish database error: {str(e)}")
        return Response.redirect(f"/manage-databases?error=Publish database error: {str(e)}")

async def create_database(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Create Database Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

    if not actor:
        logger.warning(f"Unauthorized create database attempt: actor=None")
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
        logger.error(f"Error verifying user in create_database: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    title = await query_db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    if request.method == "POST":
        try:
            body = await request.post_body()
            content_type = request.headers.get('content-type', '')
            boundary = None
            if 'boundary=' in content_type.lower():
                boundary = content_type.split('boundary=')[-1].split(';')[0].strip().encode('utf-8')
            if not boundary:
                logger.error("No boundary found in Content-Type header")
                return Response.json({'error': 'Invalid multipart form data: missing boundary'}, status=400)

            headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
            headers['content-type'] = content_type
            msg = BytesParser(policy=default).parsebytes(b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n' + body)
            
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

            db_name = forms.get('db_name', [''])[0].strip()
            logger.debug(f"Create database: db_name={db_name}, files={files}")

            if not db_name or not files.get('dataset'):
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "Database name and CSV file are required"
                        },
                        request=request
                    )
                )

            file = files['dataset']
            if len(file['content']) > MAX_FILE_SIZE:
                logger.error("File exceeds 50MB limit")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "File exceeds 50MB limit"
                        },
                        request=request
                    )
                )

            ext = Path(file['filename']).suffix.lower()
            if ext != '.csv':
                logger.error(f"Invalid file extension: {ext}")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "Only .csv files allowed"
                        },
                        request=request
                    )
                )

            username = actor.get("username")
            user_id = actor.get("id")
            result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ?", [user_id])
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

            db_id = str(uuid.uuid4())
            website_url = f"{username}-{db_name}.datasette-portal.fly.dev"
            table_name = f"{username}_{db_name}_{Path(file['filename']).stem.lower().replace(' ', '_')}"

            try:
                df = pd.read_csv(io.BytesIO(file['content']))
                columns = {col: str for col in df.columns}
                portal_db.create_table(table_name, columns, if_not_exists=True)
                portal_db[table_name].insert_all(df.to_dict('records'), ignore=True)
                portal_db.create_table(f"{username}_{db_name}_admin_content", {
                    "section": str,
                    "content": str,
                    "updated_at": str,
                    "updated_by": str
                }, pk="section", if_not_exists=True)
                portal_db[f"{username}_{db_name}_admin_content"].upsert({
                    "section": "title",
                    "content": json.dumps({"content": db_name}),
                    "updated_at": datetime.utcnow().isoformat(),
                    "updated_by": username
                }, pk="section")
                portal_db[f"{username}_{db_name}_admin_content"].upsert({
                    "section": "footer",
                    "content": json.dumps({"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}),
                    "updated_at": datetime.utcnow().isoformat(),
                    "updated_by": username
                }, pk="section")

                await query_db.execute_write(
                    "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    [db_id, user_id, db_name, website_url, "Draft", datetime.utcnow()]
                )
                await query_db.execute_write(
                    "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                    [str(uuid.uuid4()), user_id, "create_database", f"Created database {db_name}", datetime.utcnow()]
                )
                logger.debug(f"Database created: {db_name}, table: {table_name}, website_url={website_url}")
                return Response.redirect("/manage-databases?success=Database created successfully")
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

async def template_page(datasette, request, db_id=None):
    if not db_id:
        db_id = request.url_vars.get('db_id')
        if not db_id:
            logger.error("Missing db_id in template_page request")
            return Response.redirect("/manage-databases?error=Invalid database ID")

    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Template Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

    if not actor:
        logger.warning(f"Unauthorized template access attempt: actor=None")
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
        logger.error(f"Error verifying user in template_page: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    result = await query_db.execute("SELECT db_name, status, website_url FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        logger.error(f"Invalid or unauthorized database: db_id={db_id}, user_id={actor.get('id')}")
        return Response.redirect("/manage-databases?error=Invalid or unauthorized database")

    db_name = db_info["db_name"]
    db_status = db_info["status"]
    website_url = db_info["website_url"]
    username = actor.get("username")

    try:
        admin_content_table = f"{username}_{db_name}_admin_content"
        if admin_content_table not in portal_db.table_names():
            portal_db.create_table(admin_content_table, {
                "section": str,
                "content": str,
                "updated_at": str,
                "updated_by": str
            }, pk="section", if_not_exists=True)
            portal_db[admin_content_table].upsert({
                "section": "title",
                "content": json.dumps({"content": db_name}),
                "updated_at": datetime.utcnow().isoformat(),
                "updated_by": username
            }, pk="section")
            portal_db[admin_content_table].upsert({
                "section": "footer",
                "content": json.dumps({"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}),
                "updated_at": datetime.utcnow().isoformat(),
                "updated_by": username
            }, pk="section")
        sections = await query_db.execute(f'SELECT section, content FROM {admin_content_table}')
        content = {row['section']: json.loads(row['content']) for row in sections}
        content['description'] = {'content': 'Environmental data dashboard.'}
        content['header_image'] = {'image_url': '', 'alt_text': '', 'credit_url': '', 'credit_text': ''}
        if db_status == "Published":
            web_sections = await query_db.execute("SELECT section, content FROM web_content WHERE db_id = ?", [db_id])
            for row in web_sections:
                content[row['section']] = json.loads(row['content'])
    except Exception as e:
        logger.error(f"Error loading database content for db_id={db_id}: {str(e)}")
        return Response.redirect("/manage-databases?error=Error loading database content")

    if 'title' not in content:
        content['title'] = {'content': db_name}
    if 'footer' not in content:
        content['footer'] = {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': parse_markdown_links('Made with EDGI')}
    if 'footer' in content and 'content' in content['footer'] and 'paragraphs' not in content['footer']:
        content['footer']['paragraphs'] = parse_markdown_links(content['footer']['content'])

    return Response.html(
        await datasette.render_template(
            'template.html',
            {
                'content': content,
                'metadata': datasette.metadata(),
                'actor': actor,
                'db_id': db_id,
                'db_name': db_name,
                'db_status': db_status,
                'website_url': website_url,
                'success': request.args.get('success'),
                'error': request.args.get('error')
            },
            request=request
        )
    )

async def create_homepage(datasette, request, db_id=None):
    if not db_id:
        db_id = request.url_vars.get('db_id')
        if not db_id:
            logger.error("Missing db_id in create_homepage request")
            return Response.redirect("/manage-databases?error=Invalid database ID")

    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Create Homepage Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = datasette.unsign(ds_actor_cookie, "actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

    if not actor:
        logger.warning(f"Unauthorized create homepage attempt: actor=None")
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
        logger.error(f"Error verifying user in create_homepage: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    result = await query_db.execute("SELECT db_name, status, website_url FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        logger.error(f"Invalid or unauthorized database: db_id={db_id}, user_id={actor.get('id')}")
        return Response.redirect("/manage-databases?error=Invalid or unauthorized database")
    if db_info["status"] != "Published":
        logger.error(f"Database not published: db_id={db_id}, status={db_info['status']}")
        return Response.redirect("/manage-databases?error=Can only edit homepage for published databases")

    db_name = db_info["db_name"]
    db_status = db_info["status"]
    website_url = db_info["website_url"]
    username = actor.get("username")

    try:
        homepage_content = {
            'title': {'content': db_name},
            'description': {'content': 'Environmental data dashboard.'},
            'header_image': {'image_url': '', 'alt_text': '', 'credit_url': '', 'credit_text': ''},
            'footer': {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': ['Made with EDGI']}
        }
        web_sections = await query_db.execute("SELECT section, content FROM web_content WHERE db_id = ?", [db_id])
        for row in web_sections:
            homepage_content[row['section']] = json.loads(row['content'])
        if 'footer' in homepage_content and 'content' in homepage_content['footer'] and 'paragraphs' not in homepage_content['footer']:
            homepage_content['footer']['paragraphs'] = parse_markdown_links(homepage_content['footer']['content'])
    except Exception as e:
        logger.error(f"Error loading homepage content for db_id={db_id}: {str(e)}")
        return Response.redirect("/create-homepage/{}?error=Error loading homepage content".format(db_id))

    if request.method == "POST":
        try:
            body = await request.post_body()
            content_type = request.headers.get('content-type', '')
            boundary = None
            if 'boundary=' in content_type.lower():
                boundary = content_type.split('boundary=')[-1].split(';')[0].strip().encode('utf-8')
            if not boundary:
                logger.error("No boundary found in Content-Type header")
                return Response.json({'error': 'Invalid multipart form data: missing boundary'}, status=400)

            headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
            headers['content-type'] = content_type
            msg = BytesParser(policy=default).parsebytes(b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n' + body)
            
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

            section = forms.get('section', [''])[0]
            if section not in ['title', 'description', 'header_image', 'footer']:
                return Response.redirect("/create-homepage/{}?error=Invalid section".format(db_id))

            if section == 'header_image' and files.get('header_image'):
                file = files['header_image']
                if len(file['content']) > 5 * 1024 * 1024:  # 5MB
                    logger.error("Header image exceeds 5MB limit")
                    return Response.redirect("/create-homepage/{}?error=Header image exceeds 5MB limit".format(db_id))

                ext = Path(file['filename']).suffix.lower()
                if ext not in ['.jpg', '.png']:
                    logger.error(f"Invalid image extension: {ext}")
                    return Response.redirect("/create-homepage/{}?error=Only .jpg and .png files allowed".format(db_id))

                data_dir = os.path.join(os.getcwd(), 'data', username)
                os.makedirs(data_dir, exist_ok=True)
                image_path = os.path.join(data_dir, f"{db_name}_header{ext}")
                with open(image_path, 'wb') as f:
                    f.write(file['content'])
                content_data = {
                    'image_url': f"data/{username}/{db_name}_header{ext}",
                    'alt_text': forms.get('alt_text', [''])[0],
                    'credit_url': forms.get('credit_url', [''])[0],
                    'credit_text': forms.get('credit_text', [''])[0]
                }
            else:
                content_value = forms.get('content', [''])[0]
                content_data = {'content': content_value}
                if section == 'footer':
                    content_data['paragraphs'] = parse_markdown_links(content_value)
                    content_data['odbl_text'] = 'Data licensed under ODbL'
                    content_data['odbl_url'] = 'https://opendatacommons.org/licenses/odbl/'

            try:
                portal_db["web_content"].insert(
                    {"db_id": db_id, "section": section, "content": json.dumps(content_data), "updated_at": datetime.utcnow().isoformat(), "updated_by": username},
                    pk=("db_id", "section"), replace=True
                )
                await query_db.execute_write(
                    "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                    [str(uuid.uuid4()), actor.get("id"), "update_homepage", f"Updated homepage section {section} for database {db_name}", datetime.utcnow()]
                )
                logger.debug(f"Homepage section {section} updated for db_id={db_id}")
                return Response.redirect(f"/create-homepage/{db_id}?success=Homepage updated successfully")
            except Exception as e:
                logger.error(f"Update homepage error: {str(e)}")
                return Response.redirect(f"/create-homepage/{db_id}?error=Update homepage error: {str(e)}")
        except Exception as e:
            logger.error(f"Update homepage error: {str(e)}")
            return Response.redirect(f"/create-homepage/{db_id}?error=Update homepage error: {str(e)}")

    return Response.html(
        await datasette.render_template(
            'create_homepage.html',
            {
                'homepage_content': homepage_content,
                'metadata': datasette.metadata(),
                'actor': actor,
                'db_id': db_id,
                'db_name': db_name,
                'db_status': db_status,
                'website_url': website_url,
                'success': request.args.get('success'),
                'error': request.args.get('error')
            },
            request=request
        )
    )

async def delete_database(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Delete Database Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        ds_actor_cookie = cookies.get("ds_actor")
        if ds_actor_cookie:
            try:
                actor = datasette.unsign(ds_actor_cookie, namespace="actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {str(e)}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning(f"Unauthorized delete database attempt: actor={actor}")
        return Response.redirect("/login")

    query_db = datasette.get_database('portal')
    db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
    portal_db = sqlite_utils.Database(db_path)
    post_vars = await request.post_vars()
    db_id = post_vars.get("db_id")
    if not db_id:
        return Response.redirect("/manage-databases?error=Missing database ID")

    result = await query_db.execute("SELECT db_name, status FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        return Response.redirect("/manage-databases?error=Invalid or unauthorized database")
    if db_info["status"] != "Draft":
        return Response.redirect(f"/manage-databases?error=Can only delete Draft databases")

    username = actor.get("username")
    db_name = db_info["db_name"]
    try:
        prefix = f"{username}_{db_name}_"
        for table_name in portal_db.table_names():
            if table_name.startswith(prefix):
                portal_db[table_name].drop()
        await query_db.execute_write("DELETE FROM databases WHERE db_id = ?", [db_id])
        await query_db.execute_write("DELETE FROM web_content WHERE db_id = ?", [db_id])
        await query_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [str(uuid.uuid4()), actor.get("id"), "delete_database", f"Deleted database {db_name}", datetime.utcnow()]
        )
        logger.debug(f"Database deleted: db_id={db_id}")
        return Response.redirect("/dashboard?success=Database deleted successfully")
    except Exception as e:
        logger.error(f"Delete database error: {str(e)}")
        return Response.redirect(f"/manage-databases?error=Delete database error: {str(e)}")

async def update_content(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Update Content Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        ds_actor_cookie = cookies.get("ds_actor")
        if ds_actor_cookie:
            try:
                actor = datasette.unsign(ds_actor_cookie, namespace="actor")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {str(e)}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning(f"Unauthorized update content attempt: actor={actor}")
        return Response.redirect("/login")

    query_db = datasette.get_database('portal')
    db_path = os.getenv('PORTAL_DB_PATH', "C:/MS Data Science - WMU/EDGI/edgi-cloud/portal.db")
    portal_db = sqlite_utils.Database(db_path)
    post_vars = await request.post_vars()
    db_id = post_vars.get("db_id")
    section = post_vars.get("section")
    if not db_id or not section:
        return Response.redirect("/manage-databases?error=Missing database ID or section")

    result = await query_db.execute("SELECT db_name, status FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        return Response.redirect("/manage-databases?error=Invalid or unauthorized database")

    username = actor.get("username")
    db_name = db_info["db_name"]
    try:
        if section == "description":
            description = post_vars.get("description", [''])[0]
            content_data = {'content': description}
            portal_db["web_content"].insert(
                {"db_id": db_id, "section": section, "content": json.dumps(content_data), "updated_at": datetime.utcnow().isoformat(), "updated_by": username},
                pk=("db_id", "section"), replace=True
            )
            await query_db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), actor.get("id"), "update_content", f"Updated {section} for database {db_name}", datetime.utcnow()]
            )
            logger.debug(f"Content updated: section={section}, db_id={db_id}")
            return Response.redirect(f"/manage-databases?success=Content updated successfully")
        else:
            return Response.redirect(f"/manage-databases?error=Invalid section")
    except Exception as e:
        logger.error(f"Update content error: {str(e)}")
        return Response.redirect(f"/manage-databases?error=Update content error: {str(e)}")

from datasette import hookimpl

@hookimpl
def register_routes():
    return [
        (r'^/create-database$', create_database),
        (r'^/manage-databases$', manage_databases),
        (r'^/add-table$', add_table),
        (r'^/delete-table$', delete_table),
        (r'^/publish-database$', publish_database),
        (r'^/template/(?P<db_id>[^/]+)$', template_page),
        (r'^/create-homepage/(?P<db_id>[^/]+)$', create_homepage),
        (r'^/delete-database$', delete_database),
        (r'^/update-content$', update_content),
        (r'^/$', index_page),
        (r'^/login$', login_page),
        (r'^/register$', register_page),
        (r'^/profile$', profile_page),
        (r'^/dashboard$', dashboard_page),
        (r'^/system-admin$', system_admin_page),
        (r'^/change-password$', change_password_page),
        (r'^/logout$', logout_page),
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
            "created_at": str
        }, pk="db_id", if_not_exists=True)

        portal_db.create_table("admin_content", {
            "section": str,
            "content": str,
            "updated_at": str,
            "updated_by": str
        }, pk="section", if_not_exists=True)

        portal_db.create_table("web_content", {
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
            await query_db.execute_write(
                "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                ["title", json.dumps({"content": "EDGI Datasette Cloud Portal"}), datetime.utcnow().isoformat(), "system"]
            )
            await query_db.execute_write(
                "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                ["header_image", json.dumps({"image_url": "static/header.jpg", "alt_text": "", "credit_url": "", "credit_text": ""}), datetime.utcnow().isoformat(), "system"]
            )
            await query_db.execute_write(
                "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                ["info", json.dumps({"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.", "paragraphs": parse_markdown_links("The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.")}), datetime.utcnow().isoformat(), "system"]
            )
        except Exception as e:
            logger.error(f"Error initializing admin_content: {str(e)}")

    return inner