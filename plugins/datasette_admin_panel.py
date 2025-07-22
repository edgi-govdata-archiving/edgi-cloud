import io
import json
import bcrypt
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response, AsgiLifespan
from email.parser import BytesParser
from email.policy import default
import bleach
import re
import os
import sqlite_utils
import uuid
import pandas as pd

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv', '.db'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_DATABASES_PER_USER = 5

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
        parsed = link_pattern.sub(lambda m: f'<a href="{sanitize_text(m.group(2))}" class="text-accent hover:text-primary">{sanitize_text(m.group(1))}</a>', paragraph)
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
    content['header_image'] = await get_section("header_image") or {'image_url': '/static/header.jpg', 'alt_text': '', 'credit_url': '', 'credit_text': ''}
    content['info'] = await get_section("info") or {'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.', 'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')}
    content['title'] = await get_section("title") or {'content': 'EDGI Datasette Cloud Portal'}

    # Fetch user databases for feature_cards
    try:
        result = await db.execute("SELECT db_id, db_name, website_url, status FROM databases WHERE status IN ('Draft', 'Pending', 'Published') ORDER BY created_at DESC LIMIT 6")
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

    # Define statistics based on databases table
    statistics_data = []
    try:
        total_result = await db.execute("SELECT COUNT(*) FROM databases")
        total_count = total_result.first()[0]
        published_result = await db.execute("SELECT COUNT(*) FROM databases WHERE status = 'Published'")
        published_count = published_result.first()[0]
        statistics_data = [
            {"label": "Total User Websites", "value": total_count, "url": "/databases"},
            {"label": "Published Websites", "value": published_count, "url": "/databases?status=Published"}
        ]
    except Exception as e:
        logger.error(f"Error fetching statistics: {str(e)}")
        statistics_data = [
            {"label": "Total User Websites", "value": "Error", "url": ""},
            {"label": "Published Websites", "value": "Error", "url": ""}
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
                logger.debug(f"Raw ds_actor cookie before unsigning: {ds_actor_cookie}")
                logger.debug(f"Attempting to unsign ds_actor cookie: {ds_actor_cookie}")
                actor = datasette.unsign(ds_actor_cookie, "actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
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
            redirect_url = "/system-admin" if actor.get("role") == "system_admin" else "/dashboard"
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
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}
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
                logger.debug(f"User found: user_id={user['user_id']}, username={user['username']}, role={user['role']}, password_hash={user['password_hash']}")
                try:
                    if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                        logger.debug(f"Login successful for user: {username}, role: {user['role']}")
                        redirect_url = "/system-admin" if user["role"] == "system_admin" else "/dashboard"
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
    content = {'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}}

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"Register POST vars: {post_vars}")
        username = post_vars.get("username")
        password = post_vars.get("password")
        email = post_vars.get("email")
        role = post_vars.get("role")
        invite_code = post_vars.get("invite_code")
        if not username or not password or not email or not role or not invite_code:
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Username, password, email, role, and invite code are required"
                    },
                    request=request
                )
            )
        try:
            db = datasette.get_database("portal")
            result = await db.execute("SELECT inviter_id FROM invites WHERE code = ? AND used_by IS NULL", [invite_code])
            invite = result.first()
            if not invite:
                return Response.html(
                    await datasette.render_template(
                        "register.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Invalid or used invite code"
                        },
                        request=request
                    )
                )
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
                "UPDATE invites SET used_by = ?, used_at = ? WHERE code = ?",
                [user_id, datetime.utcnow(), invite_code]
            )
            await db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), user_id, "register", f"User {username} registered with invite code {invite_code}", datetime.utcnow()]
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
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}
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
            response = Response.redirect("/dashboard?success=Profile updated successfully")
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
                logger.debug(f"Attempting to unsign ds_actor cookie: {ds_actor_cookie}")
                actor = datasette.unsign(ds_actor_cookie, "actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning(f"Unauthorized dashboard access attempt: actor=None")
        return Response.redirect("/login")

    # Verify user exists in database
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
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}
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
                logger.debug(f"Raw ds_actor cookie before unsigning: {ds_actor_cookie}")
                logger.debug(f"Attempting to unsign ds_actor cookie: {ds_actor_cookie}")
                actor = datasette.unsign(ds_actor_cookie, "actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
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

    # Verify user exists in database and has system_admin role
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
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}
    }

    try:
        users = await db.execute("SELECT user_id, username, email, role, created_at FROM users")
        users_list = [dict(row) for row in users]
        invites = await db.execute("SELECT i.code, i.inviter_id, i.used_by, i.created_at, u.username AS inviter_username, u2.username AS used_by_username FROM invites i LEFT JOIN users u ON i.inviter_id = u.user_id LEFT JOIN users u2 ON i.used_by = u2.user_id")
        invites_list = [dict(row) for row in invites]
        requests = await db.execute("SELECT pr.request_id, pr.db_id, pr.user_id, pr.status, pr.submitted_at, pr.feedback, d.db_name, u.username FROM publish_requests pr JOIN databases d ON pr.db_id = d.db_id JOIN users u ON pr.user_id = u.user_id")
        requests_list = [dict(row) for row in requests]
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
                    'invites': [],
                    'publish_requests': [],
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
                'invites': invites_list,
                'publish_requests': requests_list,
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
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
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
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}
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
                return Response.redirect("/dashboard?success=Password changed successfully")
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
                logger.debug(f"Raw ds_actor cookie before unsigning: {ds_actor_cookie}")
                logger.debug(f"Attempting to unsign ds_actor cookie: {ds_actor_cookie}")
                actor = datasette.unsign(ds_actor_cookie, "actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

    if not actor:
        logger.warning(f"Unauthorized create database attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user exists in database
    db = datasette.get_database('portal')
    try:
        result = await db.execute("SELECT user_id, username FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
    except Exception as e:
        logger.error(f"Error verifying user in create_database: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'header_image': {'image_url': '', 'alt_text': '', 'credit_url': '', 'credit_text': ''},
        'description': {'content': ''},
        'footer': {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': ['Made with EDGI']},
        'tags': {'content': []}
    }

    if request.method == "POST":
        logger.debug(f"POST request headers: {dict(request.scope.get('headers', []))}")
        logger.debug(f"POST request body: {await request.post_body()}")
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
            description = forms.get('description', [''])[0].strip()
            tags = forms.get('tags', [''])[0].strip().split(',')
            header_image_file = files.get('header_image')
            logger.debug(f"Create database: db_name={db_name}, files={files}, description={description}, tags={tags}, header_image_file={header_image_file}")

            if not db_name or not files.get('dataset'):
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "Database name and dataset file are required"
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

            if header_image_file and len(header_image_file['content']) > 5 * 1024 * 1024:  # 5MB limit
                logger.error("Header image exceeds 5MB limit")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "Header image exceeds 5MB limit"
                        },
                        request=request
                    )
                )

            ext = Path(file['filename']).suffix.lower()
            if ext not in {'.csv', '.db'}:
                logger.error(f"Invalid file extension: {ext}")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "Only .csv and .db files allowed"
                        },
                        request=request
                    )
                )

            username = actor.get("username")
            user_id = actor.get("id")
            result = await db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ?", [user_id])
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
            db_path = f"/data/{username}/{db_name}.db"
            website_url = f"{username}-{db_name}.datasette-portal.fly.dev"

            # Ensure directory exists and is writable
            try:
                os.makedirs(f"/data/{username}", exist_ok=True)
                # Verify write permission
                with open(db_path, 'a') as f:
                    pass
            except PermissionError as e:
                logger.error(f"Permission denied creating database at {db_path}: {str(e)}")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": f"Permission denied creating database: {str(e)}"
                        },
                        request=request
                    )
                )
            except Exception as e:
                logger.error(f"Error creating directory or file at {db_path}: {str(e)}")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": f"Error creating database: {str(e)}"
                        },
                        request=request
                    )
                )

            if ext == '.csv':
                db_file = sqlite_utils.Database(db_path)
                # Read CSV to determine columns
                df = pd.read_csv(io.BytesIO(file['content']))
                columns = {col: str for col in df.columns}  # Treat all columns as TEXT for simplicity
                # Create or update measurements table with dynamic columns
                if "measurements" not in db_file.table_names():
                    db_file.create_table("measurements", columns)
                else:
                    existing_columns = set(db_file["measurements"].columns_dict.keys())
                    for col in df.columns:
                        if col not in existing_columns:
                            db_file["measurements"].add_column(col, str)
                db_file["measurements"].insert_all(
                    df.to_dict('records'),
                    ignore=True
                )
                # Create or update admin_content table
                if "admin_content" not in db_file.table_names():
                    db_file.create_table("admin_content", {
                        "section": str,
                        "content": str,
                        "updated_at": str,
                        "updated_by": str
                    }, pk="section")
                db_file["admin_content"].upsert({
                    "section": "title",
                    "content": json.dumps({"content": db_name}),
                    "updated_at": datetime.utcnow().isoformat(),
                    "updated_by": username
                }, pk="section")
                db_file["admin_content"].upsert({
                    "section": "description",
                    "content": json.dumps({"content": description}),
                    "updated_at": datetime.utcnow().isoformat(),
                    "updated_by": username
                }, pk="section")
                db_file["admin_content"].upsert({
                    "section": "tags",
                    "content": json.dumps({"content": [tag.strip() for tag in tags if tag.strip()]}),
                    "updated_at": datetime.utcnow().isoformat(),
                    "updated_by": username
                }, pk="section")
                if header_image_file:
                    image_path = f"/data/{username}/{db_name}_header.jpg"
                    with open(image_path, 'wb') as f:
                        f.write(header_image_file['content'])
                    db_file["admin_content"].upsert({
                        "section": "header_image",
                        "content": json.dumps({
                            "image_url": f"/data/{username}/{db_name}_header.jpg",
                            "alt_text": forms.get('alt_text', [''])[0],
                            "credit_url": forms.get('credit_url', [''])[0],
                            "credit_text": forms.get('credit_text', [''])[0]
                        }),
                        "updated_at": datetime.utcnow().isoformat(),
                        "updated_by": username
                    }, pk="section")
                db_file["admin_content"].upsert({
                    "section": "footer",
                    "content": json.dumps({"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}),
                    "updated_at": datetime.utcnow().isoformat(),
                    "updated_by": username
                }, pk="section")
            else:
                with open(db_path, 'wb') as f:
                    f.write(file['content'])
                db_file = sqlite_utils.Database(db_path)
                if "admin_content" not in db_file.table_names():
                    db_file.create_table("admin_content", {
                        "section": str,
                        "content": str,
                        "updated_at": str,
                        "updated_by": str
                    }, pk="section")
                    db_file["admin_content"].insert({
                        "section": "title",
                        "content": json.dumps({"content": db_name}),
                        "updated_at": datetime.utcnow().isoformat(),
                        "updated_by": username
                    })
                    db_file["admin_content"].insert({
                        "section": "description",
                        "content": json.dumps({"content": description}),
                        "updated_at": datetime.utcnow().isoformat(),
                        "updated_by": username
                    })
                    db_file["admin_content"].insert({
                        "section": "tags",
                        "content": json.dumps({"content": [tag.strip() for tag in tags if tag.strip()]}),
                        "updated_at": datetime.utcnow().isoformat(),
                        "updated_by": username
                    })
                    if header_image_file:
                        image_path = f"/data/{username}/{db_name}_header.jpg"
                        with open(image_path, 'wb') as f:
                            f.write(header_image_file['content'])
                        db_file["admin_content"].insert({
                            "section": "header_image",
                            "content": json.dumps({
                                "image_url": f"/data/{username}/{db_name}_header.jpg",
                                "alt_text": forms.get('alt_text', [''])[0],
                                "credit_url": forms.get('credit_url', [''])[0],
                                "credit_text": forms.get('credit_text', [''])[0]
                            }),
                            "updated_at": datetime.utcnow().isoformat(),
                            "updated_by": username
                        })
                    db_file["admin_content"].insert({
                        "section": "footer",
                        "content": json.dumps({"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": ["Made with EDGI"]}),
                        "updated_at": datetime.utcnow().isoformat(),
                        "updated_by": username
                    })

            portal_db = datasette.get_database("portal")
            await portal_db.execute_write(
                "INSERT INTO databases (db_id, user_id, db_name, db_path, website_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [db_id, user_id, db_name, db_path, website_url, "Draft", datetime.utcnow()]
            )
            await portal_db.execute_write(
                "INSERT INTO user_database_roles (user_id, db_id, role, assigned_at) VALUES (?, ?, ?, ?)",
                [user_id, db_id, "admin", datetime.utcnow()]
            )
            await db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), user_id, "create_database", f"Created database {db_name}", datetime.utcnow()]
            )

            logger.debug(f"Database created: {db_path}, website_url={website_url}")
            return Response.redirect("/dashboard?success=Database created successfully")
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
        logger.error("Missing db_id in template_page request")
        return Response.redirect("/dashboard?error=Invalid database ID")

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
                logger.debug(f"Raw ds_actor cookie before unsigning: {ds_actor_cookie}")
                logger.debug(f"Attempting to unsign ds_actor cookie: {ds_actor_cookie}")
                actor = datasette.unsign(ds_actor_cookie, "actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                response = Response.redirect("/login?error=Session expired or invalid")
                response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
                return response

    if not actor:
        logger.warning(f"Unauthorized template access attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user exists in database
    portal_db = datasette.get_database('portal')
    try:
        result = await portal_db.execute("SELECT user_id, username FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
    except Exception as e:
        logger.error(f"Error verifying user in template_page: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    result = await portal_db.execute("SELECT db_path, db_name, status FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        logger.error(f"Invalid or unauthorized database: db_id={db_id}, user_id={actor.get('id')}")
        return Response.redirect("/dashboard?error=Invalid or unauthorized database")

    db_path = db_info["db_path"]
    db_name = db_info["db_name"]
    db_status = db_info["status"]

    try:
        db = sqlite_utils.Database(db_path)
        sections = await db.execute('SELECT section, content FROM admin_content')
        content = {row['section']: json.loads(row['content']) for row in sections}
    except Exception as e:
        logger.error(f"Error loading database content for db_id={db_id}: {str(e)}")
        return Response.redirect("/dashboard?error=Error loading database content")

    if 'title' not in content:
        content['title'] = {'content': db_name}
    if 'header_image' not in content:
        content['header_image'] = {'image_url': '/static/header.jpg', 'alt_text': '', 'credit_url': '', 'credit_text': ''}
    if 'info' not in content:
        content['info'] = {'content': f'About {db_name}', 'paragraphs': parse_markdown_links(f'About {db_name}')}
    if 'feature_cards' not in content:
        content['feature_cards'] = []
    if 'statistics' not in content:
        content['statistics'] = []
    if 'footer' not in content:
        content['footer'] = {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': parse_markdown_links('Made with EDGI')}
    if 'description' not in content:
        content['description'] = {'content': ''}
    if 'icon' not in content:
        content['icon'] = {'content': 'ri-table-line'}
    if 'tags' not in content:
        content['tags'] = {'content': []}

    if 'info' in content and 'content' in content['info'] and 'paragraphs' not in content['info']:
        content['info']['paragraphs'] = parse_markdown_links(content['info']['content'])
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
                'success': request.args.get('success'),
                'error': request.args.get('error')
            },
            request=request
        )
    )

async def publish_request(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Publish Request Cookies: {cookies}")

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

    if not actor:
        logger.warning(f"Unauthorized publish request attempt: actor={actor}")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    post_vars = await request.post_vars()
    db_id = post_vars.get("db_id")
    if not db_id:
        return Response.redirect("/dashboard?error=Missing database ID")

    result = await db.execute("SELECT db_name, db_path, status FROM databases WHERE db_id = ? AND user_id = ?", [db_id, actor.get("id")])
    db_info = result.first()
    if not db_info:
        return Response.redirect("/dashboard?error=Invalid or unauthorized database")
    if db_info["status"] in ["Pending", "Published"]:
        return Response.redirect(f"/template/{db_id}?error=Database already submitted or published")

    try:
        await db.execute_write(
            "INSERT INTO publish_requests (request_id, db_id, user_id, status, submitted_at) VALUES (?, ?, ?, ?, ?)",
            [str(uuid.uuid4()), db_id, actor.get("id"), "Pending", datetime.utcnow()]
        )
        await db.execute_write(
            "UPDATE databases SET status = 'Pending' WHERE db_id = ?",
            [db_id]
        )
        await db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [str(uuid.uuid4()), actor.get("id"), "publish_request", f"Submitted publish request for {db_info['db_name']}", datetime.utcnow()]
        )
        logger.debug(f"Publish request submitted for db_id: {db_id}")
        return Response.redirect(f"/template/{db_id}?success=Publish request submitted")
    except Exception as e:
        logger.error(f"Publish request error: {str(e)}")
        return Response.redirect(f"/template/{db_id}?error=Publish request error: {str(e)}")

async def invite_user(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Invite User Cookies: {cookies}")
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
                logger.debug(f"Raw ds_actor cookie before unsigning: {ds_actor_cookie}")
                logger.debug(f"Attempting to unsign ds_actor cookie: {ds_actor_cookie}")
                actor = datasette.unsign(ds_actor_cookie, "actor")
                logger.debug(f"Parsed and unsigned actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except Exception as e:
                logger.error(f"Failed to unsign ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                return Response.redirect("/login?error=Session expired or invalid")
    if not actor or actor.get("role") != "system_admin":
        logger.warning(f"Unauthorized invite attempt: actor={actor}")
        return Response.redirect("/login?error=Unauthorized access")

    db = datasette.get_database('portal')
    if request.method == "POST":
        post_vars = await request.post_vars()
        email = post_vars.get("email")
        if not email:
            template = "system_admin.html" if actor.get("role") == "system_admin" else "dashboard.html"
            extra_context = {}
            if template == "dashboard.html":
                result = await db.execute("SELECT db_id, db_name, website_url, status FROM databases WHERE user_id = ?", [actor.get("id")])
                extra_context["user_databases"] = [{"db_id": row["db_id"], "db_name": row["db_name"], "website_url": row["website_url"], "status": row["status"]} for row in result]
                user_result = await db.execute("SELECT user_id, username, email FROM users WHERE user_id = ?", [actor.get("id")])
                extra_context["user_info"] = dict(user_result.first()) if user_result.first() else {}
            elif template == "system_admin.html":
                users = await db.execute("SELECT user_id, username, email, role, created_at FROM users")
                extra_context["users"] = [dict(row) for row in users]
                invites = await db.execute("SELECT i.code, i.inviter_id, i.used_by, i.created_at, u.username AS inviter_username, u2.username AS used_by_username FROM invites i LEFT JOIN users u ON i.inviter_id = u.user_id LEFT JOIN users u2 ON i.used_by = u2.user_id")
                extra_context["invites"] = [dict(row) for row in invites]
                requests = await db.execute("SELECT pr.request_id, pr.db_id, pr.user_id, pr.status, pr.submitted_at, pr.feedback, d.db_name, u.username FROM publish_requests pr JOIN databases d ON pr.db_id = d.db_id JOIN users u ON pr.user_id = u.user_id")
                extra_context["publish_requests"] = [dict(row) for row in requests]
                logs = await db.execute("SELECT log_id, user_id, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC LIMIT 100")
                extra_context["activity_logs"] = [dict(row) for row in logs]
            return Response.html(
                await datasette.render_template(
                    template,
                    {
                        "metadata": datasette.metadata(),
                        "content": {'title': {'content': 'EDGI Datasette Cloud Portal'}},
                        "actor": actor,
                        "error": "Email is required",
                        **extra_context
                    },
                    request=request
                )
            )
        try:
            invite_code = str(uuid.uuid4())
            await db.execute_write(
                "INSERT INTO invites (code, inviter_id, email, created_at) VALUES (?, ?, ?, ?)",
                [invite_code, actor.get("id"), email, datetime.utcnow()]
            )
            await db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), actor.get("id"), "invite_user", f"Invited user with email {email} and code {invite_code}", datetime.utcnow()]
            )
            logger.debug(f"Invite sent to {email} with code {invite_code}")
            redirect_url = "/system-admin" if actor.get("role") == "system_admin" else "/dashboard"
            return Response.redirect(f"{redirect_url}?success=Invite code {invite_code} sent to {email}")
        except Exception as e:
            logger.error(f"Invite error: {str(e)}")
            template = "system_admin.html" if actor.get("role") == "system_admin" else "dashboard.html"
            extra_context = {}
            if template == "dashboard.html":
                result = await db.execute("SELECT db_id, db_name, website_url, status FROM databases WHERE user_id = ?", [actor.get("id")])
                extra_context["user_databases"] = [{"db_id": row["db_id"], "db_name": row["db_name"], "website_url": row["website_url"], "status": row["status"]} for row in result]
                user_result = await db.execute("SELECT user_id, username, email FROM users WHERE user_id = ?", [actor.get("id")])
                extra_context["user_info"] = dict(user_result.first()) if user_result.first() else {}
            elif template == "system_admin.html":
                users = await db.execute("SELECT user_id, username, email, role, created_at FROM users")
                extra_context["users"] = [dict(row) for row in users]
                invites = await db.execute("SELECT i.code, i.inviter_id, i.used_by, i.created_at, u.username AS inviter_username, u2.username AS used_by_username FROM invites i LEFT JOIN users u ON i.inviter_id = u.user_id LEFT JOIN users u2 ON i.used_by = u2.user_id")
                extra_context["invites"] = [dict(row) for row in invites]
                requests = await db.execute("SELECT pr.request_id, pr.db_id, pr.user_id, pr.status, pr.submitted_at, pr.feedback, d.db_name, u.username FROM publish_requests pr JOIN databases d ON pr.db_id = d.db_id JOIN users u ON pr.user_id = u.user_id")
                extra_context["publish_requests"] = [dict(row) for row in requests]
                logs = await db.execute("SELECT log_id, user_id, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC LIMIT 100")
                extra_context["activity_logs"] = [dict(row) for row in logs]
            return Response.html(
                await datasette.render_template(
                    template,
                    {
                        "metadata": datasette.metadata(),
                        "content": {'title': {'content': 'EDGI Datasette Cloud Portal'}},
                        "actor": actor,
                        "error": f"Invite error: {str(e)}",
                        **extra_context
                    },
                    request=request
                )
            )

    redirect_url = "/system-admin" if actor.get("role") == "system_admin" else "/dashboard"
    return Response.redirect(redirect_url)

async def manage_publish_request(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Manage Publish Request Cookies: {cookies}")

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

    if not actor or actor.get("role") != "system_admin":
        logger.warning(f"Unauthorized manage publish request attempt: actor={actor}")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    post_vars = await request.post_vars()
    request_id = post_vars.get("request_id")
    action = post_vars.get("action")
    feedback = post_vars.get("feedback", "")

    if not request_id or action not in ["approve", "reject"]:
        return Response.redirect("/system-admin?error=Invalid request or action")

    try:
        result = await db.execute("SELECT db_id FROM publish_requests WHERE request_id = ?", [request_id])
        request_info = result.first()
        if not request_info:
            return Response.redirect("/system-admin?error=Invalid publish request")
        db_id = request_info["db_id"]
        status = "Published" if action == "approve" else "Rejected"
        await db.execute_write(
            "UPDATE publish_requests SET status = ?, feedback = ?, updated_at = ? WHERE request_id = ?",
            [status, feedback, datetime.utcnow(), request_id]
        )
        await db.execute_write(
            "UPDATE databases SET status = ? WHERE db_id = ?",
            [status, db_id]
        )
        await db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [
                str(uuid.uuid4()),
                actor.get("id"),
                f"{action}_publish_request",
                f"{action.capitalize()}d publish request {request_id} with feedback: {feedback}",
                datetime.utcnow()
            ]
        )
        logger.debug(f"Publish request {request_id} {action}d")
        return Response.redirect(f"/system-admin?success=Publish request {action}d")
    except Exception as e:
        logger.error(f"Manage publish request error: {str(e)}")
        return Response.redirect(f"/system-admin?error=Manage publish request error: {str(e)}")

async def update_content(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Update Content Cookies: {cookies}")

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

    if not actor or actor.get("role") != "system_admin":
        logger.warning(f"Unauthorized update content attempt: actor={actor}")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
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
            
            section = forms.get('section', [''])[0].strip()
            content_data = forms.get('content', [''])[0].strip()
            if not section or not content_data:
                return Response.redirect("/system-admin?error=Missing section or content")

            try:
                json.loads(content_data)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON for section {section}: {str(e)}")
                return Response.redirect(f"/system-admin?error=Invalid JSON content: {str(e)}")

            await db.execute_write(
                "INSERT OR REPLACE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                [section, content_data, datetime.utcnow().isoformat(), actor.get("username")]
            )
            await db.execute_write(
                "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                [str(uuid.uuid4()), actor.get("id"), "update_content", f"Updated content for section {section}", datetime.utcnow()]
            )
            logger.debug(f"Content updated for section: {section}")
            return Response.redirect("/system-admin?success=Content updated successfully")
        except Exception as e:
            logger.error(f"Update content error: {str(e)}")
            return Response.redirect(f"/system-admin?error=Update content error: {str(e)}")

    return Response.redirect("/system-admin")

@hookimpl
def register_routes():
    return [
        (r"^/$", index_page),
        (r"^/dashboard$", dashboard_page),
        (r"^/login$", login_page),
        (r"^/register$", register_page),
        (r"^/change-password$", change_password_page),
        (r"^/profile$", profile_page),
        (r"^/logout$", logout_page),
        (r"^/template/(?P<db_id>[^/]+)$", template_page),
        (r"^/publish-request$", publish_request),
        (r"^/system-admin$", system_admin_page),
        (r"^/invite-user$", invite_user),
        (r"^/manage-publish-request$", manage_publish_request),
        (r"^/admin/update$", update_content),
        (r"^/create-database$", create_database),
    ]

@hookimpl
def asgi_wrapper(datasette):
    def wrap_with_cookie_debugger(app):
        return CookieDebugger(app)
    return wrap_with_cookie_debugger

@hookimpl
def startup(datasette):
    async def init():
        db = datasette.get_database("portal")
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT CHECK(role IN ('system_admin', 'system_user')),
                email TEXT,
                created_at TIMESTAMP
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS databases (
                db_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                db_name TEXT NOT NULL,
                db_path TEXT NOT NULL,
                website_url TEXT,
                status TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS user_database_roles (
                user_id TEXT NOT NULL,
                db_id TEXT NOT NULL,
                role TEXT NOT NULL,
                assigned_at DATETIME NOT NULL,
                PRIMARY KEY (user_id, db_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (db_id) REFERENCES databases(db_id)
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS invites (
                code TEXT PRIMARY KEY,
                inviter_id TEXT NOT NULL,
                email TEXT NOT NULL,
                used_by TEXT,
                created_at DATETIME NOT NULL,
                used_at DATETIME,
                FOREIGN KEY (inviter_id) REFERENCES users(user_id),
                FOREIGN KEY (used_by) REFERENCES users(user_id)
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS publish_requests (
                request_id TEXT PRIMARY KEY,
                db_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                status TEXT NOT NULL,
                submitted_at DATETIME NOT NULL,
                feedback TEXT,
                updated_at DATETIME,
                FOREIGN KEY (db_id) REFERENCES databases(db_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                log_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                timestamp DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS admin_content (
                section TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                updated_at DATETIME NOT NULL,
                updated_by TEXT
            )
        """)
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["title", json.dumps({"content": "EDGI Datasette Cloud Portal"}), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["header_image", json.dumps({"image_url": "/static/header.jpg", "alt_text": "", "credit_url": "", "credit_text": ""}), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["info", json.dumps({"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.", "paragraphs": parse_markdown_links("The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.")}), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["feature_cards", json.dumps([]), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["statistics", json.dumps([]), datetime.utcnow().isoformat(), "system"]
        )

    return init