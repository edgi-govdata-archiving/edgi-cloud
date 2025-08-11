"""
User Profile Module - User authentication and profile management
Handles: Login, registration, profile editing, password changes, logout
"""

import json
import bcrypt
import logging
import uuid
import os
import base64
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
import bleach
import re

# Configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def sanitize_text(text):
    """Sanitize text by stripping HTML tags while preserving safe characters."""
    return bleach.clean(text, tags=[], strip=True)

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

async def get_user_statistics(datasette, user_id):
    """Get user-specific statistics."""
    try:
        db = datasette.get_database("portal")
        
        stats = {
            'user_databases': 0,
            'user_published': 0,
            'user_trashed': 0
        }
        
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
        
        return stats
        
    except Exception as e:
        logger.error(f"Error fetching user statistics: {str(e)}")
        return {'user_databases': 0, 'user_published': 0, 'user_trashed': 0}

async def login_page(datasette, request):
    """User login page and authentication."""
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
        post_vars = await request.post_vars()
        username = post_vars.get("username")
        password = post_vars.get("password")
        
        if not username or not password:
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
            if user and bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                redirect_url = "/system-admin" if user["role"] == "system_admin" else "/manage-databases"
                actor_data = {"id": user["user_id"], "name": f"User {username}", "role": user["role"], "username": username}
                
                # Log successful login
                await log_user_activity(
                    datasette, user["user_id"], "login", 
                    f"User {username} logged in",
                    {"username": username, "role": user["role"]}
                )
                
                response = Response.redirect(redirect_url)
                set_actor_cookie(response, datasette, actor_data)
                return response
            else:
                # Log failed login attempt
                await log_user_activity(
                    datasette, "anonymous", "login_failed", 
                    f"Failed login attempt for username: {username}",
                    {"username": username, "ip": request.headers.get('x-forwarded-for', 'unknown')}
                )
                
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

    # GET request - show login form
    return Response.html(
        await datasette.render_template(
            "login.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
            },
            request=request
        )
    )

async def register_page(datasette, request):
    """User registration page."""
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
                        "actor": actor,
                        "is_admin": is_admin,
                        "available_roles": available_roles
                    },
                    request=request
                )
            )
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Username must be 3-20 characters long and contain only letters, numbers, and underscores",
                        "actor": actor,
                        "is_admin": is_admin,
                        "available_roles": available_roles
                    },
                    request=request
                )
            )
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Please enter a valid email address",
                        "actor": actor,
                        "is_admin": is_admin,
                        "available_roles": available_roles
                    },
                    request=request
                )
            )
        
        # Validate password strength
        if len(password) < 6:
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Password must be at least 6 characters long",
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
            
            await log_user_activity(
                datasette, user_id, "register", 
                f"User {username} registered with role {role}",
                {"username": username, "role": role, "email": email}
            )
            
            # Log who created the user (if admin is creating)
            if is_admin:
                await log_user_activity(
                    datasette, actor.get("id"), "create_user", 
                    f"Admin {actor.get('username')} created user {username} with role {role}",
                    {"created_username": username, "created_role": role}
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
                "is_admin": is_admin,
                "available_roles": available_roles
            },
            request=request
        )
    )

async def logout_page(datasette, request):
    """User logout."""
    logger.debug(f"Logout request: method={request.method}")
    
    actor = get_actor_from_request(request)
    if actor:
        await log_user_activity(
            datasette, actor.get("id"), "logout", 
            f"User {actor.get('username')} logged out"
        )
    
    response = Response.redirect("/")
    response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
    logger.debug("Cleared ds_actor cookie")
    return response

async def profile_page(datasette, request):
    """User profile management page."""
    logger.debug(f"Profile request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized profile attempt: actor={actor}")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    
    # Get user details
    try:
        result = await db.execute("SELECT user_id, username, email, role, created_at FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            logger.error(f"No user found for user_id: {actor.get('id')}")
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
    except Exception as e:
        logger.error(f"Error getting user profile: {str(e)}")
        return Response.redirect("/login?error=Profile error")

    title = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }

    if request.method == "POST":
        post_vars = await request.post_vars()
        action = post_vars.get("action")
        
        if action == "change_password":
            current_password = post_vars.get("current_password")
            new_password = post_vars.get("new_password")
            confirm_password = post_vars.get("confirm_password")
            
            if not current_password or not new_password or new_password != confirm_password:
                return Response.html(
                    await datasette.render_template(
                        "profile.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "user": dict(user),
                            "actor": actor,
                            "stats": await get_user_statistics(datasette, actor.get("id")),
                            "error": "All fields are required and new passwords must match"
                        },
                        request=request
                    )
                )
            
            # Validate new password strength
            if len(new_password) < 6:
                return Response.html(
                    await datasette.render_template(
                        "profile.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "user": dict(user),
                            "actor": actor,
                            "stats": await get_user_statistics(datasette, actor.get("id")),
                            "error": "New password must be at least 6 characters long"
                        },
                        request=request
                    )
                )
            
            try:
                # Get current password hash
                password_result = await db.execute("SELECT password_hash FROM users WHERE user_id = ?", [actor.get("id")])
                password_row = password_result.first()
                
                # Verify current password
                if not password_row or not bcrypt.checkpw(current_password.encode('utf-8'), password_row["password_hash"].encode('utf-8')):
                    return Response.html(
                        await datasette.render_template(
                            "profile.html",
                            {
                                "metadata": datasette.metadata(),
                                "content": content,
                                "user": dict(user),
                                "actor": actor,
                                "stats": await get_user_statistics(datasette, actor.get("id")),
                                "error": "Current password is incorrect"
                            },
                            request=request
                        )
                    )
                
                # Update password
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                await db.execute_write(
                    "UPDATE users SET password_hash = ? WHERE user_id = ?",
                    [hashed_password, actor.get("id")]
                )
                
                await log_user_activity(
                    datasette, actor.get("id"), "change_password", 
                    f"User {actor.get('username')} changed password"
                )
                
                return Response.redirect("/profile?success=Password changed successfully")
                
            except Exception as e:
                logger.error(f"Password change error: {str(e)}")
                return Response.html(
                    await datasette.render_template(
                        "profile.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "user": dict(user),
                            "actor": actor,
                            "stats": await get_user_statistics(datasette, actor.get("id")),
                            "error": f"Password change failed: {str(e)}"
                        },
                        request=request
                    )
                )
        
        elif action == "update_email":
            new_email = post_vars.get("new_email")
            
            if not new_email:
                return Response.html(
                    await datasette.render_template(
                        "profile.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "user": dict(user),
                            "actor": actor,
                            "stats": await get_user_statistics(datasette, actor.get("id")),
                            "error": "Email is required"
                        },
                        request=request
                    )
                )
            
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, new_email):
                return Response.html(
                    await datasette.render_template(
                        "profile.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "user": dict(user),
                            "actor": actor,
                            "stats": await get_user_statistics(datasette, actor.get("id")),
                            "error": "Please enter a valid email address"
                        },
                        request=request
                    )
                )
            
            try:
                # Check if email already exists
                existing_email = await db.execute("SELECT user_id FROM users WHERE email = ? AND user_id != ?", [new_email, actor.get("id")])
                if existing_email.first():
                    return Response.html(
                        await datasette.render_template(
                            "profile.html",
                            {
                                "metadata": datasette.metadata(),
                                "content": content,
                                "user": dict(user),
                                "actor": actor,
                                "stats": await get_user_statistics(datasette, actor.get("id")),
                                "error": "Email already in use by another account"
                            },
                            request=request
                        )
                    )
                
                # Update email
                await db.execute_write(
                    "UPDATE users SET email = ? WHERE user_id = ?",
                    [new_email, actor.get("id")]
                )
                
                await log_user_activity(
                    datasette, actor.get("id"), "update_email", 
                    f"User {actor.get('username')} updated email from {user['email']} to {new_email}",
                    {"old_email": user['email'], "new_email": new_email}
                )
                
                return Response.redirect("/profile?success=Email updated successfully")
                
            except Exception as e:
                logger.error(f"Email update error: {str(e)}")
                return Response.html(
                    await datasette.render_template(
                        "profile.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "user": dict(user),
                            "actor": actor,
                            "stats": await get_user_statistics(datasette, actor.get("id")),
                            "error": f"Email update failed: {str(e)}"
                        },
                        request=request
                    )
                )
    
    # GET request - show profile page
    return Response.html(
        await datasette.render_template(
            "profile.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "user": dict(user),
                "actor": actor,
                "stats": await get_user_statistics(datasette, actor.get("id")),
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def forgot_password_page(datasette, request):
    """Forgot password page (placeholder for future implementation)."""
    logger.debug(f"Forgot Password request: method={request.method}")
    
    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'}
    }
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        email = post_vars.get("email")
        
        if not email:
            return Response.html(
                await datasette.render_template(
                    "forgot_password.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Email address is required"
                    },
                    request=request
                )
            )
        
        # TODO: Implement actual password reset functionality
        # For now, just show a success message
        await log_user_activity(
            datasette, "anonymous", "password_reset_request", 
            f"Password reset requested for email: {email}",
            {"email": email, "ip": request.headers.get('x-forwarded-for', 'unknown')}
        )
        
        return Response.html(
            await datasette.render_template(
                "forgot_password.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "success": "If an account with this email exists, you will receive password reset instructions."
                },
                request=request
            )
        )
    
    # GET request - show forgot password form
    return Response.html(
        await datasette.render_template(
            "forgot_password.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
            },
            request=request
        )
    )

@hookimpl
def register_routes():
    """Register user profile and authentication routes."""
    return [
        (r"^/login$", login_page),
        (r"^/register$", register_page),
        (r"^/logout$", logout_page),
        (r"^/profile$", profile_page),
        (r"^/forgot-password$", forgot_password_page),
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
def startup(datasette):
    """User Profile module startup."""
    
    async def inner():
        try:
            logger.info("👤 Starting User Profile Module...")
            
            # Get database path
            db_path = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
            
            # Check if portal database exists
            if not os.path.exists(db_path):
                logger.error(f"Portal database not found at: {db_path}")
                logger.error("Run init_db.py first to create the database")
                return
            
            logger.info(f"Using portal database: {db_path}")
            
            logger.info("User Profile Module startup completed successfully")
            
        except Exception as e:
            logger.error(f"User Profile Module startup failed: {str(e)}")

    return inner