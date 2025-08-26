"""
User Profile Module - User authentication and profile management
Handles: Login, registration, profile editing, password changes, logout
"""

import json
import bcrypt
import logging
import uuid
import os
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response

# Add the plugins directory to Python path for imports
import sys
PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGINS_DIR not in sys.path:
    sys.path.insert(0, PLUGINS_DIR)
ROOT_DIR = os.path.dirname(PLUGINS_DIR)

# Import from common_utils
from common_utils import (
    get_actor_from_request,
    set_actor_cookie,
    log_user_activity,
    verify_user_session,
    get_portal_content,
    handle_form_errors,
    get_success_error_from_request,
    validate_email,
    validate_username,
    validate_password,
    DATA_DIR,
)

# Configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

    # Get content for template
    content = await get_portal_content(datasette)
    actor = get_actor_from_request(request)

    if request.method == "POST":
        post_vars = await request.post_vars()
        username = post_vars.get("username")
        password = post_vars.get("password")
        
        if not username or not password:
            return await handle_form_errors(
                datasette, "login.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                },
                request, "Username and password are required"
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
                
                return await handle_form_errors(
                    datasette, "login.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                    },
                    request, "Invalid username or password"
                )
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return await handle_form_errors(
                datasette, "login.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                },
                request, f"Login error: {str(e)}"
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
    content = await get_portal_content(datasette)

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
        
        template_data = {
            "metadata": datasette.metadata(),
            "content": content,
            "actor": actor,
            "is_admin": is_admin,
            "available_roles": available_roles
        }
        
        if not username or not password or not email or not role:
            return await handle_form_errors(
                datasette, "register.html", template_data,
                request, "Username, password, email, and role are required"
            )
        
        # Role validation based on who is registering
        if role not in available_roles:
            error_msg = "Invalid role selected"
            if role == "system_admin" and not is_admin:
                error_msg = "Only system administrators can create admin accounts"
            
            return await handle_form_errors(
                datasette, "register.html", template_data,
                request, error_msg
            )
        
        # Validate username format
        is_valid_username, username_error = validate_username(username)
        if not is_valid_username:
            return await handle_form_errors(
                datasette, "register.html", template_data,
                request, username_error
            )
        
        # Validate email format
        is_valid_email, email_error = validate_email(email)
        if not is_valid_email:
            return await handle_form_errors(
                datasette, "register.html", template_data,
                request, email_error
            )
        
        # Validate password strength
        is_valid_password, password_error = validate_password(password)
        if not is_valid_password:
            return await handle_form_errors(
                datasette, "register.html", template_data,
                request, password_error
            )
        
        try:
            db = datasette.get_database("portal")
            
            # Check if username already exists
            existing_user = await db.execute("SELECT username FROM users WHERE username = ?", [username])
            if existing_user.first():
                return await handle_form_errors(
                    datasette, "register.html", template_data,
                    request, "Username already exists. Please choose a different username."
                )
            
            # Check if email already exists
            existing_email = await db.execute("SELECT email FROM users WHERE email = ?", [email])
            if existing_email.first():
                return await handle_form_errors(
                    datasette, "register.html", template_data,
                    request, "Email already registered. Please use a different email address."
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
            return await handle_form_errors(
                datasette, "register.html", template_data,
                request, f"Registration error: {str(e)}"
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
    """Enhanced user profile management page with improved UX."""
    logger.debug(f"Profile request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized profile attempt: actor={actor}")
        return Response.redirect("/login")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    content = await get_portal_content(datasette)
    db = datasette.get_database('portal')

    if request.method == "POST":
        post_vars = await request.post_vars()
        action = post_vars.get("action")
        
        template_data = {
            "metadata": datasette.metadata(),
            "content": content,
            "user": user_data,
            "actor": actor,
            "stats": await get_user_statistics(datasette, actor.get("id"))
        }
        
        if action == "change_password":
            current_password = post_vars.get("current_password")
            new_password = post_vars.get("new_password")
            confirm_password = post_vars.get("confirm_password")
            
            if not current_password or not new_password or new_password != confirm_password:
                return await handle_form_errors(
                    datasette, "profile.html", template_data,
                    request, "All fields are required and new passwords must match"
                )
            
            # Validate new password strength
            is_valid_password, password_error = validate_password(new_password)
            if not is_valid_password:
                return await handle_form_errors(
                    datasette, "profile.html", template_data,
                    request, password_error
                )
            
            try:
                # Get current password hash
                password_result = await db.execute("SELECT password_hash FROM users WHERE user_id = ?", [actor.get("id")])
                password_row = password_result.first()
                
                # Verify current password
                if not password_row or not bcrypt.checkpw(current_password.encode('utf-8'), password_row["password_hash"].encode('utf-8')):
                    return await handle_form_errors(
                        datasette, "profile.html", template_data,
                        request, "Current password is incorrect"
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
                return await handle_form_errors(
                    datasette, "profile.html", template_data,
                    request, f"Password change failed: {str(e)}"
                )
        
        elif action == "update_email":
            new_email = post_vars.get("new_email")
            
            if not new_email:
                return await handle_form_errors(
                    datasette, "profile.html", template_data,
                    request, "Email is required"
                )
            
            # Validate email format
            is_valid_email, email_error = validate_email(new_email)
            if not is_valid_email:
                return await handle_form_errors(
                    datasette, "profile.html", template_data,
                    request, email_error
                )
            
            try:
                # Check if email already exists
                existing_email = await db.execute("SELECT user_id FROM users WHERE email = ? AND user_id != ?", [new_email, actor.get("id")])
                if existing_email.first():
                    return await handle_form_errors(
                        datasette, "profile.html", template_data,
                        request, "Email already in use by another account"
                    )
                
                # Update email
                await db.execute_write(
                    "UPDATE users SET email = ? WHERE user_id = ?",
                    [new_email, actor.get("id")]
                )
                
                await log_user_activity(
                    datasette, actor.get("id"), "update_email", 
                    f"User {actor.get('username')} updated email from {user_data['email']} to {new_email}",
                    {"old_email": user_data['email'], "new_email": new_email}
                )
                
                return Response.redirect("/profile?success=Email updated successfully")
                
            except Exception as e:
                logger.error(f"Email update error: {str(e)}")
                return await handle_form_errors(
                    datasette, "profile.html", template_data,
                    request, f"Email update failed: {str(e)}"
                )
    
    # GET request - show profile page
    return Response.html(
        await datasette.render_template(
            "profile.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "user": user_data,
                "actor": actor,
                "stats": await get_user_statistics(datasette, actor.get("id")),
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def change_password_page(datasette, request):
    logger.debug(f"Change Password request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized change password attempt: actor={actor}")
        return Response.redirect("/login")

    # Redirect to profile page instead
    return Response.redirect("/profile")

async def forgot_password_page(datasette, request):
    """Forgot password page (placeholder for future implementation)."""
    logger.debug(f"Forgot Password request: method={request.method}")
    
    content = await get_portal_content(datasette)
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        email = post_vars.get("email")
        
        if not email:
            return await handle_form_errors(
                datasette, "forgot_password.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                },
                request, "Email address is required"
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
        (r"^/change-password$", change_password_page),
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
            logger.info("Starting User Profile Module...")
            
            # Get database path
            db_path = None
            possible_paths = [
                os.getenv('PORTAL_DB_PATH'),  # Environment variable
                "/data/portal.db",            # Docker/production
                "data/portal.db",             # Local development relative
                os.path.join(ROOT_DIR, "data", "portal.db"),  # Absolute local
                os.path.join(DATA_DIR, "..", "portal.db"),    # Parent of data dir
                "portal.db"                   # Current directory fallback
            ]
            
            # Find the portal database
            for path in possible_paths:
                if path and os.path.exists(path):
                    db_path = path
                    logger.info(f"Found portal database at: {db_path}")
                    break
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