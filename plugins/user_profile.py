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
    """User login page and authentication with forced password change check."""
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
            
            # Try to get user data - handle missing column gracefully
            try:
                result = await db.execute(
                    "SELECT user_id, username, password_hash, role, COALESCE(must_change_password, 0) as must_change_password FROM users WHERE username = ?", 
                    [username]
                )
                user_row = result.first()
                
                if user_row:
                    # Access by column name (sqlite3.Row supports this)
                    user_id = user_row["user_id"]
                    username_db = user_row["username"]
                    password_hash = user_row["password_hash"]
                    role = user_row["role"]
                    must_change_password = bool(user_row["must_change_password"])
                else:
                    user_row = None
                    
            except Exception as e:
                # If must_change_password column doesn't exist, try without it
                logger.warning(f"Column access failed, trying without must_change_password: {e}")
                result = await db.execute(
                    "SELECT user_id, username, password_hash, role FROM users WHERE username = ?", 
                    [username]
                )
                user_row = result.first()
                
                if user_row:
                    user_id = user_row["user_id"]
                    username_db = user_row["username"]
                    password_hash = user_row["password_hash"]
                    role = user_row["role"]
                    must_change_password = False  # Default if column doesn't exist
                else:
                    user_row = None
            
            if user_row and bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                actor_data = {
                    "id": user_id, 
                    "name": f"User {username}", 
                    "role": role, 
                    "username": username,
                    "must_change_password": must_change_password
                }
                
                # Log successful login
                await log_user_activity(
                    datasette, user_id, "login", 
                    f"User {username} logged in",
                    {"username": username, "role": role, "must_change_password": must_change_password}
                )
                
                # Check if user must change password
                if must_change_password:
                    logger.debug(f"User {username} must change password, redirecting to force-change-password")
                    # Set cookie and redirect to forced password change page
                    response = Response.redirect("/force-change-password?reason=first_login")
                    set_actor_cookie(response, datasette, actor_data)
                    return response
                else:
                    # Normal login flow
                    redirect_url = "/system-admin" if role == "system_admin" else "/manage-databases"
                    logger.debug(f"User {username} normal login, redirecting to {redirect_url}")
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
            import traceback
            logger.error(f"Login traceback: {traceback.format_exc()}")
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
    """User registration page - ADMIN ONLY."""
    logger.debug(f"Register request: method={request.method}")

    actor = get_actor_from_request(request)
    content = await get_portal_content(datasette)

    # ADMIN ACCESS CONTROL - ADD THIS AT THE TOP
    if not actor or actor.get("role") != "system_admin":
        return Response.html(
            await datasette.render_template(
                "register.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "error": "Access restricted to system administrators only."
                },
                request=request
            )
        )

    # Determine available roles - only admins get here now
    is_admin = True  # Always true since we check above
    available_roles = ["system_user", "system_admin"]

    if request.method == "POST":
        # ADDITIONAL POST SECURITY CHECK
        if not actor or actor.get("role") != "system_admin":
            return Response.redirect("/?error=Unauthorized access")
        
        post_vars = await request.post_vars()
        logger.debug(f"Register POST vars keys: {list(post_vars.keys())}")
        username = post_vars.get("username")
        password = post_vars.get("password")
        email = post_vars.get("email")
        role = post_vars.get("role")
        # NEW: Check if admin wants to require password change
        require_password_change = bool(post_vars.get("require_password_change"))
        
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
        
        # Role validation
        if role not in available_roles:
            return await handle_form_errors(
                datasette, "register.html", template_data,
                request, "Invalid role selected"
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
            
            # NEW: Set must_change_password flag - default to True for new users unless admin unchecks it
            must_change_password = 1 if require_password_change else 0
            
            await db.execute_write(
                "INSERT INTO users (user_id, username, password_hash, role, email, created_at, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [user_id, username, hashed_password, role, email, datetime.utcnow(), must_change_password]
            )
            
            await log_user_activity(
                datasette, user_id, "register", 
                f"User {username} registered with role {role}",
                {"username": username, "role": role, "email": email, "must_change_password": bool(must_change_password)}
            )
            
            # Log admin creation action
            await log_user_activity(
                datasette, actor.get("id"), "create_user", 
                f"Admin {actor.get('username')} created user {username} with role {role}",
                {"created_username": username, "created_role": role, "require_password_change": bool(must_change_password)}
            )
            
            logger.debug("User registered by admin: %s with role: %s, user_id: %s, must_change_password: %s", 
                        username, role, user_id, must_change_password)
            
            success_message = f"User account created successfully"
            if must_change_password:
                success_message += ". User will be required to change password on first login."
            
            # Always redirect to admin panel since only admins can access this
            return Response.redirect(f"/system-admin?success={success_message}")
                
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

async def force_change_password_page(datasette, request):
    """Force password change page for users who must change their password."""
    logger.debug(f"Force Change Password request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized force password change attempt: actor={actor}")
        return Response.redirect("/login")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    # Check database directly for must_change_password status
    db = datasette.get_database('portal')
    try:
        result = await db.execute(
            "SELECT COALESCE(must_change_password, 0) as must_change_password FROM users WHERE user_id = ?",
            [actor.get("id")]
        )
        db_user = result.first()
        
        if not db_user:
            logger.error(f"User {actor.get('username')} not found in database")
            return Response.redirect("/login")
        
        must_change_password = bool(db_user["must_change_password"])
        logger.debug(f"Database check for user {actor.get('username')}: must_change_password = {must_change_password}")
        
        # Check if user actually needs to change password
        if not must_change_password:
            redirect_url = "/system-admin" if user_data["role"] == "system_admin" else "/manage-databases"
            logger.debug(f"User {actor.get('username')} doesn't need password change, redirecting to {redirect_url}")
            return Response.redirect(redirect_url)

    except Exception as db_error:
        logger.error(f"Error checking password change requirement: {db_error}")
        must_change_password = True  # Assume true for security

    content = await get_portal_content(datasette)
    
    # Get reason for password change
    reason = request.args.get('reason', 'required')
    reason_messages = {
        'first_login': 'You must change your password before proceeding. This is required for all new accounts.',
        'admin_required': 'An administrator has required you to change your password.',
        'security': 'For security reasons, you must change your password.',
        'required': 'You must change your password before continuing.'
    }
    reason_message = reason_messages.get(reason, reason_messages['required'])

    if request.method == "POST":
        post_vars = await request.post_vars()
        
        # FOLLOW YOUR EXISTING PATTERN - Let Datasette handle CSRF validation
        # Your other forms (login, profile) don't manually validate CSRF tokens
        # They just include the token in the template and rely on Datasette's handling
        
        current_password = post_vars.get("current_password")
        new_password = post_vars.get("new_password")
        confirm_password = post_vars.get("confirm_password")
        
        logger.debug(f"Password change POST request for user {actor.get('username')}")
        
        template_data = {
            "metadata": datasette.metadata(),
            "content": content,
            "user": user_data,
            "actor": actor,
            "reason": reason,
            "reason_message": reason_message,
            "is_forced": True
        }
        
        if not current_password or not new_password or new_password != confirm_password:
            return await handle_form_errors(
                datasette, "force_change_password.html", template_data,
                request, "All fields are required and new passwords must match"
            )
        
        # Validate new password strength
        is_valid_password, password_error = validate_password(new_password)
        if not is_valid_password:
            return await handle_form_errors(
                datasette, "force_change_password.html", template_data,
                request, password_error
            )
        
        # Ensure new password is different from current password
        if current_password == new_password:
            return await handle_form_errors(
                datasette, "force_change_password.html", template_data,
                request, "New password must be different from your current password"
            )
        
        try:
            # Get current password hash
            password_result = await db.execute("SELECT password_hash FROM users WHERE user_id = ?", [actor.get("id")])
            password_row = password_result.first()
            
            # Verify current password
            if not password_row or not bcrypt.checkpw(current_password.encode('utf-8'), password_row["password_hash"].encode('utf-8')):
                return await handle_form_errors(
                    datasette, "force_change_password.html", template_data,
                    request, "Current password is incorrect"
                )
            
            # Update password and clear the must_change_password flag
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            await db.execute_write(
                "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE user_id = ?",
                [hashed_password, actor.get("id")]
            )
            
            logger.debug(f"Password updated in database for user {actor.get('username')}, must_change_password set to 0")
            
            await log_user_activity(
                datasette, actor.get("id"), "forced_password_change", 
                f"User {actor.get('username')} completed forced password change",
                {"reason": reason, "first_login": reason == 'first_login'}
            )
            
            # Update actor cookie to clear must_change_password flag
            updated_actor = actor.copy()
            updated_actor["must_change_password"] = False
            
            # Redirect to appropriate destination
            redirect_url = "/system-admin" if user_data["role"] == "system_admin" else "/manage-databases"
            success_message = "Password changed successfully. Welcome to the portal!"
            
            logger.debug(f"Password change successful for {actor.get('username')}, redirecting to {redirect_url}")
            
            response = Response.redirect(f"{redirect_url}?success={success_message}")
            set_actor_cookie(response, datasette, updated_actor)
            return response
            
        except Exception as e:
            logger.error(f"Force password change error: {str(e)}")
            import traceback
            logger.error(f"Password change traceback: {traceback.format_exc()}")
            return await handle_form_errors(
                datasette, "force_change_password.html", template_data,
                request, f"Password change failed: {str(e)}"
            )
    
    # GET request - show force password change form
    logger.debug(f"Showing force password change form for {actor.get('username')}")
    return Response.html(
        await datasette.render_template(
            "force_change_password.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "user": user_data,
                "actor": actor,
                "reason": reason,
                "reason_message": reason_message,
                "is_forced": True,
                **get_success_error_from_request(request)
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
        (r"^/force-change-password$", force_change_password_page),

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