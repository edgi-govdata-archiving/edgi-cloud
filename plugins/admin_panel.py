"""
Admin Panel Module - System administration and portal management
Handles: System admin dashboard, user management, portal homepage editing
"""

import json
import uuid
import os
import sqlite_utils
from pathlib import Path
from datetime import datetime, timedelta
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database
from email.parser import BytesParser
from email.policy import default

import sys
plugins_dir = os.path.dirname(os.path.abspath(__file__))
if plugins_dir not in sys.path:
    sys.path.insert(0, plugins_dir)

# Import from common_utils (now using absolute import)
try:
    from common_utils import (
        get_actor_from_request,
        log_user_activity,
        log_database_action,
        verify_user_session,
        get_portal_content,
        handle_form_errors,
        get_success_error_from_request,
        validate_email,
        validate_username,
        validate_password,
        parse_markdown_links,
        apply_inline_formatting,
        sanitize_text,
        ensure_data_directories,
        STATIC_DIR,
        DATA_DIR,
        MAX_FILE_SIZE
    )
except ImportError as e:
    print(f"Warning: Could not import from common_utils: {e}")
    # Define minimal fallbacks if needed
    STATIC_DIR = "/static"
    DATA_DIR = "/data"
    MAX_FILE_SIZE = 50 * 1024 * 1024

# Configuration
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

async def get_detailed_database_stats(datasette, db_name, user_id):
    """Get detailed statistics for a specific database."""
    try:
        # Get database file path
        file_path = os.path.join(DATA_DIR, user_id, f"{db_name}.db")
        
        stats = {
            'table_count': 0,
            'total_records': 0,
            'file_size_kb': 0,
            'tables': []
        }
        
        if os.path.exists(file_path):
            try:
                # Get file size
                stats['file_size_kb'] = round(os.path.getsize(file_path) / 1024, 2)
                
                # Open database and get table information
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

async def system_admin_page(datasette, request):
    """System administration page - admin users only."""
    logger.debug(f"System Admin request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized system admin access attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session and admin role
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    if user_data["role"] != "system_admin":
        logger.warning(f"Invalid role for user_id={actor.get('id')}: role={user_data['role']}")
        return Response.redirect("/login?error=Unauthorized access")

    query_db = datasette.get_database('portal')
    content = await get_portal_content(datasette)

    try:
        users = await query_db.execute("SELECT user_id, username, email, role, created_at FROM users")
        users_list = [dict(row) for row in users]
        
        databases = await query_db.execute("SELECT d.db_id, d.db_name, d.website_url, d.status, d.created_at, d.trashed_at, d.restore_deadline, u.username FROM databases d JOIN users u ON d.user_id = u.user_id WHERE d.status != 'Deleted'")
        databases_list = []
        
        # Process each database to add missing attributes
        for row in databases:
            db_dict = dict(row)
            
            # Add days_until_delete attribute for all databases
            days_until_delete = 0
            if db_dict["status"] == "Trashed" and db_dict.get("restore_deadline"):
                try:
                    deadline = datetime.fromisoformat(db_dict["restore_deadline"].replace('Z', '+00:00'))
                    now = datetime.utcnow()
                    delta = deadline - now
                    days_until_delete = max(0, delta.days)
                except Exception as e:
                    logger.error(f"Error calculating restore deadline: {e}")
            
            # Add the calculated attributes
            db_dict['days_until_delete'] = days_until_delete
            db_dict['is_expired'] = days_until_delete <= 0 if db_dict["status"] == "Trashed" else False
            
            databases_list.append(db_dict)
        
        logs = await query_db.execute("SELECT log_id, user_id, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC LIMIT 100")
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
                **get_success_error_from_request(request)
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
            query_db = datasette.get_database("portal")
            
            # Get user details
            user_result = await query_db.execute("SELECT username, role FROM users WHERE user_id = ?", [user_id])
            user = user_result.first()
            if not user:
                return Response.redirect("/system-admin?error=User not found")
            
            # Prevent admin from changing their own role
            if user_id == actor.get("id"):
                return Response.redirect("/system-admin?error=Cannot change your own role")
            
            # Update user role
            await query_db.execute_write(
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
            query_db = datasette.get_database("portal")
            
            # Get user details
            user_result = await query_db.execute("SELECT username FROM users WHERE user_id = ?", [user_id])
            user = user_result.first()
            if not user:
                return Response.redirect("/system-admin?error=User not found")
            
            # Prevent admin from deleting themselves
            if user_id == actor.get("id"):
                return Response.redirect("/system-admin?error=Cannot delete your own account")
            
            # Check if user has databases
            db_result = await query_db.execute("SELECT COUNT(*) as count FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
            db_count = db_result.first()['count']
            
            if db_count > 0:
                return Response.redirect(f"/system-admin?error=Cannot delete user {user['username']} - they have {db_count} active databases")
            
            # Delete user
            await query_db.execute_write("DELETE FROM users WHERE user_id = ?", [user_id])
            
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

    # Verify user session and admin role
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    if user_data["role"] != "system_admin":
        logger.warning(f"Invalid role for portal edit: user_id={actor.get('id')}")
        return Response.redirect("/login?error=Unauthorized access")

    query_db = datasette.get_database('portal')

    # Get current portal content using common utility
    content = await get_portal_content(datasette)

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
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def cleanup_expired_databases(datasette, request):
    """Admin function to cleanup expired databases."""
    logger.debug(f"Cleanup Expired request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.redirect("/login?error=Admin access required")

    if request.method == "POST":
        try:
            query_db = datasette.get_database("portal")
            
            # Find databases past their restore deadline
            now = datetime.utcnow()
            result = await query_db.execute(
                """SELECT db_id, db_name, user_id, file_path, restore_deadline 
                   FROM databases 
                   WHERE status = 'Trashed' AND restore_deadline < ?""",
                [now.isoformat()]
            )
            
            expired_databases = [dict(row) for row in result]
            cleanup_count = len(expired_databases)
            
            for db_info in expired_databases:
                db_name = db_info['db_name']
                db_id = db_info['db_id']
                user_id = db_info['user_id']
                
                try:
                    # Remove from Datasette if registered
                    if db_name in datasette.databases:
                        # Get the database instance to properly close it
                        db_instance = datasette.databases[db_name]
                        
                        # Close all connections to the database
                        if hasattr(db_instance, '_internal_db') and db_instance._internal_db:
                            try:
                                db_instance._internal_db.close()
                                logger.debug(f"Closed internal database connection for {db_name} during admin cleanup")
                            except Exception as close_error:
                                logger.error(f"Error closing internal database connection during admin cleanup: {close_error}")
                        
                        del datasette.databases[db_name]
                        logger.debug(f"Unregistered database {db_name} during admin cleanup")
                        
                        # Give the system a moment to release file handles
                        import time
                        time.sleep(0.5)
                    
                    # Delete database file using safe deletion
                    if db_info['file_path'] and os.path.exists(db_info['file_path']):
                        # Import the safe file delete function from delete_db module
                        from delete_db import enhanced_file_deletion
                        success = enhanced_file_deletion(db_info['file_path'], db_name)
                        if success:
                            logger.debug(f"Admin cleanup deleted database file: {db_info['file_path']}")
                            
                            # Try to remove directory if empty
                            try:
                                db_dir = os.path.dirname(db_info['file_path'])
                                os.rmdir(db_dir)
                                logger.debug(f"Admin cleanup removed empty directory: {db_dir}")
                            except OSError:
                                pass  # Directory not empty
                        else:
                            logger.warning(f"Admin cleanup could not delete database file: {db_info['file_path']}")
                    
                    # Remove database records
                    await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_id])
                    await query_db.execute_write("DELETE FROM databases WHERE db_id = ?", [db_id])
                    
                    # Log the cleanup
                    await log_admin_activity(
                        datasette, actor.get("id"), "cleanup_expired_database", 
                        f"Cleaned up expired database {db_name}",
                        {
                            "db_name": db_name,
                            "original_owner": user_id,
                            "restore_deadline": db_info['restore_deadline'],
                            "admin_cleanup": True
                        }
                    )
                    
                except Exception as e:
                    logger.error(f"Error cleaning up database {db_name}: {e}")
            
            return Response.redirect(f"/system-admin?success=Successfully cleaned up {cleanup_count} expired databases")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
            return Response.redirect(f"/system-admin?error=Failed to cleanup databases: {str(e)}")
    
    return Response.redirect("/system-admin")

async def get_database_details_api(datasette, request):
    """API endpoint to get detailed database statistics."""
    logger.debug(f"Database Details API request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.json({"error": "Admin access required"}, status=403)

    # Extract db_id from path
    path_parts = request.path.strip('/').split('/')
    if len(path_parts) < 3 or path_parts[0] != 'api' or path_parts[1] != 'database-details':
        return Response.json({"error": "Invalid path"}, status=400)
    
    db_id = path_parts[2]
    
    try:
        query_db = datasette.get_database("portal")
        
        # Get database info
        result = await query_db.execute(
            "SELECT d.db_name, d.user_id, d.status, u.username FROM databases d JOIN users u ON d.user_id = u.user_id WHERE d.db_id = ?",
            [db_id]
        )
        db_info = result.first()
        
        if not db_info:
            return Response.json({"error": "Database not found"}, status=404)
        
        # Get detailed stats
        stats = await get_detailed_database_stats(datasette, db_info['db_name'], db_info['user_id'])
        
        response_data = {
            "db_name": db_info['db_name'],
            "owner": db_info['username'],
            "status": db_info['status'],
            "table_count": stats['table_count'],
            "total_records": stats['total_records'],
            "file_size_kb": stats['file_size_kb'],
            "tables": stats['tables']
        }
        
        return Response.json(response_data)
        
    except Exception as e:
        logger.error(f"Error getting database details for {db_id}: {e}")
        return Response.json({"error": f"Failed to get database details: {str(e)}"}, status=500)

@hookimpl
def register_routes():
    """Register admin panel routes."""
    return [
        (r"^/system-admin$", system_admin_page),
        (r"^/edit-user-role$", edit_user_role),
        (r"^/delete-user$", delete_user),
        (r"^/edit-portal-homepage$", edit_portal_homepage),
        (r"^/cleanup-expired-databases$", cleanup_expired_databases),
        (r"^/api/database-details/([^/]+)$", get_database_details_api),
    ]

@hookimpl
def startup(datasette):
    """Admin Panel module startup."""
    
    async def inner():
        try:
            logger.info("🔧 Starting Admin Panel Module...")
            
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