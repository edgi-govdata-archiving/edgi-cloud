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
PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGINS_DIR not in sys.path:
    sys.path.insert(0, PLUGINS_DIR)
ROOT_DIR = os.path.dirname(PLUGINS_DIR)

# Import from common_utils
from common_utils import (
    get_actor_from_request,
    log_database_action,
    verify_user_session,
    get_system_settings,
    get_blocked_domains,
    get_max_image_size,
    get_portal_content,
    get_detailed_database_stats,
    get_success_error_from_request,
    parse_markdown_links,
    ensure_data_directories,
    optimize_existing_header_images,
    DATA_DIR,
)

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
                max_img_size = await get_max_image_size(datasette)

                if len(body) > max_img_size:
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
    
async def system_admin(datasette, request):
    """Enhanced system admin page with settings support."""
    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    if actor.get("role") != "system_admin":
        return Response.redirect("/manage-databases?error=Admin access required")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    query_db = datasette.get_database('portal')
    
    try:
        # Get system settings
        system_settings = await get_system_settings(datasette)
        
        # Get blocked domains
        blocked_domains = await get_blocked_domains(datasette)
        
        # Get system statistics
        system_stats = {}
        try:
            # Total uploads (could be enhanced with actual upload tracking)
            upload_logs = await query_db.execute("SELECT COUNT(*) FROM activity_logs WHERE action LIKE '%upload%'")
            system_stats['total_uploads'] = upload_logs.first()[0]
            
            # Calculate total storage (approximate)
            total_storage = 0
            all_dbs = await query_db.execute("SELECT user_id, db_name FROM databases WHERE status != 'Deleted'")
            for db_row in all_dbs:
                db_file = os.path.join(DATA_DIR, db_row['user_id'], f"{db_row['db_name']}.db")
                if os.path.exists(db_file):
                    total_storage += os.path.getsize(db_file)
            system_stats['total_storage_mb'] = round(total_storage / (1024 * 1024), 1)
            
            # Average database size
            db_count = len(list(all_dbs))
            system_stats['total_db'] = db_count
            system_stats['avg_db_size'] = round(total_storage / (1024 * db_count)) if db_count > 0 else 0
            
        except Exception as stats_error:
            logger.error(f"Error calculating system stats: {stats_error}")
            system_stats = {'total_db': 0, 'total_uploads': 0, 'total_storage_mb': 0, 'avg_db_size': 0}
        
        # Count expired trash
        try:
            retention_days = system_settings['trash_retention_days']
            cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
            expired_result = await query_db.execute(
                "SELECT COUNT(*) FROM databases WHERE status = 'Trashed' AND trashed_at < ?",
                [cutoff_date]
            )
            expired_trash_count = expired_result.first()[0]
        except Exception:
            expired_trash_count = 0

        # Get all users - EXCLUDE 'Deleted' status
        users_result = await query_db.execute(
            "SELECT user_id, username, email, role, created_at FROM users ORDER BY created_at DESC"
        )
        users = [dict(row) for row in users_result]

        # Get all databases with user info - EXCLUDE 'Deleted' status
        databases_result = await query_db.execute(
            """SELECT d.db_id, d.db_name, d.status, d.website_url, d.created_at, d.file_path, 
                      u.username, d.user_id
               FROM databases d 
               JOIN users u ON d.user_id = u.user_id 
               WHERE d.status IN ('Draft', 'Published', 'Unpublished')
               ORDER BY d.created_at DESC"""
        )
        
        databases_with_details = []
        for db_row in databases_result:
            db_info = dict(db_row)
            
            # Calculate database statistics
            db_name = db_info["db_name"]
            user_id = db_info["user_id"]
            
            # Build file path if not available
            file_path = db_info.get("file_path")
            if not file_path:
                file_path = os.path.join(DATA_DIR, user_id, f"{db_name}.db")
            
            table_count = 0
            total_records = 0
            file_size = 0
            
            try:
                if file_path and os.path.exists(file_path):
                    # Get file size
                    file_size = os.path.getsize(file_path) / 1024  # KB
                    
                    # Get table and record counts
                    import sqlite3
                    conn = sqlite3.connect(file_path)
                    cursor = conn.cursor()
                    
                    # Get table names
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = cursor.fetchall()
                    table_count = len(tables)
                    
                    # Count total records
                    for (table_name,) in tables:
                        try:
                            cursor.execute(f"SELECT COUNT(*) FROM [{table_name}]")
                            count = cursor.fetchone()[0]
                            total_records += count
                        except Exception:
                            continue
                    
                    conn.close()
                    
            except Exception as e:
                logger.error(f"Error getting stats for database {db_name}: {e}")
            
            db_info.update({
                'table_count': table_count,
                'total_records': total_records,
                'file_size': file_size
            })
            
            databases_with_details.append(db_info)

        # Get recent activity logs
        activity_result = await query_db.execute(
            "SELECT log_id, user_id, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC LIMIT 50"
        )
        activity_logs = [dict(row) for row in activity_result]

        # Count total trashed databases - EXCLUDE 'Deleted' status
        trashed_result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE status = 'Trashed'")
        total_trashed = trashed_result.first()[0]

        # Get content for template
        content = await get_portal_content(datasette)

        return Response.html(
            await datasette.render_template(
                "system_admin.html",
                {
                    "content": content,
                    "actor": actor,
                    "users": users,
                    "databases": databases_with_details,
                    "activity_logs": activity_logs,
                    "total_trashed": total_trashed,
                    # NEW: Settings data
                    "system_settings": system_settings,
                    "blocked_domains": blocked_domains,
                    "system_stats": system_stats,
                    "expired_trash_count": expired_trash_count,
                    **get_success_error_from_request(request)
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error in system admin: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return Response.text("Admin panel error", status=500)

async def verify_admin_password_from_request(datasette, request, actor):
    """FIXED: Verify admin password from either form data or JSON body."""
    try:
        admin_password = None
        
        # Try to get password from POST form data
        if request.method == "POST":
            try:
                post_vars = await request.post_vars()
                admin_password = post_vars.get('admin_password', '').strip()
                logger.debug(f"Got password from form data: {'Yes' if admin_password else 'No'}")
            except Exception as e:
                logger.debug(f"Failed to get form data: {e}")
                
                # Try to get password from JSON body
                try:
                    body = await request.post_body()
                    if body:
                        data = json.loads(body.decode('utf-8'))
                        admin_password = data.get('admin_password', '').strip()
                        logger.debug(f"Got password from JSON: {'Yes' if admin_password else 'No'}")
                except Exception as json_error:
                    logger.debug(f"Failed to get JSON data: {json_error}")
        
        if not admin_password:
            logger.warning("No admin password found in request")
            return False, "Administrator password is required for this operation"
        
        # Verify password against the database
        query_db = datasette.get_database('portal')
        result = await query_db.execute(
            "SELECT password_hash FROM users WHERE user_id = ? AND role = 'system_admin'",
            [actor.get("id")]
        )
        
        user_info = result.first()
        if not user_info:
            logger.warning(f"Admin user not found for user_id: {actor.get('id')}")
            return False, "Admin user not found"
        
        # Check password using bcrypt
        import bcrypt
        stored_hash = user_info['password_hash'].encode('utf-8')
        password_bytes = admin_password.encode('utf-8')
        
        if bcrypt.checkpw(password_bytes, stored_hash):
            logger.info(f"Admin password verified successfully for user: {actor.get('username')}")
            return True, None
        else:
            logger.warning(f"Invalid admin password attempt for user: {actor.get('username')}")
            return False, "Invalid administrator password"
            
    except Exception as e:
        logger.error(f"Error verifying admin password: {e}")
        return False, "Password verification failed"

async def admin_password_confirmation(datasette, request):
    """Show admin password confirmation page for sensitive operations."""
    logger.debug(f"Admin Password Confirmation: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.redirect("/login?error=Admin access required")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    if request.method == "POST":
        # Handle password verification and proceed with original operation
        post_vars = await request.post_vars()
        admin_password = post_vars.get('admin_password', '').strip()
        operation = post_vars.get('operation', '')
        
        # Verify password
        password_valid, password_error = await verify_admin_password_direct(datasette, actor, admin_password)
        
        if not password_valid:
            # Show confirmation page again with error
            return await show_confirmation_page(
                datasette, request, actor, operation, 
                error=password_error
            )
        
        # Password verified - execute operation
        try:
            if operation == 'update_system_settings':
                return await handle_system_settings_update(datasette, request, post_vars, actor)
            elif operation == 'add_blocked_domain':
                return await handle_domain_block(datasette, request, post_vars, actor)
            elif operation == 'remove_blocked_domain':
                return await handle_domain_unblock(datasette, request, post_vars, actor)
            elif operation == 'clear_old_trash':
                return await handle_maintenance_operation(datasette, request, 'clear_old_trash', actor)
            elif operation == 'optimize_database':
                return await handle_maintenance_operation(datasette, request, 'optimize_database', actor)
            elif operation == 'regenerate_thumbnails':
                return await handle_maintenance_operation(datasette, request, 'regenerate_thumbnails', actor)
            elif operation == 'export_system_logs':
                return await export_system_logs(datasette, request, actor)
            elif operation == 'reset_system_settings':
                return await handle_settings_reset(datasette, request, actor)
            else:
                logger.error(f"Unknown operation: {operation}")
                return Response.redirect("/system-admin?error=Unknown operation")
                
        except Exception as e:
            logger.error(f"Error executing confirmed operation {operation}: {e}")
            return Response.redirect(f"/system-admin?error=Operation failed: {str(e)}")
    
    # GET request - show confirmation page
    operation = request.args.get('operation', '')
    return await show_confirmation_page(datasette, request, actor, operation)

async def verify_admin_password_direct(datasette, actor, password):
    """Direct password verification for confirmation page."""
    try:
        if not password:
            return False, "Administrator password is required"
        
        query_db = datasette.get_database('portal')
        result = await query_db.execute(
            "SELECT password_hash FROM users WHERE user_id = ? AND role = 'system_admin'",
            [actor.get("id")]
        )
        
        user_info = result.first()
        if not user_info:
            return False, "Administrator account not found"
        
        import bcrypt
        stored_hash = user_info['password_hash'].encode('utf-8')
        password_bytes = password.encode('utf-8')
        
        if bcrypt.checkpw(password_bytes, stored_hash):
            return True, None
        else:
            return False, "Invalid administrator password"
            
    except Exception as e:
        logger.error(f"Error verifying admin password: {e}")
        return False, "Password verification failed"

async def show_confirmation_page(datasette, request, actor, operation, error=None):
    """Show the password confirmation page using admin_password_confirmation.html."""
    
    # Define operation details
    SECURE_OPERATIONS = {
        'update_system_settings': {
            'title': 'Update System Configuration',
            'description': 'Modify critical system settings that affect all users.',
            'details': [
                'Database retention policies',
                'User upload limits', 
                'File size restrictions',
                'Security configurations'
            ]
        },
        'add_blocked_domain': {
            'title': 'Block Domain',
            'description': 'Add a domain to the security blocklist.',
            'details': [
                'Prevent CSV imports from this domain',
                'Apply security restrictions',
                'Affect all user upload capabilities'
            ]
        },
        'clear_old_trash': {
            'title': 'Clear Expired Trash',
            'description': 'Permanently delete expired databases from trash.',
            'details': [
                'Delete databases past retention period',
                'Free up storage space',
                'Action cannot be undone'
            ]
        },
        'optimize_database': {
            'title': 'Optimize Database',
            'description': 'Optimize database performance by running VACUUM and ANALYZE.',
            'details': [
                'Compress database files',
                'Update query statistics',
                'Improve performance'
            ]
        },
        'regenerate_thumbnails': {
            'title': 'Regenerate Image Thumbnails',
            'description': 'Regenerate and optimize all image thumbnails.',
            'details': [
                'Process all uploaded images',
                'Optimize file sizes',
                'Update image cache'
            ]
        },
        'export_system_logs': {
            'title': 'Export System Logs',
            'description': 'Export system activity logs as a CSV file.',
            'details': [
                'Export all activity logs',
                'Include user information',
                'Download as CSV file'
            ]
        },
        'reset_system_settings': {
            'title': 'Reset All System Settings',
            'description': 'DANGER: Reset all system configuration to default values.',
            'details': [
                'All custom settings will be lost',
                'Blocked domains list will be cleared',
                'System will revert to factory defaults',
                'This action cannot be undone'
            ]
        }
    }
    
    # Get operation details
    op_info = SECURE_OPERATIONS.get(operation, {
        'title': 'System Operation',
        'description': 'This operation requires administrator verification.',
        'details': []
    })
    
    # FIXED: Collect form data from request - handle MultiParams properly
    form_data = {}
    if request.method == "POST":
        post_vars = await request.post_vars()
        # post_vars is already a dict-like object we can iterate over
        for key in post_vars:
            if key not in ['admin_password', 'csrftoken']:
                form_data[key] = post_vars[key]
    else:
        # For GET requests, collect from query parameters
        # FIXED: Convert MultiParams to dict properly
        for key in request.args:
            if key not in ['operation']:
                # Get the first value for each key
                form_data[key] = request.args[key]
    
    # Add operation to form data
    form_data['operation'] = operation
    
    # Get content for template
    content = await get_portal_content(datasette)

    return Response.html(
        await datasette.render_template(
            "admin_password_confirmation.html",
            {
                "content": content,
                "actor": actor,
                "operation_title": op_info['title'],
                "operation_description": op_info['description'],
                "operation_details": op_info['details'],
                "form_action": "/admin/confirm-password",
                "form_data": form_data,
                "cancel_url": "/system-admin?tab=settings",
                "error": error,
            },
            request=request
        )
    )

async def update_system_settings(datasette, request):
    """Update system settings - redirect to confirmation page for password verification."""
    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.redirect("/login?error=Admin access required")
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        
        # Check if admin password is provided
        if not post_vars.get('admin_password'):
            # Redirect to confirmation page with form data
            query_params = []
            query_params.append("operation=update_system_settings")
            
            # Add form data as query parameters
            for key, value in post_vars.items():
                if key not in ['csrftoken']:
                    query_params.append(f"{key}={value}")
            
            query_string = "&".join(query_params)
            return Response.redirect(f"/admin/confirm-password?{query_string}")
        
        # Password provided - verify it
        password_valid, password_error = await verify_admin_password_from_request(datasette, request, actor)
        if not password_valid:
            return Response.redirect(f"/system-admin?tab=settings&error={password_error}")
        
        # Execute the settings update
        return await handle_system_settings_update(datasette, request, post_vars)
    
    return Response.redirect("/system-admin")

async def handle_system_settings_update(datasette, request, post_vars, actor):
    """Handle the actual system settings update after password verification."""
    query_db = datasette.get_database('portal')
    
    try:
        # Update system configuration
        settings_to_update = [
            ('trash_retention_days', post_vars.get('trash_retention_days', '30')),
            ('max_databases_per_user', post_vars.get('max_databases_per_user', '10')),
            ('max_file_size', str(int(post_vars.get('max_file_size_mb', '50')) * 1024 * 1024)),
            ('max_img_size', str(int(post_vars.get('max_img_size_mb', '5')) * 1024 * 1024)),
            ('allowed_extensions', post_vars.get('allowed_extensions', '.jpg, .png, .csv, .xls, .xlsx, .txt'))
        ]
        
        for key, value in settings_to_update:
            await query_db.execute_write(
                "INSERT OR REPLACE INTO system_settings (setting_key, setting_value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                [key, value, datetime.utcnow().isoformat(), actor['username']]
            )
        
        await log_database_action(
            datasette, actor.get("id"), "update_system_settings", 
            "Updated system settings with admin password verification",
            {"settings": dict(settings_to_update), "password_verified": True}
        )
        
        # Return to Settings tab for system settings operations
        return Response.redirect("/system-admin?tab=settings&success=System settings updated successfully")
        
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        return Response.redirect("/system-admin?tab=settings&error=Failed to update settings")

async def handle_domain_block(datasette, request, post_vars, actor):
    """Handle domain blocking after password verification."""
    query_db = datasette.get_database('portal')
    
    try:
        domain = post_vars.get('domain', '').strip().lower()
        if domain:
            # Check if domain already blocked
            existing = await query_db.execute("SELECT COUNT(*) FROM blocked_domains WHERE domain = ?", [domain])
            if existing.first()[0] == 0:
                await query_db.execute_write(
                    "INSERT INTO blocked_domains (domain, created_at, created_by) VALUES (?, ?, ?)",
                    [domain, datetime.utcnow().isoformat(), actor['username']]
                )
                
                await log_database_action(
                    datasette, actor.get("id"), "block_domain", 
                    f"Blocked domain: {domain} with admin password verification",
                    {"domain": domain, "password_verified": True}
                )
                
                # Return to Settings tab for domain management
                return Response.redirect(f"/system-admin?tab=settings&success=Domain '{domain}' blocked successfully")
            else:
                return Response.redirect(f"/system-admin?tab=settings&error=Domain '{domain}' already blocked")
        else:
            return Response.redirect("/system-admin?tab=settings&error=Invalid domain")
            
    except Exception as e:
        logger.error(f"Error blocking domain: {e}")
        return Response.redirect("/system-admin?tab=settings&error=Failed to block domain")

async def handle_domain_unblock(datasette, request, post_vars, actor):
    """Handle domain unblocking after password verification."""
    query_db = datasette.get_database('portal')
    
    try:
        domain = post_vars.get('domain', '').strip().lower()
        if domain:
            await query_db.execute_write("DELETE FROM blocked_domains WHERE domain = ?", [domain])
            
            await log_database_action(
                datasette, actor.get("id"), "unblock_domain", 
                f"Unblocked domain: {domain}",
                {"domain": domain}
            )
            
            # Return to Settings tab for domain management
            return Response.redirect(f"/system-admin?tab=settings&success=Domain '{domain}' unblocked successfully")
        else:
            return Response.redirect("/system-admin?tab=settings&error=Invalid domain")
            
    except Exception as e:
        logger.error(f"Error unblocking domain: {e}")
        return Response.redirect("/system-admin?tab=settings&error=Failed to unblock domain")

async def handle_maintenance_operation(datasette, request, action, actor):
    """Handle maintenance operations after password verification."""
    query_db = datasette.get_database('portal')
    
    try:
        if action == 'clear_old_trash':
            # Get current settings
            settings = await get_system_settings(datasette)
            retention_days = settings['trash_retention_days']
            
            # Calculate cutoff date
            cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
            
            # Find expired databases
            expired = await query_db.execute(
                "SELECT db_id, db_name FROM databases WHERE status = 'Trashed' AND trashed_at < ?",
                [cutoff_date]
            )
            
            count = 0
            for row in expired:
                try:
                    # Delete database files
                    db_id = row['db_id']
                    user_result = await query_db.execute("SELECT user_id FROM databases WHERE db_id = ?", [db_id])
                    if user_result.first():
                        user_id = user_result.first()['user_id']
                        db_file = os.path.join(DATA_DIR, user_id, f"{row['db_name']}.db")
                        if os.path.exists(db_file):
                            os.remove(db_file)
                            logger.info(f"Deleted database file: {db_file}")
                    
                    # Update status to 'Deleted'
                    await query_db.execute_write(
                        "UPDATE databases SET status = 'Deleted', deleted_at = ? WHERE db_id = ?", 
                        [datetime.utcnow().isoformat(), db_id]
                    )
                    count += 1
                    
                except Exception as delete_error:
                    logger.error(f"Error deleting database {row['db_name']}: {delete_error}")
                    continue
            
            await log_database_action(
                datasette, actor.get("id"), "clear_old_trash", 
                f"Cleared {count} expired databases from trash with admin password verification",
                {"count": count, "retention_days": retention_days, "password_verified": True}
            )
            
            # Return to Settings tab for maintenance operations
            return Response.redirect(f"/system-admin?tab=settings&success=Successfully cleared {count} expired databases from trash")
        
        elif action == 'optimize_database':
            try:
                optimized_count = 0
                total_space_saved = 0
                
               # 1. Optimize portal database (VACUUM only, no ANALYZE)
                portal_db_path = os.getenv('PORTAL_DB_PATH', "/data/portal.db")
                if os.path.exists(portal_db_path):
                    portal_size_before = os.path.getsize(portal_db_path)
                    
                    # ONLY VACUUM - DO NOT RUN ANALYZE (which creates sqlite_stat1)
                    await query_db.execute_write("VACUUM")
                    
                    portal_size_after = os.path.getsize(portal_db_path)
                    portal_saved = max(0, portal_size_before - portal_size_after)
                    optimized_count += 1
                    total_space_saved += portal_saved
                    
                    logger.info(f"Optimized portal database: saved {portal_saved} bytes")
                
                # 2. Optimize all user databases (VACUUM only, no ANALYZE)
                user_dbs = await query_db.execute(
                    "SELECT db_name, file_path, user_id FROM databases WHERE status IN ('Draft', 'Published', 'Unpublished')"
                )
                
                for db_row in user_dbs:
                    db_dict = dict(db_row)
                    db_name = db_dict['db_name']
                    file_path = db_dict.get('file_path')
                    user_id = db_dict['user_id']
                    
                    # Build file path if not available
                    if not file_path:
                        file_path = os.path.join(DATA_DIR, user_id, f"{db_name}.db")
                    
                    if file_path and os.path.exists(file_path):
                        try:
                            # Get size before optimization
                            size_before = os.path.getsize(file_path)
                            
                            # Get the database instance
                            user_db = datasette.get_database(db_name)
                            if user_db:
                                # ONLY VACUUM - DO NOT RUN ANALYZE
                                await user_db.execute_write("VACUUM")
                                optimized_count += 1
                                
                                # Calculate space saved
                                size_after = os.path.getsize(file_path)
                                space_saved = max(0, size_before - size_after)
                                total_space_saved += space_saved
                                
                                logger.info(f"Optimized {db_name}: saved {space_saved} bytes")
                            else:
                                logger.warning(f"Database {db_name} not registered with Datasette")
                                
                        except Exception as db_error:
                            logger.error(f"Error optimizing database {db_name}: {db_error}")
                            continue
                
                await log_database_action(
                    datasette, actor.get("id"), "optimize_database", 
                    f"Optimized {optimized_count} databases with VACUUM only, saved {total_space_saved} bytes",
                    {
                        "optimized_count": optimized_count,
                        "space_saved_bytes": total_space_saved,
                        "space_saved_mb": round(total_space_saved / (1024 * 1024), 2),
                        "vacuum_only": True,
                        "password_verified": True
                    }
                )
                
                space_saved_mb = round(total_space_saved / (1024 * 1024), 2)
                return Response.redirect(f"/system-admin?tab=settings&success=Optimized {optimized_count} databases successfully with VACUUM only. Space saved: {space_saved_mb} MB")
                
            except Exception as optimize_error:
                logger.error(f"Database optimization failed: {optimize_error}")
                return Response.redirect(f"/system-admin?tab=settings&error=Database optimization failed: {str(optimize_error)}")

        elif action == 'regenerate_thumbnails':
            try:
                # Note: This requires the image optimization functions from delete_db module
                try:                    
                    # Run the comprehensive image optimization
                    optimized_count, total_savings =     optimize_existing_header_images(datasette)
                    
                    await log_database_action(
                        datasette, actor.get("id"), "regenerate_thumbnails", 
                        f"Optimized {optimized_count} images with admin password verification, saved {total_savings} bytes",
                        {
                            "images_optimized": optimized_count,
                            "space_saved_bytes": total_savings,
                            "space_saved_mb": round(total_savings / (1024 * 1024), 2),
                            "password_verified": True
                        }
                    )
                    
                    space_saved_mb = round(total_savings / (1024 * 1024), 2)
                    return Response.redirect(f"/system-admin?tab=settings&success=Successfully optimized {optimized_count} images. Space saved: {space_saved_mb} MB")
                    
                except ImportError:
                    return Response.redirect("/system-admin?tab=settings&error=Image optimization requires Pillow library")
                    
            except Exception as thumbnail_error:
                logger.error(f"Image optimization failed: {thumbnail_error}")
                return Response.redirect(f"/system-admin?tab=settings&error=Image optimization failed: {str(thumbnail_error)}")
        
        else:
            return Response.redirect(f"/system-admin?tab=settings&error=Unknown maintenance action: {action}")
        
    except Exception as e:
        logger.error(f"Maintenance operation {action} failed: {e}")
        return Response.redirect(f"/system-admin?tab=settings&error=Maintenance operation failed: {str(e)}")

async def handle_settings_reset(datasette, request, actor):
    """Handle settings reset after password verification."""
    try:
        query_db = datasette.get_database('portal')
        
        # Backup current settings before reset
        current_settings = await query_db.execute("SELECT setting_key, setting_value FROM system_settings")
        backup_data = {row['setting_key']: row['setting_value'] for row in current_settings}
        
        current_domains = await query_db.execute("SELECT domain FROM blocked_domains")
        blocked_domains_backup = [row['domain'] for row in current_domains]
        
        # Clear all settings
        await query_db.execute_write("DELETE FROM system_settings")
        await query_db.execute_write("DELETE FROM blocked_domains")
        
        # Insert default settings
        default_settings = [
            ('trash_retention_days', '30'),
            ('max_databases_per_user', '10'),
            ('max_file_size', str(50 * 1024 * 1024)),
            ('max_img_size', str(5 * 1024 * 1024)),
            ('allowed_extensions', '.jpg, .jpeg, .png, .csv, .xls, .xlsx, .txt')
        ]
        
        for key, value in default_settings:
            await query_db.execute_write(
                "INSERT INTO system_settings (setting_key, setting_value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                [key, value, datetime.utcnow().isoformat(), actor['username']]
            )
        
        await log_database_action(
            datasette, actor.get("id"), "reset_system_settings", 
            "Reset all system settings to defaults with admin password verification",
            {
                "backup_settings": backup_data,
                "backup_blocked_domains": blocked_domains_backup,
                "reset_timestamp": datetime.utcnow().isoformat(),
                "password_verified": True
            }
        )
        
        return Response.redirect("/system-admin?tab=settings&success=All system settings have been reset to default values successfully")
        
    except Exception as e:
        logger.error(f"Error resetting settings: {e}")
        return Response.redirect(f"/system-admin?tab=settings&error=Failed to reset settings: {str(e)}")

async def export_system_logs(datasette, request, actor):
    """Handle log export after password verification - FIXED to return to settings tab."""
    try:
        query_db = datasette.get_database('portal')
        
        # Get logs with user information
        logs = await query_db.execute("""
            SELECT 
                al.log_id, 
                al.user_id, 
                u.username,
                al.action, 
                al.details, 
                al.timestamp, 
                al.action_metadata
            FROM activity_logs al
            LEFT JOIN users u ON al.user_id = u.user_id
            ORDER BY al.timestamp DESC 
            LIMIT 10000
        """)
        
        # Create CSV content
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Log ID', 'User ID', 'Username', 'Action', 'Details', 
            'Timestamp', 'Metadata'
        ])
        
        # Write data
        log_count = 0
        for log in logs:
            log_dict = dict(log)
            writer.writerow([
                log_dict['log_id'], 
                log_dict['user_id'], 
                log_dict.get('username', 'Unknown'),
                log_dict['action'], 
                log_dict['details'], 
                log_dict['timestamp'], 
                log_dict.get('action_metadata', '')
            ])
            log_count += 1
        
        content = output.getvalue()
        output.close()
        
        # Log the export action
        await log_database_action(
            datasette, actor.get("id"), "export_system_logs", 
            f"Exported {log_count} system log entries with admin password verification",
            {"exported_count": log_count, "password_verified": True}
        )
        
        # SIMPLE SOLUTION: Return HTML page that triggers download and redirects
        filename = f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # Create HTML page that downloads file and redirects
        redirect_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Downloading Logs...</title>
            <meta charset="utf-8">
        </head>
        <body>
            <script>
                // Create download
                const csvContent = {repr(content)};
                const blob = new Blob([csvContent], {{ type: 'text/csv' }});
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = '{filename}';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                // Redirect to settings tab after download starts
                setTimeout(function() {{
                    window.location.href = '/system-admin?tab=settings&success=System logs exported successfully ({log_count} entries)';
                }}, 1000);
            </script>
            <p>Downloading system logs... You will be redirected back to the settings page.</p>
        </body>
        </html>
        """
        
        return Response.html(redirect_html)
        
    except Exception as e:
        logger.error(f"Error exporting logs: {e}")
        # If export fails, redirect to settings tab with error
        return Response.redirect(f"/system-admin?tab=settings&error=Export failed: {str(e)}")
    
@hookimpl
def register_routes():
    """Register admin panel routes."""
    return [
        (r"^/system-admin$", system_admin),
        (r"^/admin/confirm-password$", admin_password_confirmation),
        (r"^/admin/update-settings$", update_system_settings),
        (r"^/admin/export-logs$", export_system_logs),
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
            logger.info("Starting Admin Panel Module...")
            
            # Ensure directories exist
            ensure_data_directories()
                       
            # Get database path - SUPPORT BOTH ENVIRONMENTS
            db_path = None
            if not db_path:
                # Check common locations
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
            
            logger.info("Admin Panel Module startup completed successfully")
            
        except Exception as e:
            logger.error(f"Admin Panel Module startup failed: {str(e)}")

    return inner