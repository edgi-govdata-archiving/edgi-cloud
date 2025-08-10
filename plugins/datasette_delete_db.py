"""
Database Deletion Module - Three-tier deletion system
Handles: Unpublish → Trash → Permanent Delete
"""

import os
import json
import uuid
import logging
import sqlite_utils
from pathlib import Path
from datetime import datetime, timedelta
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database

logger = logging.getLogger(__name__)

# Configuration
TRASH_RETENTION_DAYS = 30
DATA_DIR = os.getenv('EDGI_DATA_DIR', "/data")

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
                import base64
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

async def unpublish_database(datasette, request):
    """Tier 1: Unpublish database (Published -> Unpublished)"""
    logger.debug(f"Unpublish Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Handle /db/{db_name}/unpublish path
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        if db_info['status'] != 'Published':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is not published")
        
        # Update status to Unpublished
        await query_db.execute_write(
            "UPDATE databases SET status = 'Unpublished' WHERE db_name = ?",
            [db_name]
        )
        
        await log_database_action(
            datasette, actor.get("id"), "unpublish_database", 
            f"Unpublished database {db_name}",
            {
                "db_name": db_name,
                "previous_status": "Published",
                "new_status": "Unpublished"
            }
        )
        
        return Response.redirect(f"/manage-databases?success=Database '{db_name}' unpublished successfully! It's now private.")
        
    except Exception as e:
        logger.error(f"Error unpublishing database {db_name}: {str(e)}")
        return Response.text(f"Error unpublishing database: {str(e)}", status=500)

async def trash_bin_page(datasette, request):
    """Dedicated trash bin page for managing trashed databases."""
    logger.debug(f"Trash Bin request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    query_db = datasette.get_database('portal')
    
    # Verify user
    try:
        result = await query_db.execute("SELECT user_id, username, role FROM users WHERE user_id = ?", [actor.get("id")])
        user = result.first()
        if not user:
            response = Response.redirect("/login?error=User not found")
            response.set_cookie("ds_actor", "", httponly=True, expires=0, samesite="lax")
            return response
    except Exception as e:
        logger.error(f"Error verifying user in trash_bin_page: {str(e)}")
        return Response.redirect("/login?error=Authentication error")

    is_admin = actor.get("role") == "system_admin"
    
    # Get trashed databases - admin sees all, users see their own
    if is_admin:
        query = """SELECT d.db_id, d.db_name, d.status, d.user_id, d.trashed_at, d.restore_deadline, 
                          d.file_path, u.username
                   FROM databases d 
                   JOIN users u ON d.user_id = u.user_id 
                   WHERE d.status = 'Trashed'
                   ORDER BY d.trashed_at DESC"""
        result = await query_db.execute(query)
    else:
        query = """SELECT db_id, db_name, status, user_id, trashed_at, restore_deadline, file_path
                   FROM databases 
                   WHERE user_id = ? AND status = 'Trashed'
                   ORDER BY trashed_at DESC"""
        result = await query_db.execute(query, [actor.get("id")])
    
    trashed_databases = []
    for row in result:
        db_info = dict(row)
        
        # Calculate days until auto-delete
        days_until_delete = 0
        if db_info["restore_deadline"]:
            try:
                deadline = datetime.fromisoformat(db_info["restore_deadline"].replace('Z', '+00:00'))
                now = datetime.utcnow()
                delta = deadline - now
                days_until_delete = max(0, delta.days)
            except Exception as e:
                logger.error(f"Error calculating restore deadline: {e}")
        
        # Get database size and table count
        table_count = 0
        database_size = 0
        if db_info["file_path"] and os.path.exists(db_info["file_path"]):
            try:
                user_db = sqlite_utils.Database(db_info["file_path"])
                table_count = len(user_db.table_names())
                database_size = os.path.getsize(db_info["file_path"]) / 1024  # KB
            except Exception as e:
                logger.error(f"Error getting database info: {e}")
        
        db_info.update({
            'days_until_delete': days_until_delete,
            'table_count': table_count,
            'database_size': database_size,
            'trashed_at_formatted': db_info.get("trashed_at", "").split('T')[0] if db_info.get("trashed_at") else None,
            'is_expired': days_until_delete <= 0
        })
        
        trashed_databases.append(db_info)

    # Get content for page
    title = await query_db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
    title_row = title.first()
    content = {
        'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
        'description': {'content': 'Environmental data dashboard.'},
        'footer': {'content': 'Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': ['Made with \u2764\ufe0f by EDGI and Public Environmental Data Partners.']}
    }

    return Response.html(
        await datasette.render_template(
            "trash_bin.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "is_admin": is_admin,
                "trashed_databases": trashed_databases,
                "total_trashed": len(trashed_databases),
                "success": request.args.get('success'),
                "error": request.args.get('error'),
            },
            request=request
        )
    )


async def trash_database(datasette, request):
    """Tier 2: Move database to trash"""
    logger.debug(f"Trash Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Handle /db/{db_name}/trash path
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        confirm_db_name = post_vars.get("confirm_db_name", "").strip()
        
        # Validate confirmation
        if confirm_db_name != db_name:
            return Response.redirect(f"{request.path}?error=Database name confirmation does not match")
        
        try:
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor.get("id")]
            )
            db_info = result.first()
            if not db_info:
                return Response.text("Database not found or you do not have permission", status=404)
            
            if db_info['status'] == 'Trashed':
                return Response.redirect(f"/manage-databases?error=Database '{db_name}' is already in trash")
            
            if db_info['status'] == 'Deleted':
                return Response.redirect(f"/manage-databases?error=Database '{db_name}' has been permanently deleted")
            
            # Calculate restore deadline (30 days from now)
            trashed_at = datetime.utcnow()
            restore_deadline = trashed_at + timedelta(days=TRASH_RETENTION_DAYS)
            
            # Update status to Trashed (FIXED: removed deletion_reason)
            await query_db.execute_write(
                """UPDATE databases SET 
                status = 'Trashed', 
                trashed_at = ?, 
                restore_deadline = ?, 
                deleted_by_user_id = ?
                WHERE db_name = ?""",
                [trashed_at.isoformat(), restore_deadline.isoformat(), actor.get("id"), db_name]
            )
            
            # Unregister from Datasette
            try:
                if db_name in datasette.databases:
                    del datasette.databases[db_name]
                    logger.debug(f"Unregistered database {db_name} from Datasette")
            except Exception as unreg_error:
                logger.error(f"Error unregistering database {db_name}: {unreg_error}")
            
            # Get database stats for logging
            table_count = 0
            total_records = 0
            database_size = 0
            if db_info['file_path'] and os.path.exists(db_info['file_path']):
                try:
                    user_db = sqlite_utils.Database(db_info['file_path'])
                    table_names = user_db.table_names()
                    table_count = len(table_names)
                    for table_name in table_names:
                        try:
                            table_info = user_db[table_name]
                            total_records += table_info.count
                        except Exception:
                            continue
                    database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                except Exception as e:
                    logger.error(f"Error getting database stats: {e}")
            
            await log_database_action(
                datasette, actor.get("id"), "trash_database", 
                f"Moved database {db_name} to trash",
                {
                    "db_name": db_name,
                    "previous_status": db_info['status'],
                    "trashed_at": trashed_at.isoformat(),
                    "restore_deadline": restore_deadline.isoformat(),
                    "table_count": table_count,
                    "total_records": total_records,
                    "database_size_kb": database_size
                }
            )
            
            return Response.redirect(f"/manage-databases?success=Database '{db_name}' moved to trash. You have {TRASH_RETENTION_DAYS} days to restore it.")
            
        except Exception as e:
            logger.error(f"Error trashing database {db_name}: {str(e)}")
            return Response.text(f"Error moving database to trash: {str(e)}", status=500)
    
    # GET request - show confirmation page
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        # Get database statistics
        table_count = 0
        total_records = 0
        database_size = 0
        
        if db_info['file_path'] and os.path.exists(db_info['file_path']):
            try:
                user_db = sqlite_utils.Database(db_info['file_path'])
                table_names = user_db.table_names()
                table_count = len(table_names)
                
                for table_name in table_names:
                    try:
                        table_info = user_db[table_name]
                        total_records += table_info.count
                    except Exception:
                        continue
                
                database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
            except Exception as e:
                logger.error(f"Error getting database info for {db_name}: {str(e)}")

        # Get title content for template
        title_result = await query_db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
        title_row = title_result.first()
        content = {
            'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
            'description': {'content': 'Environmental data dashboard.'}
        }

        return Response.html(
            await datasette.render_template(
                "trash_confirm.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "db_name": db_name,
                    "db_status": db_info['status'],
                    "table_count": table_count,
                    "total_records": total_records,
                    "database_size": database_size,
                    "retention_days": TRASH_RETENTION_DAYS,
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error showing trash confirmation for {db_name}: {str(e)}")
        return Response.text(f"Error loading trash confirmation: {str(e)}", status=500)

async def restore_database(datasette, request):
    """Restore database from trash"""
    logger.debug(f"Restore Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Handle /db/{db_name}/restore path
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    
    try:
        # Check user permission (admin can restore any database)
        is_admin = actor.get("role") == "system_admin"
        if is_admin:
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status, restore_deadline FROM databases WHERE db_name = ? AND status = 'Trashed'",
                [db_name]
            )
        else:
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status, restore_deadline FROM databases WHERE db_name = ? AND user_id = ? AND status = 'Trashed'",
                [db_name, actor.get("id")]
            )
        
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found in trash or you do not have permission", status=404)
        
        # Check if restore deadline has passed (unless admin override)
        if not is_admin and db_info['restore_deadline']:
            try:
                deadline = datetime.fromisoformat(db_info['restore_deadline'].replace('Z', '+00:00'))
                now = datetime.utcnow()
                if now > deadline:
                    return Response.redirect(f"/trash?error=Database '{db_name}' restore deadline has passed")
            except Exception as e:
                logger.error(f"Error checking restore deadline: {e}")
        
        # Restore database to Draft status
        await query_db.execute_write(
            """UPDATE databases SET 
               status = 'Draft', 
               trashed_at = NULL, 
               restore_deadline = NULL, 
               deleted_by_user_id = NULL
               WHERE db_name = ?""",
            [db_name]
        )
        
        # Re-register with Datasette
        if db_info['file_path'] and os.path.exists(db_info['file_path']):
            try:
                db_instance = Database(datasette, path=db_info['file_path'], is_mutable=True)
                datasette.add_database(db_instance, name=db_name)
                logger.debug(f"Successfully re-registered restored database: {db_name}")
            except Exception as reg_error:
                logger.error(f"Error re-registering database {db_name}: {reg_error}")
        
        await log_database_action(
            datasette, actor.get("id"), "restore_database", 
            f"Restored database {db_name} from trash",
            {
                "db_name": db_name,
                "restored_by": actor.get("username"),
                "restored_by_admin": is_admin,
                "original_owner": db_info['user_id']
            }
        )
        
        redirect_page = "/trash" if request.args.get('from') == 'trash' else "/manage-databases"
        return Response.redirect(f"{redirect_page}?success=Database '{db_name}' restored successfully!")
        
    except Exception as e:
        logger.error(f"Error restoring database {db_name}: {str(e)}")
        return Response.text(f"Error restoring database: {str(e)}", status=500)

async def permanent_delete_database(datasette, request):
    """Tier 3: Permanent deletion of database"""
    logger.debug(f"Permanent Delete Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Handle both /db/{db_name}/delete-permanent and force delete paths
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
        is_force_delete = len(path_parts) > 3 and path_parts[3] == 'force'
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    is_admin = actor.get("role") == "system_admin"
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        confirm_input = post_vars.get("confirm_input", "").strip()
        
        # Different confirmation requirements
        if is_force_delete and is_admin:
            required_confirmation = "FORCE DELETE"
        else:
            required_confirmation = db_name
        
        if confirm_input != required_confirmation:
            return Response.redirect(f"{request.path}?error=Confirmation text does not match")
        
        try:
            # Check user permission
            if is_admin:
                result = await query_db.execute(
                    "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ?",
                    [db_name]
                )
            else:
                result = await query_db.execute(
                    "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
                    [db_name, actor.get("id")]
                )
            
            db_info = result.first()
            if not db_info:
                return Response.text("Database not found or you do not have permission", status=404)
            
            # For non-admin users, database must be in trash
            if not is_admin and db_info['status'] != 'Trashed':
                return Response.redirect(f"/manage-databases?error=Database must be in trash before permanent deletion")
            
            # Get database stats for logging before deletion
            table_count = 0
            total_records = 0
            database_size = 0
            if db_info['file_path'] and os.path.exists(db_info['file_path']):
                try:
                    user_db = sqlite_utils.Database(db_info['file_path'])
                    table_names = user_db.table_names()
                    table_count = len(table_names)
                    for table_name in table_names:
                        try:
                            table_info = user_db[table_name]
                            total_records += table_info.count
                        except Exception:
                            continue
                    database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                except Exception as e:
                    logger.error(f"Error getting database stats before deletion: {e}")
            
            # Remove from Datasette if registered
            try:
                if db_name in datasette.databases:
                    del datasette.databases[db_name]
                    logger.debug(f"Unregistered database {db_name} from Datasette")
            except Exception as unreg_error:
                logger.error(f"Error unregistering database {db_name}: {unreg_error}")
            
            # Delete database file and directory
            if db_info['file_path'] and os.path.exists(db_info['file_path']):
                try:
                    os.remove(db_info['file_path'])
                    # Try to remove directory if empty
                    db_dir = os.path.dirname(db_info['file_path'])
                    try:
                        os.rmdir(db_dir)
                    except OSError:
                        pass  # Directory not empty
                    logger.debug(f"Deleted database file: {db_info['file_path']}")
                except Exception as file_error:
                    logger.error(f"Error deleting database file: {file_error}")
            
            # Remove all database records and content
            await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_info['db_id']])
            await query_db.execute_write("DELETE FROM databases WHERE db_id = ?", [db_info['db_id']])
            
            # Enhanced logging
            action_type = "force_delete_database" if is_force_delete else "permanent_delete_database"
            await log_database_action(
                datasette, actor.get("id"), action_type, 
                f"Permanently deleted database {db_name}",
                {
                    "db_name": db_name,
                    "previous_status": db_info['status'],
                    "deleted_by": actor.get("username"),
                    "force_delete": is_force_delete,
                    "admin_delete": is_admin,
                    "table_count": table_count,
                    "total_records": total_records,
                    "database_size_kb": database_size,
                    "original_owner": db_info['user_id']
                }
            )
            
            success_msg = f"Database '{db_name}' permanently deleted"
            if is_force_delete:
                success_msg += " (force deleted by admin)"
            
            redirect_page = "/system-admin" if is_admin and request.args.get('from') == 'admin' else "/manage-databases"
            return Response.redirect(f"{redirect_page}?success={success_msg}")
            
        except Exception as e:
            logger.error(f"Error permanently deleting database {db_name}: {str(e)}")
            return Response.redirect(f"{request.path}?error=Error deleting database: {str(e)}")
    
    # GET request - show confirmation page
    try:
        if is_admin:
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status, trashed_at FROM databases WHERE db_name = ?",
                [db_name]
            )
        else:
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status, trashed_at FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor.get("id")]
            )
        
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        # Convert sqlite3.Row to dict for easier access
        db_dict = dict(db_info)
        
        # Get database statistics
        table_count = 0
        total_records = 0
        database_size = 0
        
        if db_dict['file_path'] and os.path.exists(db_dict['file_path']):
            try:
                user_db = sqlite_utils.Database(db_dict['file_path'])
                table_names = user_db.table_names()
                table_count = len(table_names)
                
                for table_name in table_names:
                    try:
                        table_info = user_db[table_name]
                        total_records += table_info.count
                    except Exception:
                        continue
                
                database_size = os.path.getsize(db_dict['file_path']) / 1024  # KB
            except Exception as e:
                logger.error(f"Error getting database info for {db_name}: {str(e)}")

        # Get title content for template
        title_result = await query_db.execute("SELECT content FROM admin_content WHERE db_id IS NULL AND section = ?", ["title"])
        title_row = title_result.first()
        content = {
            'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'},
            'description': {'content': 'Environmental data dashboard.'}
        }

        return Response.html(
            await datasette.render_template(
                "permanent_delete_confirm.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "is_admin": is_admin,
                    "is_force_delete": is_force_delete,
                    "db_name": db_name,
                    "db_status": db_dict['status'],
                    "table_count": table_count,
                    "total_records": total_records,
                    "database_size": database_size,
                    "trashed_at": db_dict['trashed_at'].split('T')[0] if db_dict['trashed_at'] else None,
                    "required_confirmation": "FORCE DELETE" if is_force_delete and is_admin else db_name,
                    "error": request.args.get('error'),
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error showing permanent delete confirmation for {db_name}: {str(e)}")
        return Response.text(f"Error loading permanent delete confirmation: {str(e)}", status=500)

async def auto_cleanup_expired_databases(datasette):
    """Background task to automatically delete expired databases."""
    logger.debug("Running auto cleanup for expired databases")
    
    query_db = datasette.get_database('portal')
    try:
        # Find databases past their restore deadline
        now = datetime.utcnow()
        result = await query_db.execute(
            """SELECT db_id, db_name, user_id, file_path, restore_deadline 
               FROM databases 
               WHERE status = 'Trashed' AND restore_deadline < ?""",
            [now.isoformat()]
        )
        
        expired_databases = [dict(row) for row in result]
        
        for db_info in expired_databases:
            db_name = db_info['db_name']
            db_id = db_info['db_id']
            
            try:
                # Get database stats for logging before deletion
                table_count = 0
                total_records = 0
                database_size = 0
                if db_info['file_path'] and os.path.exists(db_info['file_path']):
                    try:
                        user_db = sqlite_utils.Database(db_info['file_path'])
                        table_names = user_db.table_names()
                        table_count = len(table_names)
                        for table_name in table_names:
                            try:
                                table_info = user_db[table_name]
                                total_records += table_info.count
                            except Exception:
                                continue
                        database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                    except Exception as e:
                        logger.error(f"Error getting database stats for auto-cleanup: {e}")
                
                # Remove from Datasette if registered
                try:
                    if db_name in datasette.databases:
                        del datasette.databases[db_name]
                        logger.debug(f"Unregistered database {db_name} from Datasette during auto-cleanup")
                except Exception as unreg_error:
                    logger.error(f"Error unregistering database {db_name} during auto-cleanup: {unreg_error}")
                
                # Delete database file and directory
                if db_info['file_path'] and os.path.exists(db_info['file_path']):
                    try:
                        os.remove(db_info['file_path'])
                        # Try to remove directory if empty
                        db_dir = os.path.dirname(db_info['file_path'])
                        try:
                            os.rmdir(db_dir)
                        except OSError:
                            pass  # Directory not empty
                        logger.debug(f"Auto-deleted database file: {db_info['file_path']}")
                    except Exception as file_error:
                        logger.error(f"Error deleting database file during auto-cleanup: {file_error}")
                
                # Remove all database records and content
                await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_id])
                await query_db.execute_write("DELETE FROM databases WHERE db_id = ?", [db_id])
                
                # Log the auto-deletion
                await log_database_action(
                    datasette, "system", "auto_delete_database", 
                    f"Auto-deleted expired database {db_name}",
                    {
                        "db_name": db_name,
                        "original_owner": db_info['user_id'],
                        "restore_deadline": db_info['restore_deadline'],
                        "table_count": table_count,
                        "total_records": total_records,
                        "database_size_kb": database_size,
                        "auto_cleanup": True
                    }
                )
                
                logger.info(f"Auto-deleted expired database: {db_name}")
                
            except Exception as e:
                logger.error(f"Error during auto-cleanup of database {db_name}: {e}")
        
        if expired_databases:
            logger.info(f"Auto-cleanup completed: {len(expired_databases)} databases deleted")
        else:
            logger.debug("Auto-cleanup completed: no expired databases found")
            
    except Exception as e:
        logger.error(f"Error during auto-cleanup process: {e}")

@hookimpl
def register_routes():
    """Register database deletion routes"""
    return [
        (r"^/trash$", trash_bin_page),
        (r"^/db/([^/]+)/unpublish$", unpublish_database),
        (r"^/db/([^/]+)/trash$", trash_database),
        (r"^/db/([^/]+)/restore$", restore_database),
        (r"^/db/([^/]+)/delete-permanent$", permanent_delete_database),
        (r"^/db/([^/]+)/delete-permanent/force$", permanent_delete_database),
    ]