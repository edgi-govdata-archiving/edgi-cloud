"""
Database Deletion Module - Three-tier deletion system
Handles: Unpublish → Trash → Permanent Delete
FIXED: Windows file locking issues
"""

import os
import json
import uuid
import logging
import sqlite_utils
import base64
from pathlib import Path
from datetime import datetime, timedelta
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database

# Add the plugins directory to Python path for imports
import sys
plugins_dir = os.path.dirname(os.path.abspath(__file__))
if plugins_dir not in sys.path:
    sys.path.insert(0, plugins_dir)

# Import from common_utils
from common_utils import (
    get_actor_from_request,
    log_database_action,
    verify_user_session,
    get_portal_content,
    handle_form_errors,
    get_success_error_from_request,
    user_owns_database,
    DATA_DIR,
    TRASH_RETENTION_DAYS
)

logger = logging.getLogger(__name__)

def force_close_database_connections(datasette, db_name):
    """ENHANCED: Force close all database connections - Windows compatible"""
    import gc
    import time
    
    logger.info(f"Force closing all connections for database: {db_name}")
    
    try:
        # Step 1: Remove from Datasette registry first
        if db_name in datasette.databases:
            try:
                db_instance = datasette.databases[db_name]
                
                # Close internal database connection
                if hasattr(db_instance, '_internal_db') and db_instance._internal_db:
                    try:
                        db_instance._internal_db.close()
                        logger.debug(f"Closed _internal_db for {db_name}")
                    except Exception as close_error:
                        logger.error(f"Error closing _internal_db: {close_error}")
                
                # Close any other database attributes
                if hasattr(db_instance, 'db') and db_instance.db:
                    try:
                        db_instance.db.close()
                        logger.debug(f"Closed db attribute for {db_name}")
                    except Exception as close_error:
                        logger.error(f"Error closing db attribute: {close_error}")
                
                # Remove from datasette
                del datasette.databases[db_name]
                logger.debug(f"Removed {db_name} from Datasette registry")
                
            except Exception as unreg_error:
                logger.error(f"Error during database unregistration: {unreg_error}")
        
        # Step 2: Force garbage collection multiple times
        for i in range(3):  # Reduced from 5 to 3
            gc.collect()
            time.sleep(0.1)  # Reduced from 0.2 to 0.1
        
        # Step 3: Wait for Windows to release file handles
        time.sleep(1.0)  # Reduced from 2.0 to 1.0
        
        logger.info(f"Completed connection cleanup for {db_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error in force_close_database_connections: {e}")
        return False
    
def enhanced_file_deletion(file_path, db_name):
    """ENHANCED: Multi-strategy file deletion for Windows - REDUCED DELAYS"""
    import time
    import tempfile
    import shutil
    
    logger.info(f"Enhanced file deletion for: {file_path}")
    
    if not os.path.exists(file_path):
        logger.info(f"File doesn't exist, deletion considered successful: {file_path}")
        return True
    
    # Strategy 1: Direct deletion
    try:
        os.remove(file_path)
        logger.info(f"Strategy 1 (direct) succeeded: {file_path}")
        return True
    except OSError as e:
        logger.warning(f"Strategy 1 (direct) failed: {e}")
    
    # Strategy 2: Move to temp directory then delete
    try:
        temp_dir = tempfile.gettempdir()
        temp_name = f"deleted_{db_name}_{int(time.time())}_{os.getpid()}.db"
        temp_path = os.path.join(temp_dir, temp_name)
        
        shutil.move(file_path, temp_path)
        logger.info(f"Strategy 2 (move to temp) succeeded: {file_path} -> {temp_path}")
        
        # Try to delete from temp location
        try:
            time.sleep(0.5)  # Keep this delay for temp cleanup
            os.remove(temp_path)
            logger.info(f"Temp file deleted: {temp_path}")
        except OSError:
            logger.info(f"Temp file will be cleaned up by system: {temp_path}")
        
        return True
        
    except OSError as e:
        logger.warning(f"Strategy 2 (move to temp) failed: {e}")
    
    # Strategy 3: Rename with timestamp and mark for cleanup
    try:
        timestamp = int(time.time())
        deleted_name = f"{file_path}.DELETED_{timestamp}_{os.getpid()}"
        
        os.rename(file_path, deleted_name)
        logger.info(f"Strategy 3 (rename) succeeded: {file_path} -> {deleted_name}")
        
        # Try to delete renamed file
        try:
            time.sleep(0.5)  # Keep this delay for rename cleanup
            os.remove(deleted_name)
            logger.info(f"Renamed file deleted: {deleted_name}")
        except OSError:
            logger.info(f"Renamed file marked for cleanup: {deleted_name}")
        
        return True
        
    except OSError as e:
        logger.warning(f"Strategy 3 (rename) failed: {e}")
    
    # Strategy 4: Truncate file (last resort)
    try:
        with open(file_path, 'w') as f:
            f.write('')  # Truncate to empty
        
        logger.info(f"Strategy 4 (truncate) succeeded: {file_path}")
        
        # Try rename after truncate
        try:
            time.sleep(0.5)  # Keep this delay for truncate
            truncated_name = f"{file_path}.TRUNCATED_{int(time.time())}"
            os.rename(file_path, truncated_name)
            logger.info(f"Truncated file renamed: {truncated_name}")
            return True
        except OSError:
            logger.info(f"File truncated but still locked: {file_path}")
            return True  # Consider truncation as successful deletion
            
    except OSError as e:
        logger.error(f"All deletion strategies failed: {e}")
        return False
    
async def trash_database(datasette, request):
    """Tier 2: Move database to trash - supports admin override"""
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
            # Check if user owns the database OR is system admin
            is_admin = actor.get("role") == "system_admin"
            
            if is_admin:
                # Admin can trash any database
                result = await query_db.execute(
                    "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ?",
                    [db_name]
                )
            else:
                # Regular user can only trash their own databases
                result = await query_db.execute(
                    "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
                    [db_name, actor.get("id")]
                )
            
            db_info = result.first()
            if not db_info:
                if is_admin:
                    return Response.text("Database not found", status=404)
                else:
                    return Response.text("Database not found or you do not have permission", status=404)
            
            db_info = dict(db_info)

            if db_info['status'] == 'Trashed':
                redirect_url = "/system-admin" if is_admin else "/manage-databases"
                return Response.redirect(f"{redirect_url}?error=Database '{db_name}' is already in trash")
            
            if db_info['status'] == 'Deleted':
                redirect_url = "/system-admin" if is_admin else "/manage-databases"
                return Response.redirect(f"{redirect_url}?error=Database '{db_name}' has been permanently deleted")
            
            # Calculate restore deadline (30 days from now)
            trashed_at = datetime.utcnow()
            restore_deadline = trashed_at + timedelta(days=TRASH_RETENTION_DAYS)
            
            # CRITICAL: Close database connections BEFORE updating status
            force_close_database_connections(datasette, db_name)
            
            # Update status to Trashed with updated_at timestamp
            await query_db.execute_write(
                """UPDATE databases SET 
                status = 'Trashed', 
                trashed_at = ?, 
                restore_deadline = ?, 
                deleted_by_user_id = ?,
                updated_at = ?
                WHERE db_name = ?""",
                [trashed_at.isoformat(), restore_deadline.isoformat(), actor.get("id"), trashed_at.isoformat(), db_name]
            )
            
            # Get database stats for logging (safe file size only)
            database_size = 0
            if db_info['file_path'] and os.path.exists(db_info['file_path']):
                try:
                    database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                except Exception as e:
                    logger.error(f"Error getting database size: {e}")
            
            # Log with admin context if applicable
            action_details = f"Moved database {db_name} to trash"
            if is_admin and db_info['user_id'] != actor.get("id"):
                action_details = f"Admin moved database {db_name} (owned by user {db_info['user_id']}) to trash"
            
            await log_database_action(
                datasette, actor.get("id"), "trash_database", 
                action_details,
                {
                    "db_name": db_name,
                    "previous_status": db_info['status'],
                    "trashed_at": trashed_at.isoformat(),
                    "restore_deadline": restore_deadline.isoformat(),
                    "database_size_kb": database_size,
                    "admin_override": is_admin and db_info['user_id'] != actor.get("id"),
                    "target_user_id": db_info['user_id'] if is_admin else None
                }
            )
            
            # Redirect appropriately
            if is_admin:
                return Response.redirect(f"/system-admin?success=Database '{db_name}' moved to trash. You have {TRASH_RETENTION_DAYS} days to restore it.")
            else:
                return Response.redirect(f"/manage-databases?success=Database '{db_name}' moved to trash. You have {TRASH_RETENTION_DAYS} days to restore it.")
            
        except Exception as e:
            logger.error(f"Error trashing database {db_name}: {str(e)}")
            return Response.text(f"Error moving database to trash: {str(e)}", status=500)
    
    # GET request - show confirmation page
    try:
        # Check if user owns the database OR is system admin
        is_admin = actor.get("role") == "system_admin"
        
        if is_admin:
            # Admin can view any database
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ?",
                [db_name]
            )
        else:
            # Regular user can only view their own databases
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor.get("id")]
            )
        
        db_info = result.first()
        if not db_info:
            if is_admin:
                return Response.text("Database not found", status=404)
            else:
                return Response.text("Database not found or you do not have permission", status=404)
        
        # Get database statistics safely
        table_count = 0
        total_records = 0
        database_size = 0
        
        if db_info['file_path'] and os.path.exists(db_info['file_path']):
            try:
                database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                
                # Get stats safely without locking file
                user_db = sqlite_utils.Database(db_info['file_path'])
                table_names = user_db.table_names()
                table_count = len(table_names)
                
                for table_name in table_names:
                    try:
                        table_info = user_db[table_name]
                        total_records += table_info.count
                    except Exception:
                        continue
                
                user_db.close()
                
            except Exception as e:
                logger.error(f"Error getting database info for {db_name}: {str(e)}")

        # Get content for template
        content = await get_portal_content(datasette)

        return Response.html(
            await datasette.render_template(
                "trash_confirm.html",  # Same template for both user and admin
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
                    "is_admin_override": is_admin and db_info['user_id'] != actor.get("id"),
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error showing trash confirmation for {db_name}: {str(e)}")
        return Response.text(f"Error loading trash confirmation: {str(e)}", status=500)
    
async def restore_database(datasette, request):
    """Restore database from trash - Only own databases"""
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
        # Only allow users to restore their own databases
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status, restore_deadline FROM databases WHERE db_name = ? AND user_id = ? AND status = 'Trashed'",
            [db_name, actor.get("id")]
        )
        
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found in trash or you do not have permission", status=404)
        
        db_info = dict(db_info)

        # Check if restore deadline has passed
        if db_info['restore_deadline']:
            try:
                deadline = datetime.fromisoformat(db_info['restore_deadline'].replace('Z', '+00:00'))
                now = datetime.utcnow()
                if now > deadline:
                    return Response.redirect(f"/trash?error=Database '{db_name}' restore deadline has passed")
            except Exception as e:
                logger.error(f"Error checking restore deadline: {e}")
        
        # Restore database to Draft status with updated timestamp
        current_time = datetime.utcnow().isoformat()
        await query_db.execute_write(
            """UPDATE databases SET 
               status = 'Draft', 
               trashed_at = NULL, 
               restore_deadline = NULL, 
               deleted_by_user_id = NULL,
               updated_at = ?
               WHERE db_name = ?""",
            [current_time, db_name]
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
                "original_owner": db_info['user_id']
            }
        )
        
        # Check where the restore request came from and redirect appropriately
        from_param = request.args.get('from', '')
        is_admin = actor.get("role") == "system_admin"
        
        if from_param == 'system-trash' and is_admin:
            # Admin restoring from system trash - stay in system trash
            return Response.redirect(f"/system-trash?success=Database '{db_name}' restored successfully!")
        elif from_param == 'trash' or from_param == 'user-trash':
            # User restoring from their own trash
            return Response.redirect(f"/manage-databases?status=trash&success=Database '{db_name}' restored successfully!")
        else:
            # Default behavior - check user role
            if is_admin:
                return Response.redirect(f"/system-trash?success=Database '{db_name}' restored successfully!")
            else:
                return Response.redirect(f"/manage-databases?success=Database '{db_name}' restored successfully!")
        
    except Exception as e:
        logger.error(f"Error restoring database {db_name}: {str(e)}")
        return Response.text(f"Error restoring database: {str(e)}", status=500)
    
async def auto_cleanup_expired_databases(datasette):
    """Background task to automatically delete expired databases - ENHANCED for renamed databases"""
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
            original_db_name = db_name  # Store original name for logging
            
            try:
                # Get database statistics SAFELY (minimal file access)
                database_size = 0
                
                # Build file path if not available
                if not db_info.get('file_path'):
                    db_info['file_path'] = os.path.join(DATA_DIR, db_info['user_id'], f"{db_name}.db")
                
                if db_info['file_path'] and os.path.exists(db_info['file_path']):
                    try:
                        database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                        logger.debug(f"Auto-cleanup stats for {db_name}: {database_size}KB")
                    except Exception as e:
                        logger.error(f"Error getting file size for {db_name} in auto-cleanup: {e}")
                
                # Force close database connections (use original db_name for Datasette registry)
                force_close_database_connections(datasette, db_name)
                
                # ENHANCED FILE DELETION
                file_deleted = False
                if db_info['file_path'] and os.path.exists(db_info['file_path']):
                    file_deleted = enhanced_file_deletion(db_info['file_path'], db_name)
                else:
                    file_deleted = True  # No file to delete
                
                # HANDLE DELETION FAILURE (keep database record for manual retry)
                if not file_deleted:
                    logger.warning(f"Auto-cleanup: File deletion failed for {db_name}, keeping database record")
                    
                    # Log the failure but don't delete database record
                    await log_database_action(
                        datasette, "system", "auto_cleanup_failed", 
                        f"Auto-cleanup failed for {db_name} - file deletion unsuccessful",
                        {
                            "db_name": db_name,
                            "original_owner": db_info['user_id'],
                            "restore_deadline": db_info['restore_deadline'],
                            "reason": "file_deletion_failed",
                            "file_path": db_info['file_path']
                        }
                    )
                    
                    # Skip to next database (keep this one for manual cleanup)
                    continue
                
                # RENAME DATABASE TO FREE UP THE NAME
                import time
                deleted_name = f"{db_name}_deleted_{int(time.time())}_{db_id[:8]}"
                
                # UPDATE DATABASE RECORD: RENAME AND MARK AS DELETED
                current_time = datetime.utcnow().isoformat()
                await query_db.execute_write(
                    """UPDATE databases SET 
                       db_name = ?,
                       status = 'Deleted',
                       deleted_at = ?,
                       updated_at = ?
                       WHERE db_id = ?""",
                    [deleted_name, current_time, current_time, db_id]
                )
                
                # Delete related admin content
                await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_id])
                
                # Log successful auto-deletion
                await log_database_action(
                    datasette, "system", "auto_delete_database", 
                    f"Auto-deleted expired database {original_db_name} (renamed to {deleted_name})",
                    {
                        "original_db_name": original_db_name,
                        "renamed_to": deleted_name,
                        "original_owner": db_info['user_id'],
                        "restore_deadline": db_info['restore_deadline'],
                        "database_size_kb": database_size,
                        "auto_cleanup": True,
                        "file_deleted": file_deleted
                    }
                )
                
                logger.info(f"Auto-deleted expired database: {original_db_name} (renamed to {deleted_name})")
                
            except Exception as e:
                logger.error(f"Error during auto-cleanup of database {db_name}: {e}")
                # Continue with other databases even if one fails
                continue
        
        # Summary logging
        if expired_databases:
            successful_deletions = len([db for db in expired_databases if db])
            logger.info(f"Auto-cleanup completed: processed {len(expired_databases)} expired databases")
        else:
            logger.debug("Auto-cleanup completed: no expired databases found")
            
    except Exception as e:
        logger.error(f"Error during auto-cleanup process: {e}")

async def system_trash_bin_page(datasette, request):
    """System-wide trash bin page for administrators."""
    logger.debug(f"System Trash Bin request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.redirect("/login?error=Admin access required")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    query_db = datasette.get_database('portal')
    
    # Get ALL trashed databases system-wide for admins
    # FIXED: Include file_path in query and use proper user_id
    query = """SELECT d.db_id, d.db_name, d.status, d.user_id, d.trashed_at, d.restore_deadline, 
                      d.file_path, u.username, u.email
               FROM databases d 
               JOIN users u ON d.user_id = u.user_id 
               WHERE d.status = 'Trashed'
               ORDER BY d.trashed_at DESC"""
    result = await query_db.execute(query)
    
    trashed_databases = []
    for row in result:
        db_info = dict(row)
        
        # Admin can see all but can only restore/delete their own
        is_own_database = db_info["user_id"] == actor.get("id")
        
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
        
        # Get database size and statistics safely
        table_count = 0
        total_records = 0
        database_size = 0
        
        try:
            # Build the file path if not available
            if not db_info.get("file_path"):
                db_info["file_path"] = os.path.join(DATA_DIR, db_info["user_id"], f"{db_info['db_name']}.db")
            
            if db_info["file_path"] and os.path.exists(db_info["file_path"]):
                # Get file size (doesn't open database)
                database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                
                # Get table count and records safely
                try:
                    user_db = sqlite_utils.Database(db_info['file_path'])
                    table_names = user_db.table_names()
                    table_count = len(table_names)
                    
                    # Get total records
                    for table_name in table_names:
                        try:
                            table_info = user_db[table_name]
                            total_records += table_info.count
                        except Exception:
                            continue
                    
                    user_db.close()
                    logger.debug(f"Trash stats for {db_info['db_name']}: {table_count} tables, {total_records} records, {database_size:.1f}KB")
                except Exception as db_error:
                    logger.warning(f"Could not access trashed database {db_info['db_name']}: {db_error}")
                    # Keep file size but set others to 0
                    table_count = 0
                    total_records = 0
            else:
                logger.warning(f"Trashed database file not found: {db_info.get('file_path')} for {db_info['db_name']}")
                database_size = 0
                table_count = 0
                total_records = 0
                
        except Exception as e:
            logger.error(f"Error getting file size for {db_info['db_name']}: {e}")
            database_size = 0
            table_count = 0
            total_records = 0

        db_info.update({
            'days_until_delete': days_until_delete,
            'table_count': table_count,
            'total_records': total_records,
            'database_size': database_size,
            'trashed_at_formatted': db_info.get("trashed_at", "").split('T')[0] if db_info.get("trashed_at") else None,
            'is_expired': days_until_delete <= 0,
            'is_own_database': is_own_database
        })
        
        trashed_databases.append(db_info)

    # Get content for page
    content = await get_portal_content(datasette)

    return Response.html(
        await datasette.render_template(
            "system_trash_bin.html",  # Different template for system trash
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "is_admin": True,
                "trashed_databases": trashed_databases,
                "total_trashed": len(trashed_databases),
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def permanent_delete_database(datasette, request):
    """Tier 3: Permanent deletion - FIXED to rename database"""
    logger.debug(f"Permanent Delete Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # This function should ONLY handle regular user deletes: /db/{db_name}/delete-permanent
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3 and path_parts[2] == 'delete-permanent':
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        confirm_db_name = post_vars.get("confirm_db_name", "").strip()
        
        if confirm_db_name != db_name:
            return Response.redirect(f"{request.path}?error=Database name confirmation does not match")
        
        try:
            # Regular user can only delete their own trashed databases
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor.get("id")]
            )
            
            db_info = result.first()
            if not db_info:
                return Response.text("Database not found or you do not have permission", status=404)
            
            db_info = dict(db_info)

            if db_info['status'] != 'Trashed':
                return Response.redirect(f"/manage-databases?error=Database must be in trash before permanent deletion")
            
            # Get basic file size only (no database access)
            database_size = 0
            actual_file_path = None
            
            file_paths_to_try = [
                db_info['file_path'],
                os.path.join(DATA_DIR, db_info['user_id'], f"{db_name}.db")
            ]
            
            for path in file_paths_to_try:
                if path and os.path.exists(path):
                    actual_file_path = path
                    break
            
            if actual_file_path:
                try:
                    database_size = os.path.getsize(actual_file_path) / 1024  # KB
                except Exception as e:
                    logger.error(f"Error getting file size: {e}")
            
            logger.debug(f"File deletion attempt for: {actual_file_path}")
            
            # CRITICAL: Force close all database connections
            success = force_close_database_connections(datasette, db_name)
            if not success:
                logger.warning(f"Connection cleanup had issues for {db_name}")
            
            # ENHANCED FILE DELETION
            file_deleted = False
            if actual_file_path and os.path.exists(actual_file_path):
                file_deleted = enhanced_file_deletion(actual_file_path, db_name)
            else:
                logger.warning(f"No file found to delete for {db_name}")
                file_deleted = True  # Consider as successful if no file exists
            
            # HANDLE DELETION FAILURE
            if not file_deleted:
                logger.warning(f"Permanent deletion: File deletion failed for {db_name}, keeping database record")
                
                await log_database_action(
                    datasette, actor.get("id"), "deletion_failed", 
                    f"Permanent deletion failed for {db_name} - file deletion unsuccessful",
                    {
                        "db_name": db_name,
                        "reason": "file_deletion_failed",
                        "file_path": actual_file_path,
                        "is_admin_force_delete": False
                    }
                )
                
                return Response.redirect(f"/trash?error=Database '{db_name}' deletion failed. File could not be removed. Please try again or contact administrator.")
            
            # RENAME DATABASE TO FREE UP THE NAME FOR FUTURE USE
            import time
            deleted_name = f"{db_name}_deleted_{int(time.time())}_{db_info['db_id'][:8]}"
            
            # Update database record: rename and mark as deleted
            current_time = datetime.utcnow().isoformat()
            await query_db.execute_write(
                """UPDATE databases SET 
                   db_name = ?,
                   status = 'Deleted',
                   deleted_at = ?,
                   updated_at = ?
                   WHERE db_id = ?""",
                [deleted_name, current_time, current_time, db_info['db_id']]
            )
            
            # Delete related admin content (homepage customizations)
            await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_info['db_id']])
            
            # Success logging
            await log_database_action(
                datasette, actor.get("id"), "permanent_delete_database", 
                f"Permanently deleted database {db_name} (renamed to {deleted_name})",
                {
                    "original_db_name": db_name,
                    "renamed_to": deleted_name,
                    "deleted_by": actor.get("username"),
                    "database_size_kb": database_size,
                    "file_deleted": file_deleted
                }
            )
            
            return Response.redirect(f"/manage-databases?success=Database '{db_name}' permanently deleted")
            
        except Exception as e:
            logger.error(f"Error during deletion of database {db_name}: {str(e)}")
            return Response.redirect(f"{request.path}?error=Error deleting database: {str(e)}")
        
    # GET request - show confirmation page for regular delete
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status, trashed_at FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        db_dict = dict(db_info)
        
        # Get minimal stats safely - AVOID DUPLICATE CONNECTIONS
        table_count = None  # Set to None if we can't get it safely
        database_size = 0
        
        # Fallback: get file size if available
        if db_dict['file_path'] and os.path.exists(db_dict['file_path']):
            try:
                database_size = os.path.getsize(db_dict['file_path']) / 1024  # KB
                
                # Try to get table count ONLY if we can do it safely
                try:
                    user_db = sqlite_utils.Database(db_dict['file_path'])
                    table_names = user_db.table_names()
                    table_count = len(table_names)
                    user_db.close()  # Explicitly close
                except Exception as e:
                    logger.warning(f"Could not get table count for {db_name}: {str(e)}")
                    table_count = None
                    
            except Exception as e:
                logger.error(f"Error getting stats for {db_name}: {str(e)}")

        # Get content for template
        content = await get_portal_content(datasette)

        return Response.html(
            await datasette.render_template(
                "permanent_delete.html",  # RENAMED TEMPLATE
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "db_name": db_name,
                    "db_status": db_dict['status'],
                    "table_count": table_count,  # Can be None
                    "database_size": database_size,
                    "trashed_at": db_dict['trashed_at'].split('T')[0] if db_dict.get('trashed_at') else None,
                    **get_success_error_from_request(request)
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error showing delete confirmation for {db_name}: {str(e)}")
        return Response.text(f"Error loading delete confirmation: {str(e)}", status=500)

async def admin_force_delete_confirmation(datasette, request):
    """Admin force delete confirmation page - FIXED to rename database"""
    logger.debug(f"Admin Force Delete Confirmation request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor or actor.get("role") != "system_admin":
        return Response.redirect("/login?error=Admin access required")

    # Handle /admin-force-delete/{db_name} path
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'admin-force-delete' and len(path_parts) >= 2:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        confirm_text = post_vars.get("confirm_text", "").strip()
        admin_reason = post_vars.get("admin_reason", "").strip()
        admin_notes = post_vars.get("admin_notes", "").strip()
        
        required_text = f"FORCE DELETE {db_name}"
        
        # Validate confirmation
        if confirm_text != required_text:
            return Response.redirect(f"{request.path}?error=Confirmation text does not match")
        
        if not admin_reason:
            return Response.redirect(f"{request.path}?error=Administrative reason is required")
        
        try:
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ?",
                [db_name]
            )
            db_info = result.first()
            if not db_info:
                return Response.text("Database not found", status=404)
            
            # Get owner info for logging
            owner_result = await query_db.execute(
                "SELECT username FROM users WHERE user_id = ?",
                [db_info['user_id']]
            )
            owner_info = owner_result.first()
            owner_username = owner_info['username'] if owner_info else 'Unknown'
            
            # Get basic file size only (no database access)
            database_size = 0
            actual_file_path = None
            
            file_paths_to_try = [
                db_info['file_path'],
                os.path.join(DATA_DIR, db_info['user_id'], f"{db_name}.db")
            ]
            
            for path in file_paths_to_try:
                if path and os.path.exists(path):
                    actual_file_path = path
                    break
            
            if actual_file_path:
                try:
                    database_size = os.path.getsize(actual_file_path) / 1024  # KB
                except Exception as e:
                    logger.error(f"Error getting file size: {e}")
            
            logger.debug(f"Admin force deletion attempt for: {actual_file_path}")
            
            # CRITICAL: Force close all database connections
            success = force_close_database_connections(datasette, db_name)
            if not success:
                logger.warning(f"Connection cleanup had issues for {db_name}")
            
            # ENHANCED FILE DELETION
            file_deleted = False
            if actual_file_path and os.path.exists(actual_file_path):
                file_deleted = enhanced_file_deletion(actual_file_path, db_name)
            else:
                logger.warning(f"No file found to delete for {db_name}")
                file_deleted = True  # Consider as successful if no file exists
            
            # RENAME DATABASE TO FREE UP THE NAME
            import time
            deleted_name = f"{db_name}_deleted_{int(time.time())}_{db_info['db_id'][:8]}"
            
            # UPDATE DATABASE RECORD TO "DELETED" STATUS WITH RENAME
            current_time = datetime.utcnow()
            
            # Combine admin reason and notes for audit trail
            deletion_reason = admin_reason
            if admin_notes.strip():
                deletion_reason += f" | Notes: {admin_notes.strip()}"
            
            await query_db.execute_write(
                """UPDATE databases SET 
                   db_name = ?,
                   status = 'Deleted',
                   deleted_at = ?,
                   deletion_reason = ?,
                   deleted_by_user_id = ?,
                   updated_at = ?
                   WHERE db_id = ?""",
                [
                    deleted_name,  # RENAME THE DATABASE
                    current_time.isoformat(),
                    deletion_reason,
                    actor.get("id"),  # Admin who performed the action
                    current_time.isoformat(),
                    db_info['db_id']
                ]
            )
            
            # Delete related admin content (homepage customizations)
            await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_info['db_id']])
            
            # Enhanced logging for admin force delete with all audit details
            await log_database_action(
                datasette, actor.get("id"), "admin_force_delete_database", 
                f"Admin force deleted database {db_name} (renamed to {deleted_name}) owned by {owner_username}",
                {
                    "original_db_name": db_name,
                    "renamed_to": deleted_name,
                    "db_id": db_info['db_id'],
                    "target_user": owner_username,
                    "target_user_id": db_info['user_id'],
                    "admin_reason": admin_reason,
                    "admin_notes": admin_notes,
                    "database_size_kb": database_size,
                    "file_deleted": file_deleted,
                    "admin_override": True,
                    "bypassed_user_permissions": True,
                    "audit_trail": "Database record retained for audit purposes"
                }
            )
            
            logger.info(f"Admin force deleted database: {db_name} (renamed to {deleted_name}) by {actor.get('username')}, reason: {admin_reason}")
            
            return Response.redirect(f"/system-trash?success=Database '{db_name}' force deleted successfully. Database record retained for audit trail.")
            
        except Exception as e:
            logger.error(f"Error during admin force deletion of database {db_name}: {str(e)}")
            return Response.redirect(f"{request.path}?error=Error during force deletion: {str(e)}")
        
    # GET request - show force delete confirmation page
    try:
        result = await query_db.execute(
            """SELECT d.db_id, d.user_id, d.file_path, d.status, d.trashed_at, u.username, u.email
               FROM databases d 
               JOIN users u ON d.user_id = u.user_id 
               WHERE d.db_name = ?""",
            [db_name]
        )
        
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        db_dict = dict(db_info)
        
        # Get basic stats safely - MINIMAL DATABASE ACCESS
        database_size = 0
        
        # Only get file size if possible
        if db_dict['file_path'] and os.path.exists(db_dict['file_path']):
            try:
                database_size = os.path.getsize(db_dict['file_path']) / 1024  # KB
            except Exception as e:
                logger.error(f"Error getting file size for {db_name}: {str(e)}")

        # Get content for template
        content = await get_portal_content(datasette)

        return Response.html(
            await datasette.render_template(
                "force_delete.html",  # Use dedicated force_delete.html template
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "db_name": db_name,
                    "db_status": db_dict['status'],
                    "owner_username": db_dict['username'],
                    "owner_email": db_dict.get('email', 'Not available'),
                    "database_size": database_size,
                    "trashed_at": db_dict['trashed_at'].split('T')[0] if db_dict['trashed_at'] else None,
                    **get_success_error_from_request(request)
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error showing admin force delete confirmation for {db_name}: {str(e)}")
        return Response.text(f"Error loading force delete confirmation: {str(e)}", status=500)
    
@hookimpl
def register_routes():
    """FIXED: Register database deletion routes with proper separation"""
    return [
        (r"^/system-trash$", system_trash_bin_page),  # System admin trash
        (r"^/admin-force-delete/([^/]+)$", admin_force_delete_confirmation),  # Admin force delete - SEPARATE ROUTE
        (r"^/db/([^/]+)/trash$", trash_database),
        (r"^/db/([^/]+)/restore$", restore_database),
        (r"^/db/([^/]+)/delete-permanent$", permanent_delete_database),  # Regular user delete only
    ]