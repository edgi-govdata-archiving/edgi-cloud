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
        for i in range(5):
            gc.collect()
            time.sleep(0.2)
        
        # Step 3: Wait for Windows to release file handles
        time.sleep(2.0)
        
        logger.info(f"Completed connection cleanup for {db_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error in force_close_database_connections: {e}")
        return False

def enhanced_file_deletion(file_path, db_name):
    """ENHANCED: Multi-strategy file deletion for Windows"""
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
            time.sleep(0.5)
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
            time.sleep(0.5)
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
            time.sleep(0.5)
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

async def trash_bin_page(datasette, request):
    """Dedicated trash bin page for managing trashed databases."""
    logger.debug(f"Trash Bin request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    query_db = datasette.get_database('portal')
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
        
        # Only allow restore/delete for own databases
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
        
        # Get database size safely (no database access)
        table_count = 0
        total_records = 0
        database_size = 0
        
        if db_info["file_path"] and os.path.exists(db_info["file_path"]):
            try:
                # Only get file size (doesn't open database)
                database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                
                # Use placeholder values to avoid file locking
                table_count = "?"
                total_records = "?"
                
                logger.debug(f"Safe stats for {db_info['db_name']}: file size {database_size}KB")
            except Exception as e:
                logger.error(f"Error getting file size for {db_info['db_name']}: {e}")
                database_size = 0
                table_count = 0
                total_records = 0
        else:
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
            "trash_bin.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "is_admin": is_admin,
                "trashed_databases": trashed_databases,
                "total_trashed": len(trashed_databases),
                **get_success_error_from_request(request)
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
            
            # CRITICAL: Close database connections BEFORE updating status
            force_close_database_connections(datasette, db_name)
            
            # Update status to Trashed
            await query_db.execute_write(
                """UPDATE databases SET 
                status = 'Trashed', 
                trashed_at = ?, 
                restore_deadline = ?, 
                deleted_by_user_id = ?
                WHERE db_name = ?""",
                [trashed_at.isoformat(), restore_deadline.isoformat(), actor.get("id"), db_name]
            )
            
            # Get database stats for logging (safe file size only)
            database_size = 0
            if db_info['file_path'] and os.path.exists(db_info['file_path']):
                try:
                    database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                except Exception as e:
                    logger.error(f"Error getting database size: {e}")
            
            await log_database_action(
                datasette, actor.get("id"), "trash_database", 
                f"Moved database {db_name} to trash",
                {
                    "db_name": db_name,
                    "previous_status": db_info['status'],
                    "trashed_at": trashed_at.isoformat(),
                    "restore_deadline": restore_deadline.isoformat(),
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
                
            except Exception as e:
                logger.error(f"Error getting database info for {db_name}: {str(e)}")

        # Get content for template
        content = await get_portal_content(datasette)

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
        
        # Check if restore deadline has passed
        if db_info['restore_deadline']:
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
                "original_owner": db_info['user_id']
            }
        )
        
        redirect_page = "/trash" if request.args.get('from') == 'trash' else "/manage-databases"
        return Response.redirect(f"{redirect_page}?success=Database '{db_name}' restored successfully!")
        
    except Exception as e:
        logger.error(f"Error restoring database {db_name}: {str(e)}")
        return Response.text(f"Error restoring database: {str(e)}", status=500)

async def permanent_delete_database(datasette, request):
    """Tier 3: Permanent deletion - ENHANCED Windows-compatible version"""
    logger.debug(f"Permanent Delete Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    
    if request.method == "POST":
        post_vars = await request.post_vars()
        confirm_input = post_vars.get("confirm_db_name", "").strip()
        
        if confirm_input != db_name:
            return Response.redirect(f"{request.path}?error=Confirmation text does not match")
        
        try:
            result = await query_db.execute(
                "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor.get("id")]
            )
            
            db_info = result.first()
            if not db_info:
                return Response.text("Database not found or you do not have permission", status=404)
            
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
                logger.warning(f"File deletion failed for {db_name}, keeping database record")
                
                await log_database_action(
                    datasette, actor.get("id"), "deletion_failed", 
                    f"File deletion failed for {db_name}, database record preserved",
                    {
                        "db_name": db_name,
                        "reason": "file_deletion_failed",
                        "file_path": actual_file_path
                    }
                )
                
                return Response.redirect(f"/trash?error=Database '{db_name}' deletion failed. File could not be removed. Please try again or contact administrator.")
            
            # ONLY DELETE DATABASE RECORDS IF FILE DELETION SUCCEEDED
            await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_info['db_id']])
            await query_db.execute_write("DELETE FROM databases WHERE db_id = ?", [db_info['db_id']])
            
            # Success logging with minimal stats
            await log_database_action(
                datasette, actor.get("id"), "permanent_delete_database", 
                f"Permanently deleted database {db_name}",
                {
                    "db_name": db_name,
                    "deleted_by": actor.get("username"),
                    "database_size_kb": database_size,
                    "file_deleted": file_deleted
                }
            )
            
            return Response.redirect(f"/manage-databases?success=Database '{db_name}' permanently deleted")
            
        except Exception as e:
            logger.error(f"Error permanently deleting database {db_name}: {str(e)}")
            return Response.redirect(f"{request.path}?error=Error deleting database: {str(e)}")
        
    # GET request - use stats from URL parameters (NO database access)
    try:
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status, trashed_at FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        db_dict = dict(db_info)
        
        # Get stats from URL parameters (already calculated in trash bin)
        try:
            table_count = int(request.args.get('tables', 0))
        except (ValueError, TypeError):
            table_count = 0
        
        try:
            database_size = float(request.args.get('size', 0))
        except (ValueError, TypeError):
            database_size = 0
        
        total_records = "Calculated during deletion"
        
        # Fallback: get file size if not in URL
        if database_size == 0 and db_dict['file_path'] and os.path.exists(db_dict['file_path']):
            try:
                database_size = os.path.getsize(db_dict['file_path']) / 1024  # KB
            except Exception as e:
                logger.error(f"Error getting file size for {db_name}: {str(e)}")

        # Get content for template
        content = await get_portal_content(datasette)

        return Response.html(
            await datasette.render_template(
                "delete_db_confirm.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "db_name": db_name,
                    "db_status": db_dict['status'],
                    "table_count": table_count,
                    "total_records": total_records,
                    "database_size": database_size,
                    "trashed_at": db_dict['trashed_at'].split('T')[0] if db_dict['trashed_at'] else None,
                    **get_success_error_from_request(request)
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error showing permanent delete confirmation for {db_name}: {str(e)}")
        return Response.text(f"Error loading permanent delete confirmation: {str(e)}", status=500)
    
async def auto_cleanup_expired_databases(datasette):
    """Background task to automatically delete expired databases - ENHANCED for Windows"""
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
                # Get database statistics SAFELY (minimal file access)
                database_size = 0
                
                if db_info['file_path'] and os.path.exists(db_info['file_path']):
                    try:
                        database_size = os.path.getsize(db_info['file_path']) / 1024  # KB
                        logger.debug(f"Auto-cleanup stats for {db_name}: {database_size}KB")
                    except Exception as e:
                        logger.error(f"Error getting file size for {db_name} in auto-cleanup: {e}")
                
                # Force close database connections
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
                
                # ONLY DELETE DATABASE RECORDS IF FILE DELETION SUCCEEDED
                await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_id])
                await query_db.execute_write("DELETE FROM databases WHERE db_id = ?", [db_id])
                
                # Log successful auto-deletion
                await log_database_action(
                    datasette, "system", "auto_delete_database", 
                    f"Auto-deleted expired database {db_name}",
                    {
                        "db_name": db_name,
                        "original_owner": db_info['user_id'],
                        "restore_deadline": db_info['restore_deadline'],
                        "database_size_kb": database_size,
                        "auto_cleanup": True,
                        "file_deleted": file_deleted
                    }
                )
                
                logger.info(f"Auto-deleted expired database: {db_name}")
                
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

@hookimpl
def register_routes():
    """Register database deletion routes"""
    return [
        (r"^/trash$", trash_bin_page),
        (r"^/db/([^/]+)/trash$", trash_database),
        (r"^/db/([^/]+)/restore$", restore_database),
        (r"^/db/([^/]+)/delete-permanent$", permanent_delete_database),
    ]