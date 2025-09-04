
"""
Database Management Module - Database creation and management
Handles: Create, manage, publish, unpublish databases, custom homepages, databases list with filtering and preview functionality
"""

import json
import logging
import uuid
import os
import sqlite_utils
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database
import sqlite3
from email.parser import BytesParser
from email.policy import default
import re

# Add the plugins directory to Python path for imports
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
    get_portal_content,
    get_database_content,
    get_database_statistics,
    user_owns_database,
    redirect_authenticated_user,
    ensure_data_directories,
    get_all_published_databases,
    get_success_error_from_request,
    create_feature_cards_from_databases,
    create_statistics_data,
    update_database_timestamp,
    update_database_timestamp_by_id,
    parse_markdown_links,
    DATA_DIR,
    get_max_image_size,
    is_system_table,
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def index_page(datasette, request):
    """Index page with improved statistics and user database info."""
    logger.debug(f"Index request: {request.method}")

    # Get base content using common utility
    content = await get_portal_content(datasette)

    # Get actor and check authentication
    actor = get_actor_from_request(request)
    
    if actor:
        # Verify user session using common utility
        is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
        
        if not is_valid:
            return redirect_response
        
        # Redirect authenticated users to appropriate dashboard
        return await redirect_authenticated_user(actor)

    # Get statistics for public homepage
    stats = await get_database_statistics(datasette)
    
    # Format featured databases as cards using common utility
    feature_cards = create_feature_cards_from_databases(stats['featured_databases'], limit=50)
    
    # Statistics for the cards section using common utility
    statistics_data = create_statistics_data(stats)

    logger.debug(f"Rendering public index with statistics: {stats}")

    return Response.html(
        await datasette.render_template(
            "index.html",
            {
                "page_title": content['title'].get('content', "Resette"),
                "header_image": content['header_image'],
                "info": content['info'],
                "feature_cards": feature_cards,
                "total_published": stats['published_databases'],
                "statistics": statistics_data,
                "content": content,
                "actor": actor,
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def all_databases_page(datasette, request):
    """Show all published databases - custom page."""
    logger.debug(f"All Databases request: method={request.method}")

    # Get base content using common utility
    content = await get_portal_content(datasette)
    actor = get_actor_from_request(request)

    try:
        # Get all published databases using common utility
        all_databases = await get_all_published_databases(datasette)
        
        return Response.html(
            await datasette.render_template(
                "all_databases.html",
                {
                    "page_title": "All Datasets | Resette",
                    "content": content,
                    "databases": all_databases,
                    "total_count": len(all_databases),
                    "actor": actor,
                    **get_success_error_from_request(request)
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error in all_databases_page: {str(e)}")
        return Response.html(
            await datasette.render_template(
                "all_databases.html",
                {
                    "page_title": "All Datasets | Resette",
                    "content": content,
                    "databases": [],
                    "total_count": 0,
                    "actor": actor,
                    "error": f"Error loading databases: {str(e)}"
                },
                request=request
            )
        )

async def manage_databases(datasette, request):
    """Manage databases with improved filtering and sorting by most recent."""
    logger.debug(f"Manage Databases request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized manage databases attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    status_filter = request.args.get('status', 'active')
    
    # Filter options - EXCLUDE 'Deleted' status from all queries
    query_db = datasette.get_database('portal')
    
    if status_filter == 'active':
        query = """SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at, updated_at 
                FROM databases 
                WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished') 
                ORDER BY updated_at DESC NULLS LAST, created_at DESC"""
    elif status_filter == 'draft':
        query = """SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at, updated_at 
                FROM databases 
                WHERE user_id = ? AND status = 'Draft' 
                ORDER BY updated_at DESC NULLS LAST, created_at DESC"""
    elif status_filter == 'published':
        query = """SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at, updated_at 
                FROM databases 
                WHERE user_id = ? AND status = 'Published' 
                ORDER BY updated_at DESC NULLS LAST, created_at DESC"""
    elif status_filter == 'unpublished':
        query = """SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at, updated_at 
                FROM databases 
                WHERE user_id = ? AND status = 'Unpublished' 
                ORDER BY updated_at DESC NULLS LAST, created_at DESC"""
    elif status_filter == 'trash':
        query = """SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at, updated_at 
                FROM databases 
                WHERE user_id = ? AND status = 'Trashed' 
                ORDER BY updated_at DESC NULLS LAST, created_at DESC"""
    else:  # 'all' - EXCLUDE 'Deleted' status
        query = """SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at, updated_at 
                FROM databases 
                WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed') 
                ORDER BY updated_at DESC NULLS LAST, created_at DESC"""

    result = await query_db.execute(query, [actor.get("id")])
    user_databases = [dict(row) for row in result]
    
    # Add days_until_delete calculation for each database
    for db in user_databases:
        if db.get('status') == 'Trashed' and db.get('restore_deadline'):
            try:
                deadline = datetime.fromisoformat(db['restore_deadline'].replace('Z', '+00:00'))
                now = datetime.utcnow()
                delta = deadline - now
                db['days_until_delete'] = max(0, delta.days)
            except Exception as e:
                logger.error(f"Error calculating restore deadline for {db.get('db_name')}: {e}")
                db['days_until_delete'] = 0
        else:
            db['days_until_delete'] = None
        
        # Add formatted trash date
        if db.get('trashed_at'):
            db['trashed_at_formatted'] = db['trashed_at'].split('T')[0]
        else:
            db['trashed_at_formatted'] = None
    
    # Get content using common utility
    content = await get_portal_content(datasette)

    # Database processing with table visibility integration
    databases_with_tables = []
    for db_info in user_databases:
        db_name = db_info["db_name"]
        db_id = db_info["db_id"]
        total_size = 0
        table_count = 0
        file_size_kb = 0 

        # Check if database has custom homepage
        homepage_result = await query_db.execute(
            "SELECT COUNT(*) FROM admin_content WHERE db_id = ? AND section = 'title'",
            [db_id]
        )
        has_custom_homepage = homepage_result.first()[0] > 0
        
        try:
            # Build file path if not available
            db_path = db_info.get("file_path")
            if not db_path:
                db_path = os.path.join(DATA_DIR, actor.get("id"), f"{db_name}.db")
                db_info["file_path"] = db_path
            
            if db_path and os.path.exists(db_path):
                # Get actual file size first
                try:
                    file_size_kb = os.path.getsize(db_path) / 1024  # Convert to KB
                    logger.debug(f"File size for {db_name}: {file_size_kb:.1f} KB")
                except Exception as size_error:
                    logger.error(f"Error getting file size for {db_name}: {size_error}")
                    file_size_kb = 0
                
                # Get database contents with visibility information
                tables = await get_database_tables_with_visibility(datasette, db_id, db_name)
                table_count = len(tables)
                
                # Calculate total size estimate
                for table in tables:
                    total_size += table.get('size', 0)
                
            else:
                logger.warning(f"Database file not found for {db_name}: {db_path}")
                file_size_kb = 0
                tables = []
                
        except Exception as e:
            logger.error(f"Error loading database {db_name}: {str(e)}")
            file_size_kb = 0
            tables = []
            
        databases_with_tables.append({
            **db_info,
            'tables': tables,
            'table_count': table_count,
            'total_size': file_size_kb,
            'file_size_kb': file_size_kb,
            'website_url': f"/db/{db_name}/homepage",
            'has_custom_homepage': has_custom_homepage
        })

    # Get user statistics - EXCLUDE 'Deleted' databases
    stats = await get_database_statistics(datasette, actor.get("id"))

    return Response.html(
        await datasette.render_template(
            "manage_databases.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "user_databases": databases_with_tables,
                "status_filter": status_filter,
                "stats": stats,
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def publish_database(datasette, request):
    """Publish database (make it publicly accessible)."""
    logger.debug(f"Publish Database request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Handle /db/{db_name}/publish path
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]
    else:
        return Response.text("Invalid URL format", status=400)
    
    query_db = datasette.get_database('portal')
    try:
        # EXCLUDE 'Deleted' status from query
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ? AND status != 'Deleted'",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        # Convert to dict
        db_info = dict(db_info)
        
        if db_info['status'] == 'Published':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is already published")
        
        if db_info['status'] == 'Trashed':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is in trash. Restore it first.")
        
        # Update status to Published with updated_at timestamp
        current_time = datetime.utcnow().isoformat()
        await query_db.execute_write(
            "UPDATE databases SET status = 'Published', updated_at = ? WHERE db_name = ? AND status != 'Deleted'",
            [current_time, db_name]
        )
        
        # Build file path if not available
        file_path = db_info.get('file_path')
        if not file_path:
            file_path = os.path.join(DATA_DIR, actor.get("id"), f"{db_name}.db")
        
        # Register database with Datasette
        if file_path and os.path.exists(file_path):
            try:
                user_db = Database(datasette, path=file_path, is_mutable=True)
                datasette.add_database(user_db, name=db_name)
                logger.debug(f"Successfully registered published database: {db_name}")
            except Exception as reg_error:
                logger.error(f"Error registering database {db_name}: {reg_error}")
        
        await log_database_action(
            datasette, actor.get("id"), "publish_database", 
            f"Published database {db_name}",
            {
                "db_name": db_name,
                "previous_status": db_info['status'],
                "new_status": "Published"
            }
        )
        
        return Response.redirect(f"/manage-databases?success=Database '{db_name}' published successfully! It's now publicly accessible at /{db_name}/")
        
    except Exception as e:
        logger.error(f"Error publishing database {db_name}: {str(e)}")
        return Response.text(f"Error publishing database: {str(e)}", status=500)
    
async def unpublish_database(datasette, request):
    """Unpublish database (make it private)."""
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
        # EXCLUDE 'Deleted' status from query
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ? AND status != 'Deleted'",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        # Convert to dict
        db_info = dict(db_info)
        
        if db_info['status'] != 'Published':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is not published")
        
        # Update status to Unpublished with updated_at timestamp
        current_time = datetime.utcnow().isoformat()
        await query_db.execute_write(
            "UPDATE databases SET status = 'Unpublished', updated_at = ? WHERE db_name = ? AND status != 'Deleted'",
            [current_time, db_name]
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
    
async def delete_table(datasette, request):
    """Delete table from database with database_tables cleanup - PREVENT SYSTEM TABLE DELETION."""
    actor = get_actor_from_request(request)
    
    # Check if user is authenticated
    if not actor:
        return Response.redirect("/login")
    
    # Extract parameters from URL path
    path_parts = request.path.strip('/').split('/')
    if len(path_parts) >= 3 and path_parts[0] == 'delete-table':
        db_name = path_parts[1]
        table_name = path_parts[2]
    else:
        return Response.redirect("/manage-databases?error=Invalid URL format")
    
    # PREVENT DELETION OF SYSTEM TABLES
    if is_system_table(table_name):
        return Response.redirect(f"/manage-databases?error=Cannot delete system table '{table_name}'. This table is required for database functionality.")
    
    logger.debug(f"Delete table request: db_name={db_name}, table_name={table_name}")
    
    # Verify user owns the database
    if not await user_owns_database(datasette, actor["id"], db_name):
        return Response(
            "Access denied: You don't have permission to delete tables from this database",
            status=403
        )
    
    # Handle POST request (actual deletion)
    if request.method == "POST":
        try:
            post_vars = await request.post_vars()
            logger.debug(f"POST vars: {list(post_vars.keys())}")

            # Get the target database
            target_db = datasette.get_database(db_name)

            # Check if table exists
            tables = await target_db.table_names()
            if table_name not in tables:
                return Response.redirect(
                    f"/manage-databases?error=Table '{table_name}' not found in database '{db_name}'"
                )
            
            # Get db_id for cleanup
            portal_db = datasette.get_database("portal")
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ?", [db_name]
            )
            db_record = db_result.first()
                        
            # Delete the table
            await target_db.execute_write(f"DROP TABLE [{table_name}]")
            logger.debug(f"Successfully deleted table {table_name} from {db_name}")

            # Clean up database_tables record
            if db_record:
                try:
                    table_id = f"{db_record['db_id']}_{table_name}"
                    await portal_db.execute_write(
                        "DELETE FROM database_tables WHERE table_id = ?", [table_id]
                    )
                    logger.debug(f"Cleaned up database_tables record for {table_name}")
                except Exception as cleanup_error:
                    logger.error(f"Error cleaning up database_tables: {cleanup_error}")

            # Update database timestamp
            current_time = datetime.utcnow().isoformat()
            await portal_db.execute_write(
                "UPDATE databases SET updated_at = ? WHERE db_name = ?",
                [current_time, db_name]
            )

            await log_database_action(
                datasette, actor.get("id"), "delete_table", 
                f"Deleted table {table_name} from {db_name}",
                {"db_name": db_name, "table_name": table_name}
            )

            return Response.redirect(
                f"/manage-databases?success=Table '{table_name}' deleted successfully from '{db_name}'"
            )
            
        except Exception as e:
            logger.error(f"Error deleting table {table_name} from {db_name}: {e}")
            return Response.redirect(
                f"/manage-databases?error=Failed to delete table: {str(e)}"
            )
    
    # Handle GET request (show confirmation page)
    else:
        try:
            target_db = datasette.get_database(db_name)
            
            # Get table information
            table_info = await target_db.execute(
                f"SELECT COUNT(*) as row_count FROM [{table_name}]"
            )
            row_count = table_info.rows[0][0] if table_info.rows else 0
            
            # Get column information
            columns_info = await target_db.execute(f"PRAGMA table_info([{table_name}])")
            columns = [row[1] for row in columns_info.rows]  # column names
            
            return Response.html(
                await datasette.render_template(
                    "delete_table_confirm.html",
                    {
                        "db_name": db_name,
                        "table_name": table_name,
                        "row_count": row_count,
                        "column_count": len(columns),
                        "columns": columns[:5],  # Show first 5 columns
                    },
                    request=request
                )
            )
            
        except Exception as e:
            logger.error(f"Error accessing table information for {table_name}: {e}")
            return Response.redirect(
                f"/manage-databases?error=Error accessing table information: {str(e)}"
            )

async def delete_table_ajax(datasette, request):
    """AJAX endpoint for table deletion - PREVENT SYSTEM TABLE DELETION."""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)
    
    try:
        # Parse JSON body
        import json
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))
        
        db_name = data.get('db_name')
        table_name = data.get('table_name')
        
        if not db_name or not table_name:
            return Response.json({"error": "Missing db_name or table_name"}, status=400)
        
        # PREVENT DELETION OF SYSTEM TABLES
        if is_system_table(table_name):
            return Response.json({"error": f"Cannot delete system table '{table_name}'. This table is required for database functionality."}, status=400)
              
        # Verify ownership
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"error": "Access denied"}, status=403)
        
        # Get target database
        target_db = datasette.get_database(db_name)
        if not target_db:
            return Response.json({"error": f"Database '{db_name}' not found"}, status=404)
        
        # Check if table exists
        tables = await target_db.table_names()
        if table_name not in tables:
            return Response.json({"error": f"Table '{table_name}' not found"}, status=404)
        
        # Delete the table
        await target_db.execute_write(f"DROP TABLE [{table_name}]")
        
        # Clean up database_tables record
        portal_db = datasette.get_database("portal")
        db_result = await portal_db.execute(
            "SELECT db_id FROM databases WHERE db_name = ?", [db_name]
        )
        db_record = db_result.first()
        
        if db_record:
            try:
                table_id = f"{db_record['db_id']}_{table_name}"
                await portal_db.execute_write(
                    "DELETE FROM database_tables WHERE table_id = ?", [table_id]
                )
                logger.debug(f"Cleaned up database_tables record for {table_name}")
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up database_tables: {cleanup_error}")
        
        # Log the deletion
        await log_database_action(
            datasette, actor["id"], "delete_table",
            f"Deleted table {table_name} from {db_name}",
            {"db_name": db_name, "table_name": table_name}
        )
        
        return Response.json({
            "success": True,
            "message": f"Table '{table_name}' deleted successfully from '{db_name}'"
        })
        
    except Exception as e:
        logger.error(f"Error in delete_table_ajax: {e}")
        return Response.json({"error": f"Failed to delete table: {str(e)}"}, status=500)

async def database_homepage(datasette, request):
    """Database homepage with preview functionality and table visibility filtering."""
    logger.debug(f"Database homepage request: method={request.method}, path={request.path}")

    # Handle both /db/{db_name}/homepage and /{db_name}/ patterns
    path_parts = request.path.strip('/').split('/')
    if path_parts[0] == 'db' and len(path_parts) >= 3:
        db_name = path_parts[1]  # /db/{db_name}/homepage
        is_preview = True  # This is a preview request
    else:
        db_name = path_parts[0]  # /{db_name}/
        is_preview = False  # This is a public access request
    
    if not db_name:
        return Response.text("Not found", status=404)
    
    # Check if database exists and user has permission - EXCLUDE 'Deleted' status
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, db_name, status, user_id, file_path FROM databases WHERE db_name = ? AND status != 'Deleted'",
            [db_name]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        
        # Access control logic
        if db_info['status'] == 'Trashed':
            return Response.text("Database not found or not published", status=404)

        # Check if database is registered correctly
        try:
            # Try to get the database - this will work if it's registered
            user_db = datasette.get_database(db_name)
            if not user_db:
                # Database not registered, try to register it
                file_path = db_info.get('file_path')
                if not file_path:
                    file_path = os.path.join(DATA_DIR, db_info['user_id'], f"{db_name}.db")
                
                if file_path and os.path.exists(file_path):
                    new_db = Database(datasette, path=file_path, is_mutable=True)
                    datasette.add_database(new_db, name=db_name)
                    user_db = datasette.get_database(db_name)
                    logger.debug(f"Successfully registered database: {db_name}")
                else:
                    return Response.text("Database file not found", status=500)
        except Exception as reg_error:
            logger.error(f"Failed to register database {db_name}: {reg_error}")
            return Response.text("Database registration failed", status=500)
        
    except Exception as e:
        logger.error(f"Error checking database {db_name}: {e}")
        return Response.text("Database error", status=500)
    
    # Get content and check customization
    try:
        content = await get_database_content(datasette, db_name)
        if not content:
            logger.error(f"No content found for database {db_name}")
            return Response.redirect(f"/{db_name}")
        
        # Check if content is customized
        default_title = db_name.replace('_', ' ').title()
        default_description = db_name.replace('_', ' ').title()
        default_footer = f"{db_name.replace('_', ' ').title()} | Resette."

        has_custom_title = content.get('title', {}).get('content', '') != default_title
        has_custom_description = content.get('description', {}).get('content', '') != default_description
        has_custom_footer = content.get('footer', {}).get('content', '') != default_footer
        
        # Check for custom header image
        has_custom_image = False
        header_image = content.get('header_image', {})
        if 'image_url' in header_image:
            image_url = header_image['image_url']
            has_custom_image = not image_url.endswith('/static/default_header.jpg')
        
        is_customized = has_custom_title or has_custom_description or has_custom_footer or has_custom_image
        
        # If not customized and not preview mode, redirect to Datasette's default database page
        if not is_customized and not is_preview:
            logger.debug(f"No customization found for {db_name}, redirecting to Datasette default")
            return Response.redirect(f"/{db_name}")
        
        # Get database statistics with table visibility filtering
        try:
            user_db = datasette.get_database(db_name)
            if user_db:
                # Get tables with visibility information
                tables_with_visibility = await get_database_tables_with_visibility(
                    datasette, db_info['db_id'], db_name
                )
                
                # Filter visible tables for homepage display
                visible_tables = [t for t in tables_with_visibility if t.get('show_in_homepage', True)]
                
                tables = []
                total_records = 0
                
                # Process ALL visible tables
                for table in visible_tables:
                    try:
                        count_result = await user_db.execute(f"SELECT COUNT(*) as count FROM [{table['name']}]")
                        record_count = count_result.first()['count'] if count_result.first() else 0
                        total_records += record_count
                        
                        tables.append({
                            'title': table['name'].replace('_', ' ').title(),
                            'description': table.get('table_description') or f"Data table with {record_count:,} records",
                            'url': f"/{db_name}/{table['name']}",
                            'icon': 'ri-table-line',
                            'count': record_count,
                            'display_order': table.get('display_order', 100)
                        })
                    except Exception as table_error:
                        logger.error(f"Error processing table {table['name']}: {table_error}")
                        continue
                logger.debug(f"Final tables count for homepage: {len(tables)} tables")

                # Use total tables count (including hidden ones) for statistics
                all_tables_count = len(tables_with_visibility)
                
                statistics = [
                    {
                        'label': 'Data Tables',
                        'value': all_tables_count,
                        'url': f'/{db_name}'
                    },
                    {
                        'label': 'Total Records',
                        'value': f"{total_records:,}",
                        'url': f'/{db_name}'
                    },
                    {
                        'label': 'View all available data tables',
                        'value': 'Explore All Tables',
                        'url': f'/{db_name}'
                    }
                ]
            else:
                tables = []
                statistics = []
        except Exception as stats_error:
            logger.error(f"Error getting database stats for {db_name}: {stats_error}")
            tables = []
            statistics = []
        
        # Sort tables by display_order
        tables.sort(key=lambda x: x.get('display_order', 100), reverse=True)

        # ADD DEBUG LINE to verify ordering
        logger.debug(f"Tables sorted by display_order for homepage: {[(t['title'], t.get('display_order', 100)) for t in tables]}")

        # Add preview mode indicator to page title if in preview
        page_title = content.get('title', {}).get('content', db_name) + " | Resette"
        if is_preview:
            page_title = "[PREVIEW] " + page_title
        
        return Response.html(
            await datasette.render_template(
                "database_homepage.html",
                {
                    "page_title": page_title,
                    "content": content,
                    "header_image": content.get('header_image', {}),
                    "info": content.get('info', content.get('description', {})),
                    "feature_cards": tables,
                    "statistics": statistics,
                    "footer": content.get('footer', {}),
                    "db_name": db_name,
                    "tables": tables,
                    "is_preview": is_preview,
                    "actor": actor
                },
                request=request
            )
        )
        
    except Exception as e:
        logger.error(f"Error rendering database homepage for {db_name}: {e}")
        return Response.text("Error loading homepage", status=500)
    
async def edit_content(datasette, request):
    """Edit database content and homepage."""
    logger.debug(f"Edit Content request: method={request.method}, path={request.path}")

    path_parts = request.path.strip('/').split('/')
    if len(path_parts) < 2:
        return Response.text("Invalid URL", status=400)
    
    db_id = path_parts[1]
    
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute("SELECT db_name, status, user_id FROM databases WHERE db_id = ?", [db_id])
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        if not actor or actor['id'] != db_info['user_id']:
            return Response.text("Permission denied", status=403)
    except Exception as e:
        logger.error(f"Error checking database for db_id {db_id}: {e}")
        return Response.text("Database error", status=500)
    
    db_name = db_info['db_name']
    db_status = db_info['status']
    
    content = await get_database_content(datasette, db_name)
    
    if request.method == "POST":
        content_type = request.headers.get('content-type', '').lower()
        if 'multipart/form-data' in content_type:
            # Handle image upload using email.parser approach
            try:
                body = await request.post_body()
                max_img_size = await get_max_image_size(datasette)

                if len(body) > max_img_size:
                    return Response.text("File too large", status=400)
                
                # Parse the content-type header to get boundary
                boundary = None
                if 'boundary=' in content_type:
                    boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
                
                if not boundary:
                    logger.error("No boundary found in Content-Type header")
                    return Response.redirect(f"{request.path}?error=Invalid form data")
                
                # Create headers for email parser
                headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
                headers['content-type'] = request.headers.get('content-type', '')
                
                # Parse using email parser
                header_bytes = b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n'
                msg = BytesParser(policy=default).parsebytes(header_bytes + body)
                
                forms = {}
                files = {}
                
                # Extract form data and files
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
                
                logger.debug(f"Parsed forms: {forms}")
                logger.debug(f"Parsed files: {files}")
                
                new_content = content.get('header_image', {})
                
                # Handle image upload
                if 'image' in files and files['image']['content']:
                    file = files['image']
                    filename = file['filename']
                    ext = Path(filename).suffix.lower()
                    
                    if ext in ['.jpg', '.jpeg', '.png']:
                        # Create database-specific directory under data/db_id
                        db_data_dir = os.path.join(DATA_DIR, db_id)
                        os.makedirs(db_data_dir, exist_ok=True)
                        
                        # Save image as header.jpg in database directory
                        image_path = os.path.join(db_data_dir, 'header.jpg')
                        with open(image_path, 'wb') as f:
                            f.write(file['content'])
                        
                        # Update content with correct image URL
                        import time
                        timestamp = int(time.time())
                        new_content['image_url'] = f"/data/{db_id}/header.jpg?v={timestamp}"
                        logger.debug(f"Saved image to {image_path}, URL with cache busting: {new_content['image_url']}")
                
                # Update other fields from forms
                if 'alt_text' in forms:
                    new_content['alt_text'] = forms['alt_text'][0]
                if 'credit_text' in forms:
                    new_content['credit_text'] = forms['credit_text'][0]
                if 'credit_url' in forms:
                    new_content['credit_url'] = forms['credit_url'][0]
                
                # Save to database
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'header_image', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )

                # UPDATE DATABASE TIMESTAMP
                await update_database_timestamp_by_id(datasette, db_id)                               
                
                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated header image for {db_name}",
                    {"db_name": db_name, "section": "header_image"}
                )
                                
                return Response.redirect(f"{request.path}?success=Header image updated")
                
            except Exception as e:
                logger.error(f"Error handling image upload: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                return Response.redirect(f"{request.path}?error=Error uploading image: {str(e)}")
        else:
            # Handle text form data
            post_vars = await request.post_vars()
            
            if 'title' in post_vars:
                new_content = {"content": post_vars['title']}
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'title', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                # UPDATE DATABASE TIMESTAMP
                await update_database_timestamp_by_id(datasette, db_id)

                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated title for {db_name}",
                    {"db_name": db_name, "section": "title"}
                )
                
                return Response.redirect(f"{request.path}?success=Title updated")
            
            if 'description' in post_vars:
                new_content = {
                    "content": post_vars['description'],
                    "paragraphs": parse_markdown_links(post_vars['description'])
                }
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'description', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                # UPDATE DATABASE TIMESTAMP
                await update_database_timestamp_by_id(datasette, db_id)

                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated description for {db_name}",
                    {"db_name": db_name, "section": "description"}
                )
                
                return Response.redirect(f"{request.path}?success=Description updated")
            
            if 'license_type' in post_vars or 'section' in post_vars and post_vars['section'] == 'data_license':
                license_type = post_vars.get('license_type')
                license_url = post_vars.get('license_url', 'https://opendatacommons.org/licenses/odbl/')
                custom_license_text = post_vars.get('custom_license_text', '')
                
                if license_type == 'custom':
                    license_text = custom_license_text
                else:
                    # Map license types to standard text
                    license_texts = {
                        'odbl': 'Data licensed under ODbL',
                        'cc0': 'Data licensed under CC0',
                        'cc-by': 'Data licensed under CC BY',
                        'cc-by-sa': 'Data licensed under CC BY-SA',
                        'cc-by-nc': 'Data licensed under CC BY-NC',
                        'mit': 'Data licensed under MIT'
                    }
                    license_text = license_texts.get(license_type, 'Data licensed under ODbL')
                
                # Get existing footer content or create new
                existing_footer = content.get('footer', {})
                
                new_content = {
                    "content": existing_footer.get('content', f"{db_name.replace('_', ' ').title()} | Powered by Resette"),
                    "odbl_text": license_text,
                    "odbl_url": license_url,
                    "paragraphs": existing_footer.get('paragraphs', [existing_footer.get('content', f"{db_name.replace('_', ' ').title()} | Powered by Resette")])
                }
                
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'footer', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                # UPDATE DATABASE TIMESTAMP
                await update_database_timestamp_by_id(datasette, db_id)

                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated data license for {db_name}",
                    {"db_name": db_name, "section": "data_license"}
                )
                
                return Response.redirect(f"{request.path}?success=Data license updated")
            
            if 'footer' in post_vars:
                # Get existing footer content to preserve license settings
                existing_footer = content.get('footer', {})
                
                new_content = {
                    "content": post_vars['footer'],
                    "odbl_text": existing_footer.get('odbl_text', "Data licensed under ODbL"),
                    "odbl_url": existing_footer.get('odbl_url', "https://opendatacommons.org/licenses/odbl/"),
                    "paragraphs": parse_markdown_links(post_vars['footer'])
                }
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'footer', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
                
                # UPDATE DATABASE TIMESTAMP
                await update_database_timestamp_by_id(datasette, db_id)

                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated footer for {db_name}",
                    {"db_name": db_name, "section": "footer"}
                )
                
                return Response.redirect(f"{request.path}?success=Footer updated")
    
    return Response.html(
        await datasette.render_template(
            "template.html",
            {
                "db_name": db_name,
                "db_status": db_status,
                "db": {"db_name": db_name, "status": db_status},
                "content": content,
                "actor": actor,
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def serve_database_image(datasette, request):
    """Serve database-specific images with better cache handling."""
    try:
        # Extract db_id and filename from the URL path
        path_parts = request.path.strip('/').split('/')
        
        if len(path_parts) < 3 or path_parts[0] != 'data':
            logger.error(f"Invalid URL format: {request.path}")
            return Response.text("Not found", status=404)
        
        db_id = path_parts[1]
        filename = path_parts[2]
        
        # Remove cache busting parameter from filename
        if '?' in filename:
            filename = filename.split('?')[0]
        
        logger.debug(f"Serving image: db_id={db_id}, filename={filename}")
        
        # Security: only allow specific image files
        if filename not in ['header.jpg', 'header.png']:
            logger.error(f"Invalid filename requested: {filename}")
            return Response.text("Not found", status=404)
        
        # Check if the database exists and user has access
        query_db = datasette.get_database('portal')
        db_result = await query_db.execute("SELECT status FROM databases WHERE db_id = ?", [db_id])
        db_info = db_result.first()
        
        if not db_info:
            logger.error(f"Database not found for db_id: {db_id}")
            return Response.text("Not found", status=404)
        
        # For published databases, allow public access
        # For draft databases, check ownership
        if db_info['status'] != 'Published':
            actor = get_actor_from_request(request)
            if not actor:
                return Response.text("Not found", status=404)
            
            owner_result = await query_db.execute(
                "SELECT user_id FROM databases WHERE db_id = ? AND user_id = ?", 
                [db_id, actor.get('id')]
            )
            if not owner_result.first():
                return Response.text("Not found", status=404)
        
        # Serve the file
        file_path = os.path.join(DATA_DIR, db_id, filename)
        logger.debug(f"Looking for file at: {file_path}")
        
        if os.path.exists(file_path):
            # Get file modification time for caching
            import time
            file_mtime = os.path.getmtime(file_path)
            etag = f'"{int(file_mtime)}"'
            
            # Check if client has current version
            if_none_match = request.headers.get('if-none-match')
            if if_none_match == etag:
                return Response('', status=304)
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            content_type = 'image/jpeg' if filename.endswith('.jpg') else 'image/png'
            logger.debug(f"Serving {len(content)} bytes as {content_type} with ETag {etag}")
            
            return Response(
                content, 
                content_type=content_type,
                headers={
                    'Cache-Control': 'public, max-age=300',  # 5 minutes
                    'ETag': etag,
                    'Content-Length': str(len(content)),
                    'Last-Modified': time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(file_mtime))
                }
            )
        else:
            logger.error(f"File not found: {file_path}")
            return Response.text("Not found", status=404)
            
    except Exception as e:
        logger.error(f"Error serving image: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return Response.text("Internal server error", status=500)

async def verify_database_structure_startup(query_db):
    """Verify the portal database has required structure."""
    try:
        # Check if required tables exist
        required_tables = ['users', 'databases', 'admin_content', 'activity_logs', 'system_settings']
        
        result = await query_db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row['name'] for row in result.rows]
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            logger.error(f"Missing required tables: {missing_tables}")
            logger.error("Please ensure the portal database is properly initialized")
            return False
        
        # Check for basic data integrity
        try:
            users_result = await query_db.execute("SELECT COUNT(*) FROM users")
            databases_result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE status != 'Deleted'")
            
            user_count = users_result.first()[0] if users_result.first() else 0
            db_count = databases_result.first()[0] if databases_result.first() else 0
            
            logger.info(f"Portal database verified: {user_count} users, {db_count} active databases")
            
        except Exception as check_error:
            logger.warning(f"Database integrity check failed: {check_error}")
            # Continue anyway - structure exists
        
        return True
        
    except Exception as e:
        logger.error(f"Error verifying database structure: {e}")
        return False

async def register_user_databases_startup(datasette, query_db):
    """ENHANCED: Register all user databases with comprehensive error handling."""
    registered_count = 0
    failed_count = 0
    skipped_count = 0
    
    try:
        # Get all active databases (exclude Deleted status)
        result = await query_db.execute(
            """SELECT db_name, file_path, status, user_id, db_id, created_at 
               FROM databases 
               WHERE status IN ('Draft', 'Published', 'Unpublished', 'Trashed') 
               ORDER BY created_at DESC"""
        )
        
        total_databases = len(result.rows)
        logger.info(f"Found {total_databases} databases to register")
        
        for row in result.rows:
            db_name = row['db_name']
            file_path = row['file_path']
            status = row['status']
            user_id = row['user_id']
            db_id = row['db_id']
            
            try:
                # Build file path if not available
                if not file_path:
                    file_path = os.path.join(DATA_DIR, user_id, f"{db_name}.db")
                    # Update the database record with the correct file path
                    try:
                        await query_db.execute_write(
                            "UPDATE databases SET file_path = ? WHERE db_id = ?",
                            [file_path, db_id]
                        )
                        logger.debug(f"Updated file path for {db_name}: {file_path}")
                    except Exception as update_error:
                        logger.warning(f"Could not update file path for {db_name}: {update_error}")
                
                # Check if file exists
                if not file_path or not os.path.exists(file_path):
                    logger.warning(f"Database file not found: {file_path} for {db_name} (status: {status})")
                    failed_count += 1
                    continue
                
                # Validate SQLite file
                try:
                    conn = sqlite3.connect(file_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
                    test_result = cursor.fetchone()
                    conn.close()
                    
                    if not test_result:
                        logger.warning(f"Database file exists but contains no tables: {db_name}")
                        # Still register it - user might add tables later
                
                except Exception as sqlite_error:
                    logger.error(f"Invalid SQLite file {db_name}: {sqlite_error}")
                    failed_count += 1
                    continue
                
                # Check if already registered with Datasette
                if db_name in datasette.databases:
                    logger.debug(f"Database already registered: {db_name}")
                    skipped_count += 1
                    continue
                
                # Register with Datasette
                try:
                    db_instance = Database(datasette, path=file_path, is_mutable=True)
                    datasette.add_database(db_instance, name=db_name)
                    registered_count += 1
                    
                    logger.info(f"✓ Registered database: {db_name} ({status}) for user {user_id}")
                    
                except Exception as reg_error:
                    logger.error(f"✗ Failed to register database {db_name}: {reg_error}")
                    failed_count += 1
                    continue
                    
            except Exception as process_error:
                logger.error(f"Error processing database {db_name}: {process_error}")
                failed_count += 1
                continue
        
        logger.info(f"Database registration summary:")
        logger.info(f"  - Successfully registered: {registered_count}")
        logger.info(f"  - Failed to register: {failed_count}")  
        logger.info(f"  - Already registered: {skipped_count}")
        logger.info(f"  - Total processed: {total_databases}")
        
        return registered_count, failed_count, skipped_count
        
    except Exception as e:
        logger.error(f"Error during database registration: {e}")
        return 0, 0, 0

async def fix_missing_registrations_startup(datasette, query_db):
    """Attempt to fix databases that failed initial registration."""
    fixed_count = 0
    
    try:
        # Get databases that should be registered but aren't
        result = await query_db.execute(
            "SELECT db_name, file_path, user_id FROM databases WHERE status = 'Published'"
        )
        
        for row in result.rows:
            db_name = row['db_name']
            file_path = row['file_path'] 
            user_id = row['user_id']
            
            # Skip if already registered
            if db_name in datasette.databases:
                continue
                
            try:
                # Try to register again
                if file_path and os.path.exists(file_path):
                    db_instance = Database(datasette, path=file_path, is_mutable=True)
                    datasette.add_database(db_instance, name=db_name)
                    fixed_count += 1
                    logger.info(f"Fixed registration for: {db_name}")
                
            except Exception as fix_error:
                logger.error(f"Could not fix registration for {db_name}: {fix_error}")
                continue
        
        return fixed_count
        
    except Exception as e:
        logger.error(f"Error fixing missing registrations: {e}")
        return 0

async def log_startup_success_startup(datasette, registered_count, failed_count, skipped_count):
    """Log successful startup with detailed metrics."""
    try:
        startup_details = (
            f"Startup completed: {registered_count} registered, "
            f"{failed_count} failed, {skipped_count} skipped"
        )
        
        await log_database_action(
            datasette, "system", "startup", 
            f"EDGI Database Management Module started: {startup_details}",
            {
                "registered_databases": registered_count,
                "failed_databases": failed_count,
                "skipped_databases": skipped_count,
                "startup_time": datetime.utcnow().isoformat(),
                "total_processed": registered_count + failed_count + skipped_count
            }
        )
        
    except Exception as e:
        logger.error(f"Error logging startup: {e}")
        # Don't fail startup just because logging failed

async def update_table_display_order(datasette, request):
    """API endpoint to update table display order."""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)
    
    try:
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))
        
        db_id = data.get('db_id')
        table_name = data.get('table_name')
        display_order = data.get('display_order', 0)
        
        # Verify user owns this database
        portal_db = datasette.get_database('portal')
        db_result = await portal_db.execute(
            "SELECT db_name FROM databases WHERE db_id = ? AND user_id = ? AND status != 'Deleted'", 
            [db_id, actor['id']]
        )
        
        if not db_result.first():
            return Response.json({"error": "Database not found or access denied"}, status=404)
        
        # Update display order
        table_id = f"{db_id}_{table_name}"
        current_time = datetime.utcnow().isoformat()
        
        await portal_db.execute_write("""
            INSERT OR REPLACE INTO database_tables 
            (table_id, db_id, table_name, display_order, updated_at, 
             show_in_homepage, created_at)
            VALUES (?, ?, ?, ?, ?, 
                    COALESCE((SELECT show_in_homepage FROM database_tables WHERE table_id = ?), 1),
                    COALESCE((SELECT created_at FROM database_tables WHERE table_id = ?), ?))
        """, [table_id, db_id, table_name, display_order, current_time, table_id, table_id, current_time])
        
        return Response.json({"success": True})
        
    except Exception as e:
        logger.error(f"Error updating display order: {e}")
        return Response.json({"error": str(e)}, status=500)

async def get_database_tables_with_visibility(datasette, db_id, db_name):
    """Auto-create missing database_tables records during retrieval
    """
    portal_db = datasette.get_database('portal')
    
    # Get visibility settings from database_tables
    visibility_result = await portal_db.execute(
        "SELECT table_name, show_in_homepage, display_order FROM database_tables WHERE db_id = ? ORDER BY show_in_homepage DESC, display_order DESC", 
        [db_id]
    )
    
    visibility_settings = {}
    for row in visibility_result:
        visibility_settings[row['table_name']] = {
            'show_in_homepage': row['show_in_homepage'],
            'display_order': row['display_order']
        }
    
    # Get actual tables from the database
    tables = []
    missing_records = []  # Track tables that need database_tables records
    
    try:
        target_db = datasette.get_database(db_name)
        if target_db:
            table_names = await target_db.table_names()
            
            for table_name in table_names:
                # SKIP SYSTEM TABLES
                if is_system_table(table_name):
                    logger.debug(f"Skipping system table: {table_name}")
                    continue
                    
                try:
                    count_result = await target_db.execute(f"SELECT COUNT(*) as count FROM [{table_name}]")
                    record_count = count_result.first()['count'] if count_result.first() else 0
                    
                    # Get column count
                    columns_result = await target_db.execute(f"PRAGMA table_info([{table_name}])")
                    column_count = len(columns_result.rows)
                    
                    # Check if table has database_tables record
                    visibility = visibility_settings.get(table_name, {})
                    
                    if not visibility:
                        # Missing database_tables record - track for creation
                        missing_records.append(table_name)
                        # Use defaults
                        visibility = {'show_in_homepage': True, 'display_order': 100}
                    
                    tables.append({
                        'name': table_name,
                        'full_name': table_name,
                        'record_count': record_count,
                        'columns': column_count,
                        'size': record_count * 0.001,  # Estimate
                        'show_in_homepage': visibility.get('show_in_homepage', True),
                        'display_order': visibility.get('display_order', 100)
                    })
                    
                except Exception as table_error:
                    logger.error(f"Error processing table {table_name}: {table_error}")
                    continue
            
            # Auto-create missing database_tables records
            if missing_records:
                logger.warning(f"Found {len(missing_records)} tables without database_tables records: {missing_records}")
                current_time = datetime.utcnow().isoformat()
                
                for table_name in missing_records:
                    try:
                        table_id = f"{db_id}_{table_name}"
                        
                        # Get next display order
                        count_result = await portal_db.execute(
                            "SELECT COUNT(*) as count FROM database_tables WHERE db_id = ?", [db_id]
                        )
                        table_count = count_result.first()['count'] if count_result.first() else 0
                        display_order = table_count + 100
                        
                        await portal_db.execute_write("""
                            INSERT OR IGNORE INTO database_tables 
                            (table_id, db_id, table_name, show_in_homepage, display_order, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, [table_id, db_id, table_name, True, display_order, current_time, current_time])
                        
                        logger.info(f"Auto-created database_tables record: {table_name}")
                        
                    except Exception as create_error:
                        logger.error(f"Error creating database_tables record for {table_name}: {create_error}")
            
            # Sort by visibility first (visible=True first), then by display_order DESC
            tables.sort(key=lambda x: (not x['show_in_homepage'], -x['display_order']))
                    
    except Exception as db_error:
        logger.error(f"Error accessing database {db_name}: {db_error}")
    
    return tables

async def toggle_table_visibility(datasette, request):
    """API endpoint to toggle table visibility - PRESERVE DISPLAY ORDER."""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)
    
    try:
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))
        
        db_id = data.get('db_id')
        table_name = data.get('table_name')
        show_in_homepage = data.get('show_in_homepage', True)
        
        # Verify user owns this database
        portal_db = datasette.get_database('portal')
        db_result = await portal_db.execute(
            "SELECT db_name, user_id FROM databases WHERE db_id = ? AND user_id = ? AND status != 'Deleted'", 
            [db_id, actor['id']]
        )
        db_record = db_result.first()
        
        if not db_record:
            return Response.json({"error": "Database not found or access denied"}, status=404)
        
        table_id = f"{db_id}_{table_name}"
        current_time = datetime.utcnow().isoformat()
        
        # CRITICAL FIX: Get existing display_order or assign a default
        existing_result = await portal_db.execute(
            "SELECT display_order FROM database_tables WHERE table_id = ?", [table_id]
        )
        existing_row = existing_result.first()
        
        if existing_row:
            # Preserve existing display order
            display_order = existing_row['display_order']
        else:
            # Assign default display order based on table count
            count_result = await portal_db.execute(
                "SELECT COUNT(*) as count FROM database_tables WHERE db_id = ?", [db_id]
            )
            table_count = count_result.first()['count'] if count_result.first() else 0
            display_order = table_count + 1  # New tables get highest order (top)
        
        # Update with preserved display order
        await portal_db.execute_write("""
            INSERT OR REPLACE INTO database_tables 
            (table_id, db_id, table_name, show_in_homepage, display_order, updated_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, COALESCE(
                (SELECT created_at FROM database_tables WHERE table_id = ?), ?
            ))
        """, [table_id, db_id, table_name, show_in_homepage, display_order, current_time, table_id, current_time])
        
        await log_database_action(
            datasette, actor['id'], "toggle_table_visibility",
            f"{'Showed' if show_in_homepage else 'Hid'} table '{table_name}' on homepage",
            {
                "db_id": db_id, "table_name": table_name, 
                "show_in_homepage": show_in_homepage, "display_order": display_order
            }
        )
        
        return Response.json({"success": True})
        
    except Exception as e:
        logger.error(f"Error toggling table visibility: {e}")
        return Response.json({"error": str(e)}, status=500)

async def rename_table_api(datasette, request):
    """API endpoint to rename a table - PREVENT SYSTEM TABLE RENAMING."""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)
    
    try:
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))
        
        db_name = data.get('db_name')
        old_table_name = data.get('old_table_name')
        new_table_name = data.get('new_table_name', '').strip()
        
        # PREVENT RENAMING OF SYSTEM TABLES
        if is_system_table(old_table_name):
            return Response.json({"error": f"Cannot rename system table '{old_table_name}'. This table is required for database functionality."}, status=400)
        
        # Validate new table name
        if not new_table_name:
            return Response.json({"error": "New table name cannot be empty"}, status=400)
        
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', new_table_name):
            return Response.json({"error": "Table name must start with letter/underscore and contain only letters, numbers, underscores"}, status=400)
        
        if len(new_table_name) > 64:
            return Response.json({"error": "Table name too long (max 64 characters)"}, status=400)
        
        # PREVENT RENAMING TO SYSTEM TABLE NAMES
        if is_system_table(new_table_name):
            return Response.json({"error": f"Cannot use system table name '{new_table_name}'"}, status=400)
        
        # Verify user owns the database
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"error": "Access denied"}, status=403)
        
        # Get database and check if tables exist
        target_db = datasette.get_database(db_name)
        table_names = await target_db.table_names()
        
        if old_table_name not in table_names:
            return Response.json({"error": f"Table '{old_table_name}' not found"}, status=404)
        
        if new_table_name in table_names:
            return Response.json({"error": f"Table '{new_table_name}' already exists"}, status=400)
        
        # Rename the table using SQLite ALTER TABLE
        await target_db.execute_write(f"ALTER TABLE [{old_table_name}] RENAME TO [{new_table_name}]")
        
        # Update database_tables record if it exists
        portal_db = datasette.get_database('portal')
        db_result = await portal_db.execute(
            "SELECT db_id FROM databases WHERE db_name = ? AND user_id = ?", [db_name, actor['id']]
        )
        db_record = db_result.first()
        
        if db_record:
            old_table_id = f"{db_record['db_id']}_{old_table_name}"
            new_table_id = f"{db_record['db_id']}_{new_table_name}"
            current_time = datetime.utcnow().isoformat()
            
            # Check if record exists and update it
            existing_result = await portal_db.execute(
                "SELECT * FROM database_tables WHERE table_id = ?", [old_table_id]
            )
            existing_record = existing_result.first()
            
            if existing_record:
                await portal_db.execute_write(
                    "DELETE FROM database_tables WHERE table_id = ?", [old_table_id]
                )
                await portal_db.execute_write("""
                    INSERT INTO database_tables 
                    (table_id, db_id, table_name, show_in_homepage, display_order, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, [new_table_id, db_record['db_id'], new_table_name, 
                      existing_record['show_in_homepage'], existing_record['display_order'],
                      existing_record['created_at'], current_time])
        
        # Update database timestamp
        await update_database_timestamp(datasette, db_name)
        
        # Log the action
        await log_database_action(
            datasette, actor['id'], "rename_table",
            f"Renamed table '{old_table_name}' to '{new_table_name}' in database '{db_name}'",
            {"db_name": db_name, "old_name": old_table_name, "new_name": new_table_name}
        )
        
        return Response.json({"success": True, "new_table_name": new_table_name})
        
    except Exception as e:
        logger.error(f"Error renaming table: {e}")
        return Response.json({"error": str(e)}, status=500)
    
async def fix_missing_display_orders_startup():
    """Fix existing database_tables records that are missing display_order"""
    try:
        query_db = datasette.get_database('portal')
        
        # Find records missing display_order
        missing_order_result = await query_db.execute(
            "SELECT table_id, db_id, table_name FROM database_tables WHERE display_order IS NULL OR display_order = 0"
        )
        
        missing_records = missing_order_result.rows
        if missing_records:
            logger.warning(f"Found {len(missing_records)} table records missing display_order")
            
            current_time = datetime.utcnow().isoformat()
            
            for record in missing_records:
                table_id = record['table_id']
                db_id = record['db_id']
                table_name = record['table_name']
                
                # Get next available order for this database
                count_result = await query_db.execute(
                    "SELECT COALESCE(MAX(display_order), 99) + 1 as next_order FROM database_tables WHERE db_id = ?", [db_id]
                )
                next_order = count_result.first()['next_order']
                
                # Update the record
                await query_db.execute_write(
                    "UPDATE database_tables SET display_order = ?, updated_at = ? WHERE table_id = ?",
                    [next_order, current_time, table_id]
                )
                
                logger.info(f"Fixed missing display_order for {table_name}: {next_order}")
        
    except Exception as e:
        logger.error(f"Error fixing missing display orders: {e}")


@hookimpl
def register_routes():
    """Register datasette admin panel routes."""
    return [
        (r"^/$", index_page),
        (r"^/all-databases$", all_databases_page),
        (r"^/manage-databases$", manage_databases),
        (r"^/db/([^/]+)/publish$", publish_database),
        (r"^/db/([^/]+)/unpublish$", unpublish_database),
        (r"^/db/([^/]+)/homepage$", database_homepage),
        (r"^/edit-content/([^/]+)$", edit_content),
        (r"^/delete-table/(?P<db_name>[^/]+)/(?P<table_name>[^/]+)$", delete_table),
        (r"^/delete-table-ajax$", delete_table_ajax),
        (r"^/data/[^/]+/[^/]+$", serve_database_image),
        (r"^/api/toggle-table-visibility$", toggle_table_visibility),
        (r"^/api/update-table-order$", update_table_display_order),
        (r"^/api/rename-table$", rename_table_api),
    ]

@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Block insecure upload plugin."""
    if action == "upload-csvs":
        return False  # Block insecure official plugin
    return None

@hookimpl
def startup(datasette):
    """Startup hook with comprehensive database registration and error handling"""
    
    async def inner():
        try:
            logger.info("Starting EDGI Datasette Database Management Module...")
            
            # Ensure directories exist
            ensure_data_directories()
            
            # Get database path - SUPPORT MULTIPLE ENVIRONMENTS
            db_path = None
            possible_paths = [
                os.getenv('PORTAL_DB_PATH'),  # Environment variable
                "/data/portal.db",            # Docker/production
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
            
            if not db_path:
                logger.warning("Portal database not found. Checked paths:")
                for path in possible_paths:
                    if path:
                        logger.warning(f"  - {path} {'(exists)' if os.path.exists(path) else '(not found)'}")
                logger.warning("Database registration will be skipped. Some features may not work.")
                return
            
            # Connect to portal database
            try:
                query_db = datasette.get_database('portal')
                if not query_db:
                    logger.error("Failed to get portal database connection")
                    return
            except Exception as conn_error:
                logger.error(f"Error connecting to portal database: {conn_error}")
                return
            
            # Verify database structure
            if not await verify_database_structure_startup(query_db):
                logger.error("Portal database structure verification failed")
                return
            
            # Register existing user databases with enhanced error handling
            registered_count, failed_count, skipped_count = await register_user_databases_startup(datasette, query_db)
            
            # Log startup results
            await log_startup_success_startup(datasette, registered_count, failed_count, skipped_count)
            
            # Optional: Fix any missing registrations
            if failed_count > 0:
                logger.info("Attempting to fix missing database registrations...")
                fixed_count = await fix_missing_registrations_startup(datasette, query_db)
                if fixed_count > 0:
                    logger.info(f"Fixed {fixed_count} missing database registrations")
            
            logger.info(f"Database Management Module startup completed successfully")
            logger.info(f"Summary: {registered_count} registered, {failed_count} failed, {skipped_count} skipped")
            
        except Exception as e:
            logger.error(f"CRITICAL: Database Management Module startup failed: {str(e)}")
            import traceback
            logger.error(f"Startup traceback: {traceback.format_exc()}")
            # Don't raise - allow Datasette to continue even if registration fails

    return inner
    