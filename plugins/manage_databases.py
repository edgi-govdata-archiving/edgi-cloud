
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
    check_database_name_available,
    user_owns_database,
    validate_database_name,
    handle_form_errors,
    redirect_authenticated_user,
    generate_website_url,
    ensure_data_directories,
    get_all_published_databases,
    get_success_error_from_request,
    create_feature_cards_from_databases,
    create_statistics_data,
    update_database_timestamp_by_id,
    parse_markdown_links,
    DATA_DIR,
    get_max_image_size,
    get_max_databases_per_user,
    handle_image_upload_robust,
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
    feature_cards = create_feature_cards_from_databases(stats['featured_databases'], limit=6)
    
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

    # Database processing
    databases_with_tables = []
    for db_info in user_databases:
        db_name = db_info["db_name"]
        db_id = db_info["db_id"]
        total_size = 0
        tables = []
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
                
                # Get database contents
                user_db = sqlite_utils.Database(db_path)
                table_names = user_db.table_names()
                table_count = len(table_names)
                
                for name in table_names:
                    try:
                        table_info = user_db[name]
                        record_count = table_info.count
                        table_size = record_count * 0.001  # Estimate size for display
                        total_size += table_size
                        
                        tables.append({
                            'name': name,
                            'full_name': name,
                            'preview': f"/{db_name}/{name}",
                            'size': table_size,
                            'record_count': record_count,
                            'columns': len(list(table_info.columns_dict.keys())),
                            'progress': 100
                        })
                    except Exception as table_error:
                        logger.error(f"Error processing table {name} in {db_name}: {table_error}")
                        tables.append({
                            'name': name,
                            'full_name': name,
                            'preview': f"/{db_name}/{name}",
                            'size': 0,
                            'record_count': 0,
                            'columns': 0,
                            'progress': 0,
                            'error': True
                        })
                
                user_db.close()  # Explicitly close the database
                
            else:
                logger.warning(f"Database file not found for {db_name}: {db_path}")
                file_size_kb = 0
        except Exception as e:
            logger.error(f"Error loading database {db_name}: {str(e)}")
            file_size_kb = 0
            
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
    """Delete table from database."""
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
                        
            # Delete the table
            await target_db.execute_write(f"DROP TABLE [{table_name}]")
            logger.debug(f"Successfully deleted table {table_name} from {db_name}")

            # Update database timestamp
            portal_db = datasette.get_database("portal")
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
    """AJAX endpoint for table deletion."""
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
    """Database homepage with preview functionality for owners."""
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
    
    # Rest of the function remains the same...
    try:
        content = await get_database_content(datasette, db_name)
        if not content:
            logger.error(f"No content found for database {db_name}")
            # Redirect to standard Datasette interface
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
        
        # Get database statistics for custom homepage
        try:
            user_db = datasette.get_database(db_name)
            if user_db:
                # Use proper async operations
                table_names_result = await user_db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                table_names = [row['name'] for row in table_names_result.rows]
                
                tables = []
                total_records = 0
                
                for table_name in table_names[:6]:  # Show max 6 featured tables
                    try:
                        count_result = await user_db.execute(f"SELECT COUNT(*) as count FROM [{table_name}]")
                        record_count = count_result.first()['count'] if count_result.first() else 0
                        total_records += record_count
                        
                        tables.append({
                            'title': table_name.replace('_', ' ').title(),
                            'description': f"Data table with {record_count:,} records",
                            'url': f"/{db_name}/{table_name}",
                            'icon': 'ri-table-line',
                            'count': record_count
                        })
                    except Exception as table_error:
                        logger.error(f"Error processing table {table_name}: {table_error}")
                        continue
                
                statistics = [
                    {
                        'label': 'Data Tables',
                        'value': len(table_names),
                        'url': f'/{db_name}'
                    },
                    {
                        'label': 'Total Records',
                        'value': f"{total_records:,}",
                        'url': f'/{db_name}'
                    },
                    {
                        'label': 'View all available data tables',
                        'value': 'Browse All Tables',
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
    """FIXED: Edit database content with robust image handling."""
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
            # Handle image upload with robust parser
            try:
                max_img_size = await get_max_image_size(datasette)
                
                # Use the robust image upload handler
                result, error = await handle_image_upload_robust(
                    datasette, request, db_id, actor, max_img_size
                )
                
                if error:
                    return Response.redirect(f"{request.path}?error={error}")
                
                if result:
                    # Save to database
                    await query_db.execute_write(
                        "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                        [db_id, 'header_image', json.dumps(result), datetime.utcnow().isoformat(), actor['username']]
                    )

                    # Update database timestamp
                    await update_database_timestamp_by_id(datasette, db_id)
                    
                    await log_database_action(
                        datasette, actor.get("id"), "edit_content", 
                        f"Updated and optimized header image for {db_name}",
                        {"db_name": db_name, "section": "header_image", "image_optimized": True}
                    )
                    
                    return Response.redirect(f"{request.path}?success=Header image updated successfully")
                
            except Exception as e:
                logger.error(f"Error handling image upload: {e}")
                return Response.redirect(f"{request.path}?error=Image upload failed: {str(e)}")
        else:
            # Handle text form data (unchanged but simplified)
            post_vars = await request.post_vars()
            
            if 'title' in post_vars:
                new_content = {"content": post_vars['title']}
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'title', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
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
                await update_database_timestamp_by_id(datasette, db_id)
                await log_database_action(
                    datasette, actor.get("id"), "edit_content", 
                    f"Updated description for {db_name}",
                    {"db_name": db_name, "section": "description"}
                )
                return Response.redirect(f"{request.path}?success=Description updated")
            
            if 'footer' in post_vars:
                new_content = {
                    "content": post_vars['footer'],
                    "odbl_text": "Data licensed under ODbL",
                    "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                    "paragraphs": parse_markdown_links(post_vars['footer'])
                }
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, 'footer', json.dumps(new_content), datetime.utcnow().isoformat(), actor['username']]
                )
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
    ]

@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Block insecure upload plugin."""
    if action == "upload-csvs":
        return False  # Block insecure official plugin
    return None

@hookimpl
def startup(datasette):
    """ENHANCED: Robust startup hook with comprehensive database registration and error handling"""
    
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