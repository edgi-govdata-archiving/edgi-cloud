
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
from email.parser import BytesParser
from email.policy import default

# Add the plugins directory to Python path for imports
import sys
plugins_dir = os.path.dirname(os.path.abspath(__file__))
if plugins_dir not in sys.path:
    sys.path.insert(0, plugins_dir)

# Import from common_utils
from common_utils import (
    get_actor_from_request,
    log_database_action,
    log_user_activity,
    verify_user_session,
    get_portal_content,
    get_database_content,
    get_database_statistics,
    check_database_name_unique,
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
    parse_markdown_links,
    apply_inline_formatting,
    sanitize_text,
    DATA_DIR,
    STATIC_DIR,
    MAX_DATABASES_PER_USER,
    MAX_FILE_SIZE,
    ALLOWED_EXTENSIONS
)


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def index_page(datasette, request):
    """Enhanced index page with improved statistics and user database info."""
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

    # Get enhanced statistics for public homepage
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
    """Enhanced manage databases with improved filtering and sorting by most recent."""
    logger.debug(f"Manage Databases request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized manage databases attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    # Get enhanced filter parameter
    status_filter = request.args.get('status', 'active')
    
    # Build query based on enhanced filter options
    query_db = datasette.get_database('portal')
    
    if status_filter == 'active':
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished') ORDER BY updated_at DESC"
    elif status_filter == 'draft':
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at FROM databases WHERE user_id = ? AND status = 'Draft' ORDER BY updated_at DESC"
    elif status_filter == 'published':
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at FROM databases WHERE user_id = ? AND status = 'Published' ORDER BY updated_at DESC"
    elif status_filter == 'unpublished':
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at FROM databases WHERE user_id = ? AND status = 'Unpublished' ORDER BY updated_at DESC"
    elif status_filter == 'trash':
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at FROM databases WHERE user_id = ? AND status = 'Trashed' ORDER BY updated_at DESC"
    else:  # 'all'
        query = "SELECT db_id, db_name, status, website_url, file_path, trashed_at, restore_deadline, created_at FROM databases WHERE user_id = ? AND status IN ('Draft', 'Published', 'Unpublished', 'Trashed') ORDER BY updated_at DESC"
    
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

    # Enhanced database processing with better error handling
    databases_with_tables = []
    for db_info in user_databases:
        db_name = db_info["db_name"]
        db_id = db_info["db_id"]
        total_size = 0
        tables = []
        table_count = 0

        # Check if database has custom homepage
        homepage_result = await query_db.execute(
            "SELECT COUNT(*) FROM admin_content WHERE db_id = ? AND section = 'title'",
            [db_id]
        )
        has_custom_homepage = homepage_result.first()[0] > 0
        
        try:
            db_path = db_info["file_path"]
            if db_path and os.path.exists(db_path):
                user_db = sqlite_utils.Database(db_path)
                table_names = user_db.table_names()
                table_count = len(table_names)
                
                for name in table_names:
                    try:
                        table_info = user_db[name]
                        record_count = table_info.count
                        table_size = record_count * 0.001  # Estimate size
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
                logger.error(f"Database file not found for {db_name}: {db_path}")
        except Exception as e:
            logger.error(f"Error loading database {db_name}: {str(e)}")
            
        databases_with_tables.append({
            **db_info,
            'tables': tables,
            'table_count': table_count,
            'total_size': total_size,
            'website_url': f"/db/{db_name}/homepage",
            'upload_url': f"/upload-secure/{db_name}",
            'has_custom_homepage': has_custom_homepage
        })

    # Get user statistics
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

async def create_database(datasette, request):
    """Create new database with validation."""
    logger.debug(f"Create Database request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized create database attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    # Get content for template
    content = await get_portal_content(datasette)

    if request.method == "POST":
        post_vars = await request.post_vars()
        db_name = post_vars.get("db_name", "").strip()
        
        # Validate database name
        is_valid_name, name_error = validate_database_name(db_name)
        if not is_valid_name:
            return await handle_form_errors(
                datasette, "create_database.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                },
                request, name_error
            )

        # Check if name is available
        is_available = await check_database_name_available(datasette, db_name)
        if not is_available:
            return await handle_form_errors(
                datasette, "create_database.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                },
                request, f"Database name '{db_name}' already exists. Please choose a different name."
            )

        user_id = actor.get("id")
        
        # Check database limit
        query_db = datasette.get_database('portal')
        result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
        db_count = result.first()[0]
        if db_count >= MAX_DATABASES_PER_USER:
            return await handle_form_errors(
                datasette, "create_database.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                },
                request, f"Maximum {MAX_DATABASES_PER_USER} databases per user reached"
            )

        try:
            db_id = uuid.uuid4().hex[:20]
            website_url = generate_website_url(request, db_name)
            
            # Create user directory and database file
            user_dir = os.path.join(DATA_DIR, user_id)
            os.makedirs(user_dir, exist_ok=True)
            db_path = os.path.join(user_dir, f"{db_name}.db")
            
            # Create new SQLite database
            user_db = sqlite_utils.Database(db_path)

            # Insert database record
            await query_db.execute_write(
                "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at, file_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [db_id, user_id, db_name, website_url, "Draft", datetime.utcnow(), db_path]
            )
            
            # AUTO-CREATE CUSTOM HOMEPAGE
            custom_title = f"{db_name.replace('_', ' ').title()}"
            custom_description = f"Welcome to the {db_name.replace('_', ' ').title()}."
            custom_footer = f"{db_name.replace('_', ' ').title()} | Powered by Resette"
            
            custom_content = [
                ("title", {"content": custom_title}),
                ("description", {
                    "content": custom_description,
                    "paragraphs": parse_markdown_links(custom_description)
                }),
                ("header_image", {
                    "image_url": "/static/default_header.jpg",
                    "alt_text": f"{db_name.replace('_', ' ').title()} Portal Header",
                    "credit_text": "",
                    "credit_url": ""
                }),
                ("footer", {
                    "content": custom_footer,
                    "odbl_text": "Data licensed under ODbL",
                    "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                    "paragraphs": parse_markdown_links(custom_footer)
                })
            ]
            
            # Insert custom content for auto-created homepage
            for section, content_data in custom_content:
                await query_db.execute_write(
                    "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    [db_id, section, json.dumps(content_data), datetime.utcnow().isoformat(), actor['username']]
                )
            
            # Register database with Datasette immediately (even for drafts)
            try:
                db_instance = Database(datasette, path=db_path, is_mutable=True)
                datasette.add_database(db_instance, name=db_name)
                logger.debug(f"Successfully registered new database: {db_name} (Draft)")
            except Exception as reg_error:
                logger.error(f"Error registering new database {db_name}: {reg_error}")

            # Log activity
            await log_database_action(
                datasette, user_id, "create_database", 
                f"Created database {db_name} with custom homepage",
                {
                    "db_name": db_name,
                    "db_id": db_id,
                    "website_url": website_url,
                    "auto_homepage_created": True
                }
            )
            
            logger.debug(f"Database created with homepage: {db_name}, website_url={website_url}, file_path={db_path}")
            return Response.redirect(f"/manage-databases?success=Database '{db_name}' created successfully with custom homepage. You can now upload CSV files and customize your portal.")

        except Exception as e:
            logger.error(f"Create database error: {str(e)}")
            return await handle_form_errors(
                datasette, "create_database.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                },
                request, f"Create database error: {str(e)}"
            )

    return Response.html(
        await datasette.render_template(
            "create_database.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
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
        result = await query_db.execute(
            "SELECT db_id, user_id, file_path, status FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor.get("id")]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found or you do not have permission", status=404)
        
        if db_info['status'] == 'Published':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is already published")
        
        if db_info['status'] == 'Trashed':
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' is in trash. Restore it first.")
        
        # Update status to Published
        await query_db.execute_write(
            "UPDATE databases SET status = 'Published' WHERE db_name = ?",
            [db_name]
        )
        
        # Register database with Datasette
        if db_info['file_path'] and os.path.exists(db_info['file_path']):
            try:
                user_db = Database(datasette, path=db_info['file_path'], is_mutable=True)
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
    """Enhanced database homepage with preview functionality for owners."""
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
    
    # Check if database exists and user has permission
    query_db = datasette.get_database('portal')
    try:
        result = await query_db.execute(
            "SELECT db_id, db_name, status, user_id, file_path FROM databases WHERE db_name = ?",
            [db_name]
        )
        db_info = result.first()
        if not db_info:
            return Response.text("Database not found", status=404)
        
        actor = get_actor_from_request(request)
        
        # Access control logic
        """if is_preview:
            # Preview mode: only owners can access
            if not actor or actor['id'] != db_info['user_id']:
                return Response.text("Access denied: Only database owners can preview", status=403)
        else:
            # Public mode: Published databases are public, drafts only for owners
            if db_info['status'] != 'Published' and (not actor or actor['id'] != db_info['user_id']):
                return Response.text("Database not found or not published", status=404)
        """
        if db_info['status'] == 'Trashed' or db_info['status'] == 'Deleted':
                return Response.text("Database not found or not published", status=404)


        # Check if database is registered correctly
        try:
            # Try to get the database - this will work if it's registered
            user_db = datasette.get_database(db_name)
            if not user_db:
                # Database not registered, try to register it
                if db_info['file_path'] and os.path.exists(db_info['file_path']):
                    new_db = Database(datasette, path=db_info['file_path'], is_mutable=True)
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
        return
    
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
                
                if len(body) > MAX_FILE_SIZE:
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

async def verify_database_structure(query_db):
    """Verify the database has the required structure."""
    try:
        # Check if required tables exist
        required_tables = ['users', 'databases', 'admin_content', 'activity_logs']
        
        result = await query_db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row['name'] for row in result.rows]
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            logger.error(f"Missing required tables: {missing_tables}")
            return False
        
        logger.info("Database structure verified successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error verifying database structure: {e}")
        return False

async def register_user_databases(datasette, query_db):
    """Register all user databases with Datasette."""
    registered_count = 0
    failed_count = 0
    
    try:
        # Get all active databases
        result = await query_db.execute(
            "SELECT db_name, file_path, status FROM databases WHERE status IN ('Draft', 'Published', 'Unpublished')"
        )
        
        for row in result:
            db_name = row['db_name']
            file_path = row['file_path']
            status = row['status']
            
            try:
                if file_path and os.path.exists(file_path):
                    # Check if already registered
                    if db_name not in datasette.databases:
                        db_instance = Database(datasette, path=file_path, is_mutable=True)
                        datasette.add_database(db_instance, name=db_name)
                        registered_count += 1
                        logger.debug(f"Registered database: {db_name} ({status})")
                    else:
                        logger.debug(f"Database already registered: {db_name}")
                else:
                    logger.warning(f"Database file not found: {file_path} for {db_name}")
                    failed_count += 1
                    
            except Exception as reg_error:
                logger.error(f"Failed to register database {db_name}: {reg_error}")
                failed_count += 1
        
        logger.info(f"Database registration complete: {registered_count} registered, {failed_count} failed")
        return registered_count, failed_count
        
    except Exception as e:
        logger.error(f"Error during database registration: {e}")
        return 0, 0

async def log_startup_success(datasette, registered_count, failed_count):
    """Log successful startup."""
    try:
        startup_details = f"Registered {registered_count} databases, {failed_count} failed"
        await log_database_action(
            datasette, "system", "startup", 
            f"EDGI Cloud Portal started successfully: {startup_details}",
            {
                "registered_databases": registered_count,
                "failed_databases": failed_count,
                "startup_time": datetime.utcnow().isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Error logging startup: {e}")

async def fix_missing_database_registrations(datasette):
    """Fix missing database registrations by checking all active databases and re-registering them."""
    logger.info("Checking for missing database registrations...")
    
    query_db = datasette.get_database('portal')
    try:
        # Get all active databases from portal database
        result = await query_db.execute(
            "SELECT db_name, file_path, status FROM databases WHERE status IN ('Draft', 'Published', 'Unpublished')"
        )
        
        fixed_count = 0
        missing_files_count = 0
        
        for row in result:
            db_name = row['db_name']
            file_path = row['file_path']
            status = row['status']
            
            try:
                # Check if database is registered with Datasette
                if db_name not in datasette.databases:
                    # Check if file exists
                    if file_path and os.path.exists(file_path):
                        # Re-register the database
                        db_instance = Database(datasette, path=file_path, is_mutable=True)
                        datasette.add_database(db_instance, name=db_name)
                        fixed_count += 1
                        logger.info(f"Re-registered missing database: {db_name} ({status})")
                    else:
                        missing_files_count += 1
                        logger.warning(f"Database file missing for {db_name}: {file_path}")
                        
                        # Could optionally mark as corrupted or remove from portal database
                        # For now, just log the issue
                        
            except Exception as reg_error:
                logger.error(f"Failed to re-register database {db_name}: {reg_error}")
        
        logger.info(f"Database registration check complete: {fixed_count} fixed, {missing_files_count} missing files")
        return fixed_count, missing_files_count
        
    except Exception as e:
        logger.error(f"Error during database registration check: {e}")
        return 0, 0


@hookimpl
def register_routes():
    """Register datasette admin panel routes."""
    return [
        (r"^/$", index_page),
        (r"^/all-databases$", all_databases_page),
        (r"^/manage-databases$", manage_databases),
        (r"^/create-database$", create_database),
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
    """Enhanced startup hook with proper database registration"""
    
    async def inner():
        try:
            logger.info("Starting Datasette Database Management Module...")
            
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
            query_db = datasette.get_database('portal')
            
            # Verify database structure
            await verify_database_structure(query_db)
            
            # Register existing user databases
            registered_count, failed_count = await register_user_databases(datasette, query_db)
            
            # Log startup success
            await log_startup_success(datasette, registered_count, failed_count)
            
            logger.info("Datasette Database Management Module startup completed successfully")
            
        except Exception as e:
            logger.error(f"Datasette Database Management Module startup failed: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            # Don't re-raise - let Datasette continue starting

    return inner