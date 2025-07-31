"""
Datasette CSV Upload Plugin using Built-in Functionality
Leverages Datasette's existing CSV upload capabilities while adding user ownership verification
"""

import logging
from datasette import hookimpl
from datasette.utils.asgi import Response

logger = logging.getLogger(__name__)

@hookimpl
def register_routes():
    """Register routes that won't conflict with Datasette's default routing"""
    return [
        # Use a completely unique prefix that won't conflict
        (r"^/upload-secure/([^/]+)$", secure_csv_upload),
        # Keep the fallback
        (r"^/csv-upload-builtin$", custom_upload_page),
    ]

async def secure_csv_upload(request, datasette):
    """Secure CSV upload with database pre-selected"""
    
    # Extract database name from URL
    path_parts = request.path.strip('/').split('/')
    if len(path_parts) >= 2 and path_parts[0] == 'upload-secure':
        db_name = path_parts[1]
    else:
        return Response.redirect("/manage-databases?error=Invalid upload URL")
    
    logger.debug(f"Secure upload requested for database: {db_name}")
    
    actor = request.actor
    
    # Check authentication
    if not actor:
        return Response.redirect("/login?error=Please log in to upload CSV files")
    
    # Verify ownership
    if not await verify_database_ownership(datasette, actor["id"], db_name):
        return Response.redirect(
            f"/manage-databases?error=Access denied to database '{db_name}'"
        )
    
    # Check if database exists in Datasette
    try:
        target_db = datasette.get_database(db_name)
        if not target_db:
            return Response.redirect(f"/manage-databases?error=Database '{db_name}' not found in Datasette")
    except Exception as e:
        logger.error(f"Error accessing database {db_name}: {e}")
        return Response.redirect(f"/manage-databases?error=Database '{db_name}' not accessible")
    
    # For GET requests, redirect to Datasette's built-in upload page
    if request.method == "GET":
        # Log the activity
        await log_csv_activity(datasette, actor["id"], db_name, "csv_upload_page_access")
        
        # Redirect directly to Datasette's upload page
        upload_url = f"/{db_name}/-/upload-csvs"
        logger.debug(f"Redirecting to Datasette upload page: {upload_url}")
        return Response.redirect(upload_url)
    
    # For POST requests, we shouldn't intercept - let Datasette handle them
    else:
        # Log the activity
        await log_csv_activity(datasette, actor["id"], db_name, "csv_upload_attempt")
        
        # Let Datasette handle the POST request by redirecting to its handler
        upload_url = f"/{db_name}/-/upload-csvs"
        return Response.redirect(upload_url)

async def custom_upload_page(request, datasette):
    """Custom upload page that redirects to appropriate handler"""
    
    actor = request.actor
    if not actor:
        return Response.redirect("/login?error=Please log in to upload CSV files")
    
    database_name = request.args.get("database")
    if not database_name:
        return Response.redirect("/manage-databases?error=No database specified")
    
    # Verify ownership
    if not await verify_database_ownership(datasette, actor["id"], database_name):
        return Response.redirect(
            f"/manage-databases?error=Access denied to database '{database_name}'"
        )
    
    # Check if database exists and is accessible
    try:
        target_db = datasette.get_database(database_name)
        if not target_db:
            return Response.redirect(f"/manage-databases?error=Database '{database_name}' not found")
    except Exception as e:
        logger.error(f"Error accessing database {database_name}: {e}")
        return Response.redirect(f"/manage-databases?error=Database error: {str(e)}")
    
    # Always redirect to Datasette's built-in upload functionality
    upload_url = f"/{database_name}/-/upload-csvs"
    logger.debug(f"Redirecting to Datasette's upload page: {upload_url}")
    return Response.redirect(upload_url)

async def verify_database_ownership(datasette, user_id, db_name):
    """Verify user owns the database"""
    try:
        portal_db = datasette.get_database("portal")
        result = await portal_db.execute(
            "SELECT 1 FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, user_id]
        )
        return len(result.rows) > 0
    except Exception as e:
        logger.error(f"Ownership check error: {e}")
        return False

async def log_csv_activity(datasette, user_id, db_name, action):
    """Log CSV-related activity"""
    try:
        import uuid
        from datetime import datetime
        
        portal_db = datasette.get_database("portal")
        await portal_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [
                str(uuid.uuid4()),
                user_id,
                action,
                f"CSV activity for database {db_name}",
                datetime.utcnow().isoformat()
            ]
        )
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Control access to CSV upload functionality"""
    
    # Allow access to upload-csvs for authenticated users
    # The ownership check happens in the route handler
    if action == "upload-csvs":
        return actor is not None
    
    # Allow our custom CSV upload action
    if action == "csv-upload":
        return actor is not None
    
    return None