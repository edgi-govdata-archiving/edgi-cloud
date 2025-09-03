"""
Database Creation Module - Complete database creation functionality
Handles: Empty database creation, SQLite file import, file validation, and database registration
"""

import json
import logging
import uuid
import os
import sqlite3
import sqlite_utils
import shutil
import re
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database

# Add the plugins directory to Python path for imports
import sys
PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGINS_DIR not in sys.path:
    sys.path.insert(0, PLUGINS_DIR)

# Import from common_utils
from common_utils import (
    get_actor_from_request,
    log_database_action,
    verify_user_session,
    get_portal_content,
    check_database_name_available,
    validate_database_name,
    handle_form_errors,
    generate_website_url,
    ensure_data_directories,
    get_success_error_from_request,
    parse_markdown_links,
    DATA_DIR,
    get_max_file_size,
    get_max_databases_per_user,
    get_system_settings,
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def create_empty_database(datasette, request):
    """Create empty database - dedicated function."""
    logger.debug(f"Create Empty Database request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized create empty database attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    # Get content and system settings for template
    content = await get_portal_content(datasette)
    system_settings = await get_system_settings(datasette)

    if request.method == "POST":
        try:
            # Use regular form handling (no multipart)
            formdata = await request.post_vars()
            logger.debug(f"Empty database form data: {dict(formdata)}")
            
            db_name = formdata.get("db_name", "").strip()
            logger.debug(f"Empty database - db_name: '{db_name}'")

            # Validate database name
            if not db_name:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "system_settings": system_settings,
                    },
                    request, "Database name is required"
                )

            is_valid_name, name_error = validate_database_name(db_name)
            if not is_valid_name:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "system_settings": system_settings,
                    },
                    request, name_error
                )

            # Check if name is available
            is_available = await check_database_name_available(datasette, db_name)
            if not is_available:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "system_settings": system_settings,
                    },
                    request, f"Database name '{db_name}' already exists. Please choose a different name."
                )

            user_id = actor.get("id")
            
            # Check database limit
            query_db = datasette.get_database('portal')
            result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
            db_count = result.first()[0]
            max_databases = await get_max_databases_per_user(datasette)
            if db_count >= max_databases:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "system_settings": system_settings,
                    },
                    request, f"Maximum {max_databases} databases per user reached"
                )

            # Create empty database
            logger.debug(f"Creating empty database: {db_name}")
            
            db_id = uuid.uuid4().hex[:20]
            website_url = generate_website_url(request, db_name)
            
            # Create user directory and database file
            user_dir = os.path.join(DATA_DIR, user_id)
            os.makedirs(user_dir, exist_ok=True)
            db_path = os.path.join(user_dir, f"{db_name}.db")
            
            # Create new SQLite database
            user_db = sqlite_utils.Database(db_path)
            user_db.close()

            # Insert database record
            current_time = datetime.utcnow().isoformat()
            await query_db.execute_write(
                "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at, updated_at, file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [db_id, user_id, db_name, website_url, "Draft", current_time, current_time, db_path]
            )
            
            # Create custom homepage
            await create_simple_homepage(datasette, db_id, db_name, actor, current_time, 0, "empty")
            
            # Register with Datasette
            try:
                db_instance = Database(datasette, path=db_path, is_mutable=True)
                datasette.add_database(db_instance, name=db_name)
                logger.debug(f"Successfully registered empty database: {db_name}")
            except Exception as reg_error:
                logger.error(f"Error registering database {db_name}: {reg_error}")

            # Log activity
            await log_database_action(
                datasette, user_id, "create_empty_database", 
                f"Created empty database {db_name}",
                {
                    "db_name": db_name,
                    "db_id": db_id,
                    "website_url": website_url,
                    "creation_method": "empty"
                }
            )
            
            logger.info(f"Empty database created successfully: {db_name}")
            return Response.redirect(f"/manage-databases?success=Empty database '{db_name}' created successfully! You can now upload data files and customize your portal.")

        except Exception as e:
            logger.error(f"Create empty database error: {str(e)}")
            return await handle_form_errors(
                datasette, "create_empty_database.html",
                {
                    "metadata": datasette.metadata(),
                    "content": content,
                    "actor": actor,
                    "system_settings": system_settings,
                },
                request, f"Error creating database: {str(e)}"
            )

    # GET request
    return Response.html(
        await datasette.render_template(
            "create_empty_database.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "system_settings": system_settings,
            },
            request=request
        )
    )

async def create_import_database(datasette, request):
    """Simple database import with corrected form parsing and file size validation."""
    logger.debug(f"Create Import Database request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        logger.warning(f"Unauthorized create import database attempt: actor=None")
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    # Get content and system settings for template
    content = await get_portal_content(datasette)
    system_settings = await get_system_settings(datasette)

    if request.method == "POST":
        try:
            # Get raw body and extract data manually
            body = await request.post_body()
            logger.debug(f"Received body size: {len(body)} bytes")

            # Server-side file size validation - check raw body size first
            max_file_size = await get_max_file_size(datasette)
            if len(body) > max_file_size + 1024:  # Add 1KB buffer for form overhead
                size_mb = max_file_size // (1024 * 1024)
                actual_mb = len(body) // (1024 * 1024)
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Request too large ({actual_mb}MB). Maximum allowed: {size_mb}MB"
                )

            # Simple boundary extraction
            content_type = request.headers.get('content-type', '')
            boundary_match = re.search(r'boundary=([^;,\s]+)', content_type)
            if not boundary_match:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, "Invalid form data format"
                )

            boundary = boundary_match.group(1).strip('"')
            boundary_bytes = f'--{boundary}'.encode()
            
            logger.debug(f"Using boundary: {boundary}")

            # Split by boundary
            parts = body.split(boundary_bytes)
            logger.debug(f"Found {len(parts)} boundary parts")

            # Extract form data and file data
            db_name = ""
            file_content = None
            filename = ""

            for i, part in enumerate(parts):
                if len(part) < 20:  # Skip empty parts
                    continue

                part_str = part.decode('utf-8', errors='ignore')
                logger.debug(f"Part {i}: {part_str[:200]}...")

                # Look for db_name field with proper parsing
                if 'name="db_name"' in part_str:
                    # Find content after headers (after double newline)
                    content_start = part_str.find('\r\n\r\n')
                    if content_start == -1:
                        content_start = part_str.find('\n\n')
                    
                    if content_start != -1:
                        content_part = part_str[content_start:].strip()
                        # Remove header separators and get actual value
                        db_name = content_part.replace('\r\n\r\n', '').replace('\n\n', '').strip()
                        # Remove any trailing boundary markers
                        db_name = db_name.rstrip('-\r\n ')
                        logger.debug(f"Extracted db_name: '{db_name}'")

                # Look for file field
                elif 'name="database_file"' in part_str and 'filename=' in part_str:
                    logger.debug(f"Found file part")
                    
                    # Extract filename
                    filename_match = re.search(r'filename="([^"]*)"', part_str)
                    if filename_match:
                        filename = filename_match.group(1)
                        logger.debug(f"Extracted filename: '{filename}'")

                    # Find binary data start (after double CRLF)
                    binary_start = part.find(b'\r\n\r\n')
                    if binary_start != -1:
                        file_content = part[binary_start + 4:].rstrip(b'\r\n')
                        logger.debug(f"Extracted file content: {len(file_content)} bytes")

            # Validate extracted data
            if not db_name:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, "Database name is required"
                )

            # Server-side file size validation on actual file content
            if file_content and len(file_content) > max_file_size:
                size_mb = max_file_size // (1024 * 1024)
                actual_mb = len(file_content) // (1024 * 1024)
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"File too large ({actual_mb}MB). Maximum allowed: {size_mb}MB"
                )

            if not filename:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, "Please select a database file"
                )

            if not file_content or len(file_content) == 0:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, "Uploaded file appears to be empty"
                )

            logger.info(f"Successfully extracted: db_name='{db_name}', filename='{filename}', file_size={len(file_content)}")

            # Validate file extension
            allowed_extensions = ['.db', '.sqlite', '.sqlite3']
            ext = os.path.splitext(filename)[1].lower()
            if ext not in allowed_extensions:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Invalid file type '{ext}'. Allowed: {', '.join(allowed_extensions)}"
                )

            # Validate database name
            is_valid_name, name_error = validate_database_name(db_name)
            if not is_valid_name:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, name_error
                )

            # Check if name is available
            is_available = await check_database_name_available(datasette, db_name)
            if not is_available:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Database name '{db_name}' already exists. Please choose a different name."
                )

            user_id = actor.get("id")
            
            # Check database limit
            query_db = datasette.get_database('portal')
            result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
            db_count = result.first()[0]
            max_databases = await get_max_databases_per_user(datasette)
            if db_count >= max_databases:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Maximum {max_databases} databases per user reached"
                )

            # SIMPLE APPROACH: Copy file and register
            logger.info(f"Starting simple database import for: {db_name}")
            
            # Create user directory
            user_dir = os.path.join(DATA_DIR, user_id)
            os.makedirs(user_dir, exist_ok=True)
            
            # Create file path
            db_path = os.path.join(user_dir, f"{db_name}.db")
            
            # Write file directly
            with open(db_path, 'wb') as f:
                f.write(file_content)
            
            logger.info(f"File written to: {db_path}")
            
            # Validate SQLite file by trying to open it
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                conn.close()
                
                if not tables:
                    os.remove(db_path)  # Clean up
                    return await handle_form_errors(
                        datasette, "create_import_database.html",
                        {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                        request, "Database file contains no tables"
                    )
                
                table_count = len(tables)
                logger.info(f"Valid SQLite database with {table_count} tables")
                
            except Exception as sqlite_error:
                if os.path.exists(db_path):
                    os.remove(db_path)  # Clean up
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Invalid SQLite database: {str(sqlite_error)}"
                )

            # Register in database
            db_id = uuid.uuid4().hex[:20]
            website_url = generate_website_url(request, db_name)
            current_time = datetime.utcnow().isoformat()
            
            await query_db.execute_write(
                "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at, updated_at, file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [db_id, user_id, db_name, website_url, "Draft", current_time, current_time, db_path]
            )
            
            # Create auto homepage
            await create_simple_homepage(datasette, db_id, db_name, actor, current_time, table_count, "import")
            
            # Register with Datasette
            try:
                db_instance = Database(datasette, path=db_path, is_mutable=True)
                datasette.add_database(db_instance, name=db_name)
                logger.info(f"Successfully registered imported database: {db_name}")
            except Exception as reg_error:
                logger.error(f"Error registering imported database {db_name}: {reg_error}")

            # Log activity
            await log_database_action(
                datasette, user_id, "import_database", 
                f"Imported database {db_name} from file {filename} with {table_count} tables",
                {
                    "db_name": db_name,
                    "db_id": db_id,
                    "filename": filename,
                    "file_size": len(file_content),
                    "table_count": table_count
                }
            )
            
            success_message = f"Database '{db_name}' imported successfully from {filename}! Contains {table_count} tables. You can now customize your portal and publish when ready."
            return Response.redirect(f"/manage-databases?success={success_message}")

        except Exception as e:
            logger.error(f"Import database error: {str(e)}")
            import traceback
            logger.error(f"Error traceback: {traceback.format_exc()}")
            return await handle_form_errors(
                datasette, "create_import_database.html",
                {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                request, f"Error importing database: {str(e)}"
            )

    # GET request
    return Response.html(
        await datasette.render_template(
            "create_import_database.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "system_settings": system_settings,
            },
            request=request
        )
    )

async def create_simple_homepage(datasette, db_id, db_name, actor, current_time, table_count, creation_method):
    """Create simple homepage for database (empty or imported)."""
    try:
        query_db = datasette.get_database('portal')
        
        display_name = db_name.replace('_', ' ').replace('-', ' ').title()
        
        if creation_method == "import":
            description = f"Data portal for {display_name}. This imported database contains {table_count} data tables ready for exploration."
        else:
            description = f"Welcome to {display_name}. Start by uploading your data files to create interactive tables and visualizations."
        
        custom_content = [
            ("title", {"content": display_name}),
            ("description", {
                "content": description,
                "paragraphs": parse_markdown_links(description)
            }),
            ("header_image", {
                "image_url": "/static/default_header.jpg",
                "alt_text": f"{display_name} Portal",
                "credit_text": "",
                "credit_url": ""
            }),
            ("footer", {
                "content": f"{display_name} | Powered by Resette",
                "odbl_text": "Data licensed under ODbL",
                "odbl_url": "https://opendatacommons.org/licenses/odbl/",
                "paragraphs": parse_markdown_links(f"{display_name} | Powered by Resette")
            })
        ]
        
        for section, content_data in custom_content:
            await query_db.execute_write(
                "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                [db_id, section, json.dumps(content_data), current_time, actor['username']]
            )
        
        logger.debug(f"Created simple homepage for {creation_method} database: {db_name}")
        
    except Exception as e:
        logger.error(f"Error creating homepage for {db_name}: {e}")

async def ajax_import_database_handler(datasette, request):
    """AJAX Database Import Handler - Returns JSON response"""
    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required"}, status=401)

        # Verify user session
        is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
        if not is_valid:
            return Response.json({"success": False, "error": "Session invalid"}, status=401)

        # Parse multipart form data using the same parser as upload_table.py
        content_type = request.headers.get('content-type', '')
        body = await request.post_body()
        
        # Validate file size early
        max_file_size = await get_max_file_size(datasette)
        if len(body) > max_file_size + 1024:  # Add buffer for form overhead
            size_mb = max_file_size // (1024 * 1024)
            actual_mb = len(body) // (1024 * 1024)
            return Response.json({
                "success": False, 
                "error": f"Request too large ({actual_mb}MB). Maximum allowed: {size_mb}MB"
            }, status=400)

        # Extract boundary and parse form data
        import re
        boundary_match = re.search(r'boundary=([^;,\s]+)', content_type)
        if not boundary_match:
            return Response.json({"success": False, "error": "Invalid form data format"}, status=400)

        boundary = boundary_match.group(1).strip('"')
        boundary_bytes = f'--{boundary}'.encode()
        
        # Parse form parts
        parts = body.split(boundary_bytes)
        
        db_name = ""
        file_content = None
        filename = ""

        for part in parts:
            if len(part) < 20:
                continue

            part_str = part.decode('utf-8', errors='ignore')
            
            # Extract db_name field
            if 'name="db_name"' in part_str:
                content_start = part_str.find('\r\n\r\n')
                if content_start == -1:
                    content_start = part_str.find('\n\n')
                
                if content_start != -1:
                    content_part = part_str[content_start:].strip()
                    db_name = content_part.replace('\r\n\r\n', '').replace('\n\n', '').strip()
                    db_name = db_name.rstrip('-\r\n ')

            # Extract file field
            elif 'name="database_file"' in part_str and 'filename=' in part_str:
                filename_match = re.search(r'filename="([^"]*)"', part_str)
                if filename_match:
                    filename = filename_match.group(1)

                binary_start = part.find(b'\r\n\r\n')
                if binary_start != -1:
                    file_content = part[binary_start + 4:].rstrip(b'\r\n')

        # Validate extracted data
        if not db_name:
            return Response.json({"success": False, "error": "Database name is required"}, status=400)

        if not filename or not file_content:
            return Response.json({"success": False, "error": "Please select a database file"}, status=400)

        if len(file_content) > max_file_size:
            size_mb = max_file_size // (1024 * 1024)
            actual_mb = len(file_content) // (1024 * 1024)
            return Response.json({
                "success": False, 
                "error": f"File too large ({actual_mb}MB). Maximum allowed: {size_mb}MB"
            }, status=400)

        # Validate file extension
        allowed_extensions = ['.db', '.sqlite', '.sqlite3']
        ext = os.path.splitext(filename)[1].lower()
        if ext not in allowed_extensions:
            return Response.json({
                "success": False, 
                "error": f"Invalid file type '{ext}'. Allowed: {', '.join(allowed_extensions)}"
            }, status=400)

        # Validate database name
        is_valid_name, name_error = validate_database_name(db_name)
        if not is_valid_name:
            return Response.json({"success": False, "error": name_error}, status=400)

        # Check if name is available
        is_available = await check_database_name_available(datasette, db_name)
        if not is_available:
            return Response.json({
                "success": False, 
                "error": f"Database name '{db_name}' already exists. Please choose a different name."
            }, status=400)

        user_id = actor.get("id")
        
        # Check database limit
        query_db = datasette.get_database('portal')
        result = await query_db.execute(
            "SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", 
            [user_id]
        )
        db_count = result.first()[0]
        max_databases = await get_max_databases_per_user(datasette)
        if db_count >= max_databases:
            return Response.json({
                "success": False, 
                "error": f"Maximum {max_databases} databases per user reached"
            }, status=400)

        # Process database import
        logger.info(f"Starting AJAX database import for: {db_name}")
        
        # Create user directory
        user_dir = os.path.join(DATA_DIR, user_id)
        os.makedirs(user_dir, exist_ok=True)
        
        # Create file path
        db_path = os.path.join(user_dir, f"{db_name}.db")
        
        # Write file
        with open(db_path, 'wb') as f:
            f.write(file_content)
        
        # Validate SQLite file
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            conn.close()
            
            if not tables:
                os.remove(db_path)
                return Response.json({
                    "success": False, 
                    "error": "Database file contains no tables"
                }, status=400)
            
            table_count = len(tables)
            
        except Exception as sqlite_error:
            if os.path.exists(db_path):
                os.remove(db_path)
            return Response.json({
                "success": False, 
                "error": f"Invalid SQLite database: {str(sqlite_error)}"
            }, status=400)

        # Register in database
        db_id = uuid.uuid4().hex[:20]
        website_url = generate_website_url(request, db_name)
        current_time = datetime.utcnow().isoformat()
        
        await query_db.execute_write(
            "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at, updated_at, file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [db_id, user_id, db_name, website_url, "Draft", current_time, current_time, db_path]
        )
        
        # Create homepage
        await create_simple_homepage(datasette, db_id, db_name, actor, current_time, table_count, "import")
        
        # Register with Datasette
        try:
            from datasette.database import Database
            db_instance = Database(datasette, path=db_path, is_mutable=True)
            datasette.add_database(db_instance, name=db_name)
            logger.info(f"Successfully registered imported database: {db_name}")
        except Exception as reg_error:
            logger.error(f"Error registering imported database {db_name}: {reg_error}")

        # Log activity
        await log_database_action(
            datasette, user_id, "ajax_import_database", 
            f"Imported database {db_name} from file {filename} with {table_count} tables",
            {
                "db_name": db_name,
                "db_id": db_id,
                "filename": filename,
                "file_size": len(file_content),
                "table_count": table_count
            }
        )
        
        file_size_mb = len(file_content) / (1024 * 1024)
        success_message = f"SUCCESS: Database '{db_name}' imported successfully from {filename}! Contains {table_count} tables ({file_size_mb:.1f}MB processed)."
        
        return Response.json({
            "success": True,
            "message": success_message,
            "stats": f"{table_count} tables • {file_size_mb:.1f}MB • Import complete",
            "redirect_url": "/manage-databases"
        })

    except Exception as e:
        logger.error(f"AJAX database import error: {str(e)}")
        import traceback
        logger.error(f"Error traceback: {traceback.format_exc()}")
        
        # Clean up file if it was created
        if 'db_path' in locals() and os.path.exists(db_path):
            try:
                os.remove(db_path)
            except:
                pass
                
        return Response.json({"success": False, "error": f"Import failed: {str(e)}"}, status=500)

@hookimpl
def register_routes():
    """Register database creation routes."""
    return [
        (r"^/create-empty-database$", create_empty_database),
        (r"^/create-import-database$", create_import_database),
        (r"^/ajax-import-database$", ajax_import_database_handler),
    ]