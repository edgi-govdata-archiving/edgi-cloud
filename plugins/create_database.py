"""
Database Creation Module - Complete fixed version with robust error handling
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
import tempfile
import traceback  # MISSING IMPORT - needed for error tracing
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database
from email.parser import BytesParser
from email.policy import default

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

async def cleanup_failed_database_creation(datasette, query_db, db_id=None, db_path=None, db_name=None, user_id=None, operation_type="database creation"):
    """Comprehensive cleanup for failed database creation/import operations"""
    cleanup_results = []
    cleanup_errors = []
    
    logger.info(f"Starting cleanup for failed {operation_type}: db_id={db_id}, db_name={db_name}")
    
    # Remove database file
    if db_path and os.path.exists(db_path):
        try:
            os.remove(db_path)
            cleanup_results.append(f"Removed database file")
            logger.info(f"Cleanup: Removed database file {db_path}")
        except Exception as file_error:
            cleanup_errors.append(f"file removal: {str(file_error)}")
            logger.error(f"Cleanup: Failed to remove file {db_path}: {file_error}")
    
    # Remove from Datasette registry
    if db_name and datasette and db_name in datasette.databases:
        try:
            db_instance = datasette.databases[db_name]
            if hasattr(db_instance, '_internal_db') and db_instance._internal_db:
                try:
                    db_instance._internal_db.close()
                except Exception as close_error:
                    logger.warning(f"Cleanup: Error closing internal connection: {close_error}")
            del datasette.databases[db_name]
            cleanup_results.append(f"Unregistered from system")
            logger.info(f"Cleanup: Removed {db_name} from Datasette registry")
        except Exception as registry_error:
            cleanup_errors.append(f"system unregistration: {str(registry_error)}")
            logger.error(f"Cleanup: Failed to remove from Datasette: {registry_error}")
    
    # Remove from databases table
    if db_id and query_db:
        try:
            await query_db.execute_write("DELETE FROM databases WHERE db_id = ?", [db_id])
            cleanup_results.append("Removed database record")
            logger.info(f"Cleanup: Removed database record for {db_id}")
        except Exception as db_error:
            cleanup_errors.append(f"database record removal: {str(db_error)}")
            logger.error(f"Cleanup: Failed to remove database record: {db_error}")
    
    # Remove from admin_content table
    if db_id and query_db:
        try:
            await query_db.execute_write("DELETE FROM admin_content WHERE db_id = ?", [db_id])
            cleanup_results.append("Removed homepage customizations")
        except Exception as content_error:
            cleanup_errors.append(f"homepage content removal: {str(content_error)}")
    
    # Remove from database_tables table
    if db_id and query_db:
        try:
            await query_db.execute_write("DELETE FROM database_tables WHERE db_id = ?", [db_id])
            cleanup_results.append("Removed table configurations")
        except Exception as tables_error:
            cleanup_errors.append(f"table configurations removal: {str(tables_error)}")
    
    if cleanup_results:
        logger.info(f"Cleanup completed: {'; '.join(cleanup_results)}")
    if cleanup_errors:
        logger.error(f"Cleanup errors: {'; '.join(cleanup_errors)}")
    
    return len(cleanup_errors) == 0, cleanup_results, cleanup_errors

def parse_multipart_form(body, content_type):
    """Parse multipart form data using email parser with enhanced error handling"""
    try:
        logger.debug(f"Starting multipart parsing - Content-Type: {content_type}, Body size: {len(body)} bytes")
        
        # Create email headers with the content type
        headers = {'Content-Type': content_type}
        header_bytes = b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n'
        
        # Parse using email parser
        msg = BytesParser(policy=default).parsebytes(header_bytes + body)
        
        form_data = {}
        files = {}
        
        part_count = 0
        for part in msg.iter_parts():
            part_count += 1
            if not part.is_multipart():
                content_disposition = part.get('Content-Disposition', '')
                logger.debug(f"Part {part_count}: Content-Disposition: {content_disposition}")
                
                if content_disposition:
                    # Parse content disposition
                    disposition_params = {}
                    for param in content_disposition.split(';'):
                        param = param.strip()
                        if '=' in param:
                            key, value = param.split('=', 1)
                            disposition_params[key.strip()] = value.strip().strip('"')
                    
                    field_name = disposition_params.get('name')
                    filename = disposition_params.get('filename')
                    
                    logger.debug(f"Part {part_count}: field_name={field_name}, filename={filename}")
                    
                    if field_name:
                        if filename:
                            # This is a file field
                            file_content = part.get_payload(decode=True)
                            files[field_name] = {
                                'filename': filename,
                                'content': file_content
                            }
                            logger.debug(f"File field extracted: {field_name} -> {filename} ({len(file_content) if file_content else 0} bytes)")
                        else:
                            # This is a regular form field
                            field_value = part.get_payload(decode=True)
                            if field_value:
                                form_data[field_name] = field_value.decode('utf-8')
                                logger.debug(f"Form field extracted: {field_name} -> {form_data[field_name]}")
        
        logger.debug(f"Multipart parsing completed: {len(form_data)} form fields, {len(files)} files")
        return form_data, files
        
    except Exception as e:
        logger.error(f"Multipart parsing error: {e}")
        logger.error(f"Multipart parsing traceback: {traceback.format_exc()}")
        return {}, {}

async def create_empty_database(datasette, request):
    """Create empty database with proper error handling."""
    logger.debug(f"Create Empty Database request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    # Get content and system settings for template
    content = await get_portal_content(datasette)
    system_settings = await get_system_settings(datasette)

    if request.method == "POST":
        db_id = None
        db_path = None
        db_name = None
        user_id = actor.get("id")
        query_db = datasette.get_database('portal')
        
        try:
            # Use regular form handling (no multipart)
            formdata = await request.post_vars()
            db_name = formdata.get("db_name", "").strip()

            # Validate database name
            if not db_name:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, "Database name is required"
                )

            is_valid_name, name_error = validate_database_name(db_name)
            if not is_valid_name:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, name_error
                )

            # Check if name is available
            is_available = await check_database_name_available(datasette, db_name)
            if not is_available:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Database name '{db_name}' already exists. Please choose a different name."
                )

            # Check database limit
            result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
            db_count = result.first()[0]
            max_databases = await get_max_databases_per_user(datasette)
            if db_count >= max_databases:
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Maximum {max_databases} databases per user reached"
                )

            # Create empty database
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
                # Cleanup on registration failure
                await cleanup_failed_database_creation(datasette, query_db, db_id, db_path, db_name, user_id, "empty database creation")
                return await handle_form_errors(
                    datasette, "create_empty_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, f"Database created but failed to register: {str(reg_error)}"
                )

            # Log activity
            await log_database_action(
                datasette, user_id, "create_empty_database", 
                f"Created empty database {db_name}",
                {"db_name": db_name, "db_id": db_id, "website_url": website_url, "creation_method": "empty"}
            )
            
            return Response.redirect(f"/manage-databases?success=Empty database '{db_name}' created successfully!")

        except Exception as e:
            logger.error(f"Create empty database error: {str(e)}")
            logger.error(f"Create empty database traceback: {traceback.format_exc()}")
            if db_id or db_path or db_name:
                await cleanup_failed_database_creation(datasette, query_db, db_id, db_path, db_name, user_id, "empty database creation")
            return await handle_form_errors(
                datasette, "create_empty_database.html",
                {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                request, f"Error creating database: {str(e)}"
            )

    # GET request
    return Response.html(
        await datasette.render_template(
            "create_empty_database.html",
            {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
            request=request
        )
    )

async def create_import_database(datasette, request):
    """Database import with proper multipart parsing and early validation."""
    logger.debug(f"Create Import Database request: method={request.method}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Verify user session
    is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
    if not is_valid:
        return redirect_response

    # Get content and system settings for template
    content = await get_portal_content(datasette)
    system_settings = await get_system_settings(datasette)

    if request.method == "POST":
        db_id = None
        db_path = None
        db_name = None
        user_id = actor.get("id")
        query_db = datasette.get_database('portal')
        
        try:
            content_type = request.headers.get('content-type', '')
            body = await request.post_body()
            
            logger.debug(f"Form import: Content-Type={content_type}, Body size={len(body)}")
            
            # Check for multipart form
            if 'multipart/form-data' not in content_type:
                # Handle non-multipart (form without file)
                try:
                    post_vars = await request.post_vars()
                    db_name = post_vars.get("db_name", "").strip().lower()
                    
                    if db_name:
                        is_available = await check_database_name_available(datasette, db_name)
                        if is_available:
                            error_msg = f"Database name '{db_name}' is available! Please select your database file and click 'Import Database'."
                        else:
                            # Generate suggestions
                            suggestions = []
                            for i in range(1, 4):
                                suggested = f"{db_name}_{i}"
                                if await check_database_name_available(datasette, suggested):
                                    suggestions.append(suggested)
                            suggestion_text = f" Try: {', '.join(suggestions)}" if suggestions else ""
                            error_msg = f"Database name '{db_name}' already exists.{suggestion_text}"
                    else:
                        error_msg = "Please enter a database name and select a database file."
                except Exception:
                    error_msg = "Please select a database file to upload."
                
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, error_msg
                )
            
            # Parse multipart form using proper email parser
            form_data, files = parse_multipart_form(body, content_type)
            
            # Extract form fields
            db_name = form_data.get('db_name', '').strip().lower()
            file_info = files.get('database_file', {})
            filename = file_info.get('filename', '')
            file_content = file_info.get('content')
            
            logger.info(f"Form import parsed: db_name='{db_name}', filename='{filename}', file_size={len(file_content) if file_content else 0}")
            
            # Use the same processing logic as AJAX handler
            result = await process_database_import(
                datasette, form_data, files, user_id, actor, query_db, request, "form"
            )
            
            if result["success"]:
                file_size_mb = result.get("file_size_mb", 0)
                return Response.redirect(f"/manage-databases?success=Database '{result['db_name']}' imported successfully from {result['filename']}! Contains {result['table_count']} tables ({file_size_mb:.1f}MB).")
            else:
                return await handle_form_errors(
                    datasette, "create_import_database.html",
                    {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                    request, result["error"]
                )
            
        except Exception as e:
            logger.error(f"Form import error: {str(e)}")
            logger.error(f"Form import traceback: {traceback.format_exc()}")
            return await handle_form_errors(
                datasette, "create_import_database.html",
                {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
                request, f"Import failed: {str(e)}"
            )

    # GET request
    return Response.html(
        await datasette.render_template(
            "create_import_database.html",
            {"metadata": datasette.metadata(), "content": content, "actor": actor, "system_settings": system_settings},
            request=request
        )
    )

async def process_database_import(datasette, form_data, files, user_id, actor, query_db, request, handler_type="ajax"):
    """Shared processing logic for both form and AJAX handlers"""
    db_id = None
    db_path = None
    db_name = None
    
    try:
        logger.info(f"=== DATABASE IMPORT PROCESSING STARTED ({handler_type.upper()}) ===")
        
        # Step 1: Extract and validate form fields
        db_name = form_data.get('db_name', '').strip().lower()
        file_info = files.get('database_file', {})
        filename = file_info.get('filename', '')
        file_content = file_info.get('content')
        
        logger.info(f"Import processing: db_name='{db_name}', filename='{filename}', file_size={len(file_content) if file_content else 0}")

        # Step 2: Early validations
        if not db_name:
            logger.warning("Import processing: Missing database name")
            return {"success": False, "error": "Database name is required."}
        
        if not filename or not file_content:
            logger.warning(f"Import processing: Missing file data - filename='{filename}', file_content_exists={bool(file_content)}")
            return {"success": False, "error": "Please select a database file."}

        # Step 3: Validate database name format
        is_valid_name, name_error = validate_database_name(db_name)
        if not is_valid_name:
            logger.warning(f"Import processing: Invalid database name '{db_name}': {name_error}")
            return {"success": False, "error": f"Invalid database name: {name_error}"}

        # Step 4: Check name availability (should be validated by frontend, but double-check)
        is_available = await check_database_name_available(datasette, db_name)
        if not is_available:
            logger.warning(f"Import processing: Database name '{db_name}' already exists")
            return {"success": False, "error": f"Database name '{db_name}' already exists."}

        # Step 5: Check user limits
        result = await query_db.execute("SELECT COUNT(*) FROM databases WHERE user_id = ? AND status != 'Deleted'", [user_id])
        db_count = result.first()[0]
        max_databases = await get_max_databases_per_user(datasette)
        if db_count >= max_databases:
            logger.warning(f"Import processing: User {user_id} reached database limit ({db_count}/{max_databases})")
            return {"success": False, "error": f"Maximum {max_databases} databases per user reached."}

        # Step 6: Validate file extension
        allowed_extensions = ['.db', '.sqlite', '.sqlite3']
        ext = os.path.splitext(filename)[1].lower()
        if ext not in allowed_extensions:
            logger.warning(f"Import processing: Invalid file extension '{ext}' for file '{filename}'")
            return {"success": False, "error": f"Invalid file type '{ext}'. Use .db, .sqlite, or .sqlite3"}

        # Step 7: File size validation
        max_file_size = await get_max_file_size(datasette)
        if len(file_content) > max_file_size:
            size_mb = max_file_size // (1024 * 1024)
            actual_mb = len(file_content) // (1024 * 1024)
            logger.warning(f"Import processing: File too large {actual_mb}MB > {size_mb}MB limit")
            return {"success": False, "error": f"File too large ({actual_mb}MB). Maximum: {size_mb}MB"}

        # Step 8: Validate SQLite file integrity
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
                temp_file.write(file_content)
                temp_path = temp_file.name
            
            logger.debug(f"Import processing: Created temp file for validation: {temp_path}")
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            table_count = cursor.fetchone()[0]
            
            if table_count == 0:
                conn.close()
                logger.warning(f"Import processing: File '{filename}' contains no tables")
                return {"success": False, "error": f"File '{filename}' contains no tables."}
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            table_names = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            logger.info(f"Import processing: Valid SQLite file with {table_count} tables: {table_names}")
            
        except sqlite3.Error as e:
            logger.error(f"Import processing: Invalid SQLite file '{filename}': {e}")
            return {"success": False, "error": f"Invalid SQLite file: {str(e)}"}
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                    logger.debug(f"Import processing: Cleaned up temp file: {temp_path}")
                except:
                    pass

        # Step 9: Create user directory and database file
        logger.info(f"Import processing: Starting database creation for '{db_name}'")
        
        user_dir = os.path.join(DATA_DIR, user_id)
        os.makedirs(user_dir, exist_ok=True)
        logger.debug(f"Import processing: Created user directory: {user_dir}")
        
        db_path = os.path.join(user_dir, f"{db_name}.db")
        
        # Write file (NO modification of binary content!)
        with open(db_path, 'wb') as f:
            f.write(file_content)
        
        logger.info(f"Import processing: Database file written to: {db_path} ({len(file_content)} bytes)")

        # Step 10: Register in portal database
        db_id = uuid.uuid4().hex[:20]
        website_url = generate_website_url(request, db_name)
        current_time = datetime.utcnow().isoformat()
        
        await query_db.execute_write(
            "INSERT INTO databases (db_id, user_id, db_name, website_url, status, created_at, updated_at, file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [db_id, user_id, db_name, website_url, "Draft", current_time, current_time, db_path]
        )
        
        logger.info(f"Import processing: Database record created - db_id={db_id}, website_url={website_url}")

        # Step 11: Create homepage content
        await create_simple_homepage(datasette, db_id, db_name, actor, current_time, table_count, "import")
        logger.debug(f"Import processing: Homepage content created for db_id={db_id}")

        # Step 12: Register tables in database_tables
        try:
            for table_name in table_names:
                await query_db.execute_write(
                    "INSERT INTO database_tables (db_id, table_name, is_visible, created_at) VALUES (?, ?, ?, ?)",
                    [db_id, table_name, True, current_time]
                )
            logger.debug(f"Import processing: Registered {len(table_names)} tables in database_tables")
        except Exception as table_error:
            logger.error(f"Import processing: Error registering tables: {table_error}")
            # Continue anyway - not critical for basic functionality

        # Step 13: Register with Datasette
        try:
            db_instance = Database(datasette, path=db_path, is_mutable=True)
            datasette.add_database(db_instance, name=db_name)
            logger.info(f"Import processing: Successfully registered with Datasette: {db_name}")
        except Exception as reg_error:
            logger.error(f"Import processing: Failed to register with Datasette: {reg_error}")
            
            # CLEANUP ON REGISTRATION FAILURE
            await cleanup_failed_database_creation(
                datasette, query_db, db_id, db_path, db_name, user_id, f"{handler_type} database import"
            )
            
            return {
                "success": False, 
                "error": f"Database uploaded but failed to register with system: {str(reg_error)}"
            }

        # Step 14: Log successful import
        await log_database_action(
            datasette, user_id, f"{handler_type}_import_database", 
            f"Successfully imported database '{db_name}' from '{filename}' with {table_count} tables",
            {
                "db_name": db_name,
                "db_id": db_id,
                "filename": filename,
                "table_count": table_count,
                "file_size": len(file_content),
                "table_names": table_names,
                "handler_type": handler_type
            }
        )

        # Step 15: Return success response
        file_size_mb = len(file_content) / (1024 * 1024)
        success_message = f"Database '{db_name}' imported successfully from {filename}!"
        
        logger.info(f"Import processing: SUCCESS - {success_message} ({table_count} tables, {file_size_mb:.1f}MB)")
        
        return {
            "success": True,
            "message": success_message,
            "db_name": db_name,
            "db_id": db_id,
            "filename": filename,
            "table_count": table_count,
            "file_size_mb": file_size_mb,
            "table_names": table_names
        }

    except Exception as e:
        logger.error(f"Import processing: Unexpected error: {str(e)}")
        logger.error(f"Import processing: Error traceback: {traceback.format_exc()}")
        
        # CLEANUP ON UNEXPECTED ERROR
        if db_id or db_path or db_name:
            try:
                await cleanup_failed_database_creation(
                    datasette, query_db, db_id, db_path, db_name, user_id, f"{handler_type} database import"
                )
            except Exception as cleanup_error:
                logger.error(f"Import processing: Cleanup failed: {cleanup_error}")
        
        return {
            "success": False, 
            "error": f"Import failed due to unexpected error: {str(e)}. Please try again or contact support."
        }

async def ajax_import_database_handler(datasette, request):
    """AJAX handler using shared processing logic"""
    try:
        logger.info("=== AJAX IMPORT DATABASE HANDLER STARTED ===")
        
        # Step 1: Authentication and session verification
        actor = get_actor_from_request(request)
        if not actor:
            logger.warning("AJAX Import: No actor found")
            return Response.json({"success": False, "error": "Authentication required."}, status=401)

        is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
        if not is_valid:
            logger.warning(f"AJAX Import: Invalid session for user {actor}")
            return Response.json({"success": False, "error": "Session expired."}, status=401)

        user_id = actor.get("id")
        query_db = datasette.get_database('portal')
        logger.info(f"AJAX Import: Processing request for user_id={user_id}")

        # Step 2: Parse multipart form data
        content_type = request.headers.get('content-type', '')
        body = await request.post_body()
        
        logger.debug(f"AJAX Import: Content-Type={content_type}, Body size={len(body)} bytes")
        
        if 'multipart/form-data' not in content_type:
            logger.error("AJAX Import: Invalid content type - not multipart")
            return Response.json({"success": False, "error": "Invalid form data format"}, status=400)

        # Parse using the same method as form handler
        try:
            form_data, files = parse_multipart_form(body, content_type)
            logger.debug(f"AJAX Import: Parsed form_data keys: {list(form_data.keys())}")
            logger.debug(f"AJAX Import: Parsed files keys: {list(files.keys())}")
        except Exception as parse_error:
            logger.error(f"AJAX Import: Multipart parsing failed: {parse_error}")
            return Response.json({"success": False, "error": "Failed to parse form data"}, status=400)

        # Step 3: Use shared processing logic
        result = await process_database_import(
            datasette, form_data, files, user_id, actor, query_db, request, "ajax"
        )
        
        if result["success"]:
            return Response.json({
                "success": True,
                "message": result["message"],
                "stats": f"{result['table_count']} tables • {result['file_size_mb']:.1f}MB • Import complete",
                "redirect_url": "/manage-databases",
                "db_name": result["db_name"],
                "db_id": result["db_id"],
                "table_count": result["table_count"]
            })
        else:
            # Determine appropriate status code
            if "already exists" in result["error"]:
                status = 422
            elif "too large" in result["error"]:
                status = 413
            elif "Invalid" in result["error"] or "required" in result["error"]:
                status = 422
            else:
                status = 500
                
            return Response.json({"success": False, "error": result["error"]}, status=status)

    except Exception as e:
        logger.error(f"AJAX Import: Handler error: {str(e)}")
        logger.error(f"AJAX Import: Handler traceback: {traceback.format_exc()}")
        
        return Response.json({
            "success": False, 
            "error": f"Import failed: {str(e)}"
        }, status=500)

async def ajax_check_database_name(datasette, request):
    """Enhanced name availability check with better error handling"""
    try:
        logger.debug("AJAX Name Check: Starting validation")
        
        actor = get_actor_from_request(request)
        if not actor:
            logger.warning("AJAX Name Check: No actor found")
            return Response.json({"success": False, "error": "Authentication required"}, status=401)
        
        # Verify user session
        is_valid, user_data, redirect_response = await verify_user_session(datasette, actor)
        if not is_valid:
            logger.warning("AJAX Name Check: Invalid session")
            return Response.json({"success": False, "error": "Session expired"}, status=401)
        
        body = await request.post_body()
        try:
            data = json.loads(body.decode('utf-8'))
            db_name = data.get('db_name', '').strip().lower()
        except json.JSONDecodeError as e:
            logger.error(f"AJAX Name Check: JSON decode error: {e}")
            return Response.json({"success": False, "error": "Invalid request format"}, status=400)
        
        if not db_name:
            logger.warning("AJAX Name Check: Empty database name")
            return Response.json({"success": False, "error": "Database name is required"}, status=400)
        
        logger.debug(f"AJAX Name Check: Validating name '{db_name}'")
        
        # Validate format
        is_valid_name, name_error = validate_database_name(db_name)
        if not is_valid_name:
            logger.warning(f"AJAX Name Check: Invalid name format: {name_error}")
            return Response.json({"success": False, "error": f"Invalid name: {name_error}"}, status=400)
        
        # Check availability
        is_available = await check_database_name_available(datasette, db_name)
        if not is_available:
            logger.debug(f"AJAX Name Check: Name '{db_name}' is not available, generating suggestions")
            # Generate suggestions
            suggestions = []
            for i in range(1, 6):
                suggested = f"{db_name}_{i}"
                if await check_database_name_available(datasette, suggested):
                    suggestions.append(suggested)
                    if len(suggestions) >= 3:
                        break
            
            logger.debug(f"AJAX Name Check: Generated suggestions: {suggestions}")
            return Response.json({
                "success": False, 
                "error": f"Database name '{db_name}' already exists.",
                "suggestions": suggestions
            }, status=400)
        
        logger.debug(f"AJAX Name Check: Name '{db_name}' is available")
        return Response.json({"success": True, "message": f"Name '{db_name}' is available"})
        
    except Exception as e:
        logger.error(f"AJAX Name Check: Unexpected error: {e}")
        logger.error(f"AJAX Name Check: Error traceback: {traceback.format_exc()}")
        return Response.json({"success": False, "error": "Name validation failed"}, status=500)

async def create_simple_homepage(datasette, db_id, db_name, actor, current_time, table_count, creation_method):
    """Create simple homepage for database with enhanced error handling"""
    try:
        logger.debug(f"Creating homepage for db_id={db_id}, db_name={db_name}")
        
        query_db = datasette.get_database('portal')
        display_name = db_name.replace('_', ' ').replace('-', ' ').title()
        
        if creation_method == "import":
            description = f"Data portal for {display_name}. This imported database contains {table_count} data tables ready for exploration."
        else:
            description = f"Welcome to {display_name}. Start by uploading your data files to create interactive tables and visualizations."
        
        custom_content = [
            ("title", {"content": display_name}),
            ("description", {"content": description, "paragraphs": parse_markdown_links(description)}),
            ("header_image", {"image_url": "/static/default_header.jpg", "alt_text": f"{display_name} Portal", "credit_text": "", "credit_url": ""}),
            ("footer", {"content": f"{display_name} | Powered by Resette", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": parse_markdown_links(f"{display_name} | Powered by Resette")})
        ]
        
        for section, content_data in custom_content:
            await query_db.execute_write(
                "INSERT OR REPLACE INTO admin_content (db_id, section, content, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                [db_id, section, json.dumps(content_data), current_time, actor['username']]
            )
        
        logger.debug(f"Homepage created successfully for {db_name}")
        
    except Exception as e:
        logger.error(f"Error creating homepage for {db_name}: {e}")
        logger.error(f"Homepage creation traceback: {traceback.format_exc()}")
        # Don't raise - homepage creation failure shouldn't stop the import

@hookimpl
def register_routes():
    """Register database creation routes."""
    return [
        (r"^/create-empty-database$", create_empty_database),
        (r"^/create-import-database$", create_import_database),
        (r"^/ajax-import-database$", ajax_import_database_handler),
        (r"^/ajax-check-database-name$", ajax_check_database_name),
    ]