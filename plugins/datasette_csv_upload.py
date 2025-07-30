"""
Simplified Datasette CSV Upload Plugin
Uses Datasette's built-in request handling instead of custom multipart parsing
"""

import io
import csv
import os
import re
import uuid
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
import sqlite_utils

logger = logging.getLogger(__name__)

MAX_CSV_SIZE = 10 * 1024 * 1024  # 10MB limit for CSV files

@hookimpl
def register_routes():
    """Register routes with higher priority than default Datasette routes"""
    return [
        (r"^/csv-upload$", csv_upload_handler),
    ]

async def csv_upload_handler(request, datasette):
    """Handle CSV upload requests using Datasette's built-in form handling"""
    logger.debug(f"CSV upload handler called: {request.method} {request.path}")
    
    actor = request.actor
    
    if not actor:
        return Response.redirect("/login?error=Please log in to upload CSV files")
    
    # Get database from URL parameter
    database_name = request.args.get("database")
    if not database_name:
        return Response.redirect("/manage-databases?error=No database specified")
    
    logger.debug(f"Database requested: {database_name}")
    
    # Verify ownership
    if not await verify_database_ownership(datasette, actor["id"], database_name):
        return Response.redirect(
            f"/manage-databases?error=Access denied to database '{database_name}'"
        )
    
    if request.method == "POST":
        return await handle_csv_upload_simple(request, datasette, database_name, actor)
    else:
        return await show_upload_form(request, datasette, database_name, actor)

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

async def show_upload_form(request, datasette, database_name, actor):
    """Show the CSV upload form"""
    return Response.html(
        await datasette.render_template(
            "upload_csvs_simple.html",
            {
                "database_name": database_name,
                "database_title": database_name.replace('_', ' ').title(),
                "actor": actor,
                "success": request.args.get('success'),
                "error": request.args.get('error')
            },
            request=request
        )
    )

async def handle_csv_upload_simple(request, datasette, database_name, actor):
    """Handle CSV upload using a simpler approach that works with Datasette's form handling"""
    try:
        logger.debug(f"Handling CSV upload for {database_name}")
        
        # Get the raw body and extract CSV content manually
        body = await request.post_body()
        content_type = request.headers.get('content-type', '')
        
        logger.debug(f"Content type: {content_type}")
        logger.debug(f"Body length: {len(body)}")
        
        # Extract CSV content and form fields from the body
        csv_content, form_fields = extract_csv_from_body(body, content_type)
        
        if not csv_content:
            return Response.redirect(
                f"/csv-upload?database={database_name}&error=No CSV file content found"
            )
        
        # Get form fields
        table_name = form_fields.get("table-name", "").strip()
        replace_table = form_fields.get("replace_table") == "1"
        detect_types = form_fields.get("detect_types", "1") == "1"
        
        logger.debug(f"Form fields: table={table_name}, replace={replace_table}, detect={detect_types}")
        logger.debug(f"CSV content length: {len(csv_content)}")
        
        # Validate CSV content
        if len(csv_content.strip()) < 10:
            return Response.redirect(
                f"/csv-upload?database={database_name}&error=CSV file is too small or empty"
            )
        
        # Check file size
        if len(csv_content) > MAX_CSV_SIZE:
            return Response.redirect(
                f"/csv-upload?database={database_name}&error=CSV file too large (max 10MB)"
            )
        
        # Validate CSV format
        try:
            validate_csv_content(csv_content)
        except Exception as e:
            return Response.redirect(
                f"/csv-upload?database={database_name}&error=Invalid CSV format: {str(e)}"
            )
        
        # Generate table name if not provided
        if not table_name:
            table_name = "uploaded_data"
        
        # Clean table name
        table_name = clean_table_name(table_name)
        if not table_name:
            return Response.redirect(
                f"/csv-upload?database={database_name}&error=Invalid table name"
            )
        
        # Process the CSV
        result = await process_csv_upload(
            datasette, 
            database_name, 
            table_name, 
            csv_content, 
            replace_table, 
            detect_types
        )
        
        # Log the upload
        await log_upload_activity(datasette, actor["id"], database_name, table_name, result)
        
        return Response.redirect(
            f"/manage-databases?success=Successfully uploaded {result['rows_inserted']} rows to table '{table_name}' in database '{database_name}'"
        )
        
    except Exception as e:
        logger.error(f"CSV upload error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return Response.redirect(
            f"/csv-upload?database={database_name}&error=Upload failed: {str(e)}"
        )

def extract_csv_from_body(body, content_type):
    """Extract CSV content and form fields from multipart body using regex approach"""
    try:
        # Get boundary
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[-1].strip()
        
        if not boundary:
            logger.error("No boundary found")
            return None, {}
        
        # Convert to string
        body_str = body.decode('utf-8', errors='ignore')
        
        logger.debug(f"Looking for boundary: {boundary}")
        logger.debug(f"Body preview: {body_str[:500]}...")
        
        # Find CSV content by looking for the csv_file field with filename
        csv_content = None
        form_fields = {}
        
        # Use regex to find form fields
        import re
        
        # Pattern to match form fields
        field_pattern = r'Content-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]*)")?[^\r\n]*\r?\n(?:Content-Type: [^\r\n]*\r?\n)?\r?\n(.*?)(?=\r?\n--' + re.escape(boundary) + r')'
        
        matches = re.findall(field_pattern, body_str, re.DOTALL)
        
        logger.debug(f"Found {len(matches)} form fields")
        
        for match in matches:
            field_name, filename, content = match
            content = content.strip()
            
            logger.debug(f"Field: {field_name}, Filename: {filename}, Content length: {len(content)}")
            
            if filename:  # This is a file field
                # Remove BOM if present
                if content.startswith('\ufeff'):
                    content = content[1:]
                
                # Clean up the content - remove any trailing boundary markers
                csv_content = content.split(f'--{boundary}')[0].strip()
                logger.debug(f"Found CSV file content: {len(csv_content)} chars")
                logger.debug(f"CSV preview: {csv_content[:200]}...")
            else:  # This is a regular form field
                form_fields[field_name] = content
                logger.debug(f"Found form field {field_name}: {content}")
        
        # If regex approach didn't work, try a simpler string-based approach
        if not csv_content:
            logger.debug("Regex approach failed, trying simple string search")
            
            # Look for the csv_file field manually
            csv_file_start = body_str.find('name="csv_file"')
            if csv_file_start > -1:
                # Find the start of the content (after the headers)
                content_start = body_str.find('\r\n\r\n', csv_file_start)
                if content_start > -1:
                    content_start += 4  # Skip the \r\n\r\n
                    
                    # Find the end of the content (next boundary)
                    content_end = body_str.find(f'--{boundary}', content_start)
                    if content_end > -1:
                        csv_content = body_str[content_start:content_end].strip()
                        
                        # Remove BOM if present
                        if csv_content.startswith('\ufeff'):
                            csv_content = csv_content[1:]
                        
                        logger.debug(f"Found CSV content with simple search: {len(csv_content)} chars")
                        logger.debug(f"CSV preview: {csv_content[:200]}...")
            
            # Extract other form fields
            for field in ['table-name', 'replace_table', 'detect_types', 'database']:
                field_start = body_str.find(f'name="{field}"')
                if field_start > -1:
                    content_start = body_str.find('\r\n\r\n', field_start)
                    if content_start > -1:
                        content_start += 4
                        content_end = body_str.find(f'--{boundary}', content_start)
                        if content_end > -1:
                            field_content = body_str[content_start:content_end].strip()
                            form_fields[field] = field_content
                            logger.debug(f"Found form field {field}: {field_content}")
        
        return csv_content, form_fields
        
    except Exception as e:
        logger.error(f"Error extracting CSV from body: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return None, {}

def validate_csv_content(csv_content):
    """Validate CSV content structure"""
    if not csv_content.strip():
        raise ValueError("CSV file is empty")
    
    # Try to parse CSV to check format
    csv_file = io.StringIO(csv_content)
    reader = csv.reader(csv_file)
    
    try:
        headers = next(reader)
        if not headers or all(not h.strip() for h in headers):
            raise ValueError("CSV must have valid column headers")
        
        # Check for at least one data row
        try:
            next(reader)
        except StopIteration:
            raise ValueError("CSV must contain at least one data row")
            
    except csv.Error as e:
        raise ValueError(f"Invalid CSV format: {str(e)}")

def clean_table_name(name):
    """Clean table name to be valid SQLite identifier"""
    if not name:
        return "uploaded_table"
    
    # Remove file extension
    name = os.path.splitext(name)[0]
    
    # Replace invalid characters with underscores
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    
    # Remove consecutive underscores
    name = re.sub(r'_+', '_', name)
    
    # Remove leading/trailing underscores
    name = name.strip('_')
    
    # Ensure it doesn't start with a number
    if name and name[0].isdigit():
        name = f"table_{name}"
    
    # Ensure it's not empty and not too long
    if not name:
        name = "uploaded_table"
    elif len(name) > 50:
        name = name[:50]
    
    return name.lower()

def clean_column_name(name):
    """Clean column name to be valid SQLite identifier"""
    if not name:
        return "column"
        
    # Replace invalid characters with underscores
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name.strip())
    
    # Remove consecutive underscores
    name = re.sub(r'_+', '_', name)
    
    # Remove leading/trailing underscores
    name = name.strip('_')
    
    # Ensure it doesn't start with a number
    if name and name[0].isdigit():
        name = f"col_{name}"
    
    # Ensure it's not empty
    if not name:
        name = "column"
    
    return name.lower()

def detect_csv_column_types(rows, headers):
    """Detect column types from CSV data"""
    column_types = {}
    
    for i, header in enumerate(headers):
        sample_values = [row[i] if i < len(row) else "" for row in rows[:100]]
        sample_values = [v.strip() for v in sample_values if v.strip()]
        
        if not sample_values:
            column_types[header] = "TEXT"
            continue
        
        # Try INTEGER
        try:
            for val in sample_values:
                int(val)
            column_types[header] = "INTEGER"
            continue
        except ValueError:
            pass
        
        # Try REAL
        try:
            for val in sample_values:
                float(val)
            column_types[header] = "REAL"
            continue
        except ValueError:
            pass
        
        # Default to TEXT
        column_types[header] = "TEXT"
    
    return column_types

async def process_csv_upload(datasette, db_name, table_name, csv_content, replace_table, detect_types):
    """Process the CSV upload with enhanced error handling"""
    
    # Parse CSV
    csv_file = io.StringIO(csv_content)
    reader = csv.reader(csv_file)
    
    try:
        headers = next(reader)
        headers = [clean_column_name(h) for h in headers]
        
        # Handle duplicate headers
        seen = set()
        for i, header in enumerate(headers):
            if header in seen:
                headers[i] = f"{header}_{i}"
            seen.add(headers[i])
        
        rows = list(reader)
        
        if not rows:
            raise ValueError("CSV contains no data rows")
        
        logger.debug(f"Parsed CSV: {len(headers)} columns, {len(rows)} rows")
        
        # Get target database
        target_db = datasette.get_database(db_name)
        if not target_db:
            raise ValueError(f"Database '{db_name}' not found or not accessible")
        
        # Detect types
        if detect_types:
            column_types = detect_csv_column_types(rows, headers)
        else:
            column_types = {h: "TEXT" for h in headers}
        
        logger.debug(f"Column types: {column_types}")
        
        # Check if table exists
        existing_tables = await target_db.table_names()
        table_exists = table_name in existing_tables
        
        if table_exists and replace_table:
            logger.debug(f"Dropping existing table: {table_name}")
            await target_db.execute_write(f"DROP TABLE [{table_name}]")
            table_exists = False
        
        # Create table if needed
        if not table_exists:
            column_defs = [f"[{h}] {column_types.get(h, 'TEXT')}" for h in headers]
            create_sql = f"CREATE TABLE [{table_name}] ({', '.join(column_defs)})"
            logger.debug(f"Creating table: {create_sql}")
            await target_db.execute_write(create_sql)
        
        # Insert data in batches
        rows_inserted = 0
        batch_size = 1000
        
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i + batch_size]
            
            # Prepare batch
            prepared_batch = []
            for row in batch:
                # Pad or truncate row to match headers
                padded_row = (row + [""] * len(headers))[:len(headers)]
                prepared_batch.append(padded_row)
            
            # Insert batch
            placeholders = ", ".join(["?" for _ in headers])
            columns = ", ".join([f"[{h}]" for h in headers])
            insert_sql = f"INSERT INTO [{table_name}] ({columns}) VALUES ({placeholders})"
            
            await target_db.execute_write_many(insert_sql, prepared_batch)
            rows_inserted += len(prepared_batch)
            
            logger.debug(f"Inserted batch {i//batch_size + 1}: {len(prepared_batch)} rows")
        
        result = {
            'table_name': table_name,
            'rows_inserted': rows_inserted,
            'columns': len(headers),
            'column_names': headers,
            'replaced': replace_table and table_exists
        }
        
        logger.info(f"CSV upload completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")
        raise ValueError(f"Failed to process CSV: {str(e)}")

async def log_upload_activity(datasette, user_id, db_name, table_name, result):
    """Log upload activity to portal.db"""
    try:
        portal_db = datasette.get_database("portal")
        
        await portal_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [
                str(uuid.uuid4()), 
                user_id, 
                "csv_upload", 
                f"Uploaded {result['rows_inserted']} rows to {db_name}.{table_name}",
                datetime.utcnow().isoformat()
            ]
        )
        
        logger.debug(f"Logged upload activity for user {user_id}")
        
    except Exception as e:
        logger.error(f"Failed to log upload activity: {e}")

@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Grant CSV upload permissions"""
    if action == "upload-csvs":
        # Allow CSV uploads for authenticated users
        return actor is not None
    
    # Let other plugins handle other permissions
    return None