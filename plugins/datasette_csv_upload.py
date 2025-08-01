"""
CSV Upload Plugin - work with upload_csvs_simple.html in secure routing with CSRF protection
"""

import io
import csv
import os  # Added missing import
import re
import uuid
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from email.parser import BytesParser
from email.policy import default

logger = logging.getLogger(__name__)

# Configuration
MAX_CSV_SIZE = 10 * 1024 * 1024  # 10MB (matching your template)
MAX_TABLES_PER_DATABASE = 20
DATA_DIR = os.getenv('EDGI_DATA_DIR', "/data/data")  # Align with dynamic path from datasette_admin_panel.py

def generate_csrf_token(datasette, actor):
    """Generate CSRF token for forms using Datasette's built-in method."""
    if not actor:
        return ""
    
    return datasette._send_signed_token(
        {"a": actor.get("id", "")}, 
        max_age=3600
    )

async def verify_csrf_token(request, datasette):
    """Verify CSRF token for POST requests."""
    if request.method != "POST":
        return True
    
    # Get actor
    actor = request.actor
    if not actor:
        return False
    
    # Get CSRF token from form data or JSON
    submitted_token = ""
    content_type = request.headers.get('content-type', '').lower()
    
    if 'application/json' in content_type:
        try:
            import json
            body = await request.post_body()
            data = json.loads(body.decode('utf-8'))
            submitted_token = data.get('csrf_token', '')
        except:
            submitted_token = ""
    else:
        try:
            post_vars = await request.post_vars()
            submitted_token = post_vars.get("csrftoken", "")
        except:
            submitted_token = ""
    
    # Generate expected token using Datasette's method
    expected_token = datasette._send_signed_token(
        {"a": actor.get("id", "")}, 
        max_age=3600
    )
    
    return submitted_token == expected_token

@hookimpl
def register_routes():
    """Register secure routes with database name in path"""
    return [
        (r"^/upload-secure/([^/]+)$", secure_csv_upload),
    ]

async def secure_csv_upload(request, datasette):
    """Secure CSV upload with database ownership verification and CSRF protection"""
    
    # Extract database name from URL path (MORE SECURE than query parameter)
    path_parts = request.path.strip('/').split('/')
    if len(path_parts) != 2 or path_parts[0] != 'upload-secure':
        return Response.redirect("/manage-databases?error=Invalid upload URL")
    
    db_name = path_parts[1]
    logger.debug(f"Secure CSV upload requested for database: {db_name}")
    
    # Check authentication
    actor = request.actor
    if not actor:
        return Response.redirect("/login?error=Please log in to upload CSV files")
    
    # CRITICAL: Verify user owns this specific database
    if not await verify_database_ownership(datasette, actor["id"], db_name):
        return Response.redirect(
            f"/manage-databases?error=Access denied: You don't own database '{db_name}'"
        )
    
    if request.method == "POST":
        # CSRF protection for CSV upload
        if not await verify_csrf_token(request, datasette):
            logger.warning(f"CSRF token mismatch in CSV upload for {request.path}")
            return Response.redirect(f"/upload-secure/{db_name}?error=Security token invalid. Please try again.")
        
        return await handle_csv_upload_secure(request, datasette, db_name, actor)
    else:
        return await show_upload_form(request, datasette, db_name, actor)

async def verify_database_ownership(datasette, user_id, db_name):
    """Verify user owns the database"""
    try:
        portal_db = datasette.get_database("portal")
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, user_id]
        )
        return len(result.rows) > 0
    except Exception as e:
        logger.error(f"Ownership check error: {e}")
        return False

async def show_upload_form(request, datasette, db_name, actor):
    """Show the CSV upload form using your excellent template with CSRF token"""
    try:
        return Response.html(
            await datasette.render_template(
                "upload_csvs_simple.html",  # YOUR TEMPLATE
                {
                    "database_name": db_name,
                    "database_title": db_name.replace('_', ' ').title(),
                    "actor": actor,
                    "csrf_token": generate_csrf_token(datasette, actor),  # Add CSRF token
                    # Your template expects success/error in request.args
                    "request": request  # Pass request object so template can access request.args
                },
                request=request
            )
        )
    except Exception as e:
        logger.error(f"Error showing upload form: {e}")
        return Response.redirect(f"/manage-databases?error=Error loading upload form: {str(e)}")

async def handle_csv_upload_secure(request, datasette, db_name, actor):
    """Handle CSV upload - adapted to work with your template's form field names with CSRF protection"""
    try:
        content_type = request.headers.get('content-type', '')
        if 'multipart/form-data' not in content_type:
            return Response.redirect(f"/upload-secure/{db_name}?error=Invalid content type")
        
        # Extract boundary
        boundary = None
        for part in content_type.split(';'):
            part = part.strip()
            if part.startswith('boundary='):
                boundary = part.split('=', 1)[1].strip('"')
                break
        
        if not boundary:
            return Response.redirect(f"/upload-secure/{db_name}?error=No boundary found in request")
        
        # Get request body
        body = await request.post_body()
        if len(body) > MAX_CSV_SIZE:
            return Response.redirect(f"/upload-secure/{db_name}?error=File too large (max {MAX_CSV_SIZE // (1024*1024)}MB)")
        
        # Parse form data using reliable email parser approach
        forms, files = parse_multipart_form_data(body, boundary)
        
        # Verify CSRF token from parsed form data
        submitted_token = forms.get('csrftoken', '')
        expected_token = generate_csrf_token(datasette, actor)
        if submitted_token != expected_token:
            logger.warning(f"CSRF token mismatch in CSV upload: expected={expected_token}, got={submitted_token}")
            return Response.redirect(f"/upload-secure/{db_name}?error=Security token invalid. Please try again.")
        
        # Extract form fields - MATCHING YOUR TEMPLATE'S FIELD NAMES
        table_name = forms.get('table-name', '').strip()  # Your template uses 'table-name'
        csv_file = files.get('csv_file')  # Your template uses 'csv_file'
        replace_table = forms.get('replace_table') == '1'
        detect_types = forms.get('detect_types', '1') == '1'
        
        logger.debug(f"Form data: table_name='{table_name}', replace_table={replace_table}, detect_types={detect_types}")
        logger.debug(f"CSV file: {csv_file['filename'] if csv_file else 'None'}")
        
        # Validation
        if not csv_file:
            return Response.redirect(f"/upload-secure/{db_name}?error=No CSV file uploaded")
        
        if not csv_file['filename'].lower().endswith('.csv'):
            return Response.redirect(f"/upload-secure/{db_name}?error=File must be a CSV")
        
        # Get CSV content - handle BOM properly
        try:
            csv_content = csv_file['content'].decode('utf-8-sig')
        except UnicodeDecodeError:
            try:
                csv_content = csv_file['content'].decode('latin-1')
            except UnicodeDecodeError:
                return Response.redirect(f"/upload-secure/{db_name}?error=Unable to decode CSV file. Please save as UTF-8.")
        
        # Validate CSV content
        try:
            validate_csv_content(csv_content)
        except Exception as e:
            return Response.redirect(f"/upload-secure/{db_name}?error=Invalid CSV: {str(e)}")
        
        # Generate/clean table name
        if not table_name:
            table_name = clean_table_name(csv_file['filename'])
        else:
            table_name = clean_table_name(table_name)
        
        if not table_name:
            return Response.redirect(f"/upload-secure/{db_name}?error=Invalid table name")
        
        # Process CSV with advanced processing
        result = await process_csv_upload_advanced(
            datasette, db_name, table_name, csv_content, replace_table, detect_types
        )
        
        # Log activity
        await log_upload_activity(datasette, actor["id"], db_name, table_name, result)
        
        # Redirect back to manage-databases with success message (like your original)
        return Response.redirect(
            f"/manage-databases?success=Successfully uploaded {result['rows_inserted']} rows to table '{table_name}' in database '{db_name}'"
        )
        
    except Exception as e:
        logger.error(f"CSV upload error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return Response.redirect(f"/upload-secure/{db_name}?error=Upload failed: {str(e)}")

def parse_multipart_form_data(body, boundary):
    """Parse multipart form data using reliable email parser"""
    try:
        headers = f'Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n'
        msg = BytesParser(policy=default).parsebytes(headers.encode() + body)
        
        forms = {}
        files = {}
        
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
                        content = part.get_payload(decode=True)
                        if filename:
                            files[field_name] = {
                                'filename': filename,
                                'content': content
                            }
                        else:
                            forms[field_name] = content.decode('utf-8') if content else ''
        
        logger.debug(f"Parsed forms: {list(forms.keys())}")
        logger.debug(f"Parsed files: {list(files.keys())}")
        return forms, files
    except Exception as e:
        logger.error(f"Error parsing multipart data: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {}, {}

def validate_csv_content(csv_content):
    """Validate CSV content structure"""
    if not csv_content.strip():
        raise ValueError("CSV file is empty")
    
    csv_file = io.StringIO(csv_content)
    reader = csv.reader(csv_file)
    
    try:
        headers = next(reader)
        if not headers or all(not h.strip() for h in headers):
            raise ValueError("CSV must have valid column headers")
        
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
    
    name = os.path.splitext(name)[0]
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')
    
    if name and name[0].isdigit():
        name = f"table_{name}"
    
    if not name:
        name = "uploaded_table"
    elif len(name) > 50:
        name = name[:50]
    
    return name.lower()

def clean_column_name(name):
    """Clean column name to be valid SQLite identifier"""
    if not name:
        return "column"
        
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name.strip())
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')
    
    if name and name[0].isdigit():
        name = f"col_{name}"
    
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
        
        column_types[header] = "TEXT"
    
    return column_types

async def process_csv_upload_advanced(datasette, db_name, table_name, csv_content, replace_table, detect_types):
    """Process CSV upload with advanced features"""
    
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
        
        # Type detection
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
        elif table_exists and not replace_table:
            raise ValueError(f"Table '{table_name}' already exists. Enable 'Replace table' option to overwrite.")
        
        # Create table
        if not table_exists:
            column_defs = [f"[{h}] {column_types.get(h, 'TEXT')}" for h in headers]
            create_sql = f"CREATE TABLE [{table_name}] ({', '.join(column_defs)})"
            logger.debug(f"Creating table: {create_sql}")
            await target_db.execute_write(create_sql)
        
        # Batch processing
        rows_inserted = 0
        batch_size = 1000
        
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i + batch_size]
            
            prepared_batch = []
            for row in batch:
                padded_row = (row + [""] * len(headers))[:len(headers)]
                prepared_batch.append(padded_row)
            
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
    """Log upload activity"""
    try:
        portal_db = datasette.get_database("portal")
        await portal_db.execute_write(
            "INSERT INTO activity_logs (log_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            [
                uuid.uuid4().hex[:20],  # Shortened UUID for log_id
                user_id, 
                "csv_upload", 
                f"Uploaded {result['rows_inserted']} rows to {db_name}.{table_name}",
                datetime.utcnow().isoformat()
            ]
        )
    except Exception as e:
        logger.error(f"Failed to log upload activity: {e}")

@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Block the insecure official plugin"""
    if action == "upload-csvs":
        return False  # Always deny the official plugin for security
    return None