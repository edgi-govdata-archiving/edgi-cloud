"""
Enhanced Upload Module - Multi-source data upload with Google Sheets integration and Excel support
Handles: File uploads (CSV, Excel), Google Sheets, Web CSV, custom table names
FIXES: Data type conversion, domain allowlist, better error handling
"""

import json
import logging
import uuid
import os
import re
import csv
import io
import requests
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from email.parser import BytesParser
from email.policy import default

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
    get_portal_content,
    get_max_file_size,
    user_owns_database,
    get_success_error_from_request,
    update_database_timestamp,
    DATA_DIR,
    is_domain_blocked,
)

logger = logging.getLogger(__name__)

class GoogleSheetsHandler:
    """Handle Google Sheets data import."""
    
    @staticmethod
    def extract_sheet_id(url):
        """Extract sheet ID from Google Sheets URL."""
        patterns = [
            r'docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]+)',
            r'drive\.google\.com/file/d/([a-zA-Z0-9-_]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None
    
    @staticmethod
    def get_csv_export_url(sheet_id, gid=0):
        """Generate CSV export URL for Google Sheets."""
        return f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}"
    
    @staticmethod
    def fetch_sheet_data(sheet_url, sheet_index=0):
        """Fetch data from Google Sheets as CSV with better error handling."""
        try:
            sheet_id = GoogleSheetsHandler.extract_sheet_id(sheet_url)
            if not sheet_id:
                raise ValueError("Invalid Google Sheets URL. Please ensure the URL is in the format: https://docs.google.com/spreadsheets/d/SHEET_ID/")
            
            # Try to extract gid from URL if present
            gid = 0
            if '#gid=' in sheet_url:
                try:
                    gid = int(sheet_url.split('#gid=')[1].split('&')[0])
                except (ValueError, IndexError):
                    gid = sheet_index
            else:
                gid = sheet_index
            
            csv_url = GoogleSheetsHandler.get_csv_export_url(sheet_id, gid)
            
            # Fetch CSV data with better headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(csv_url, timeout=30, headers=headers)
            
            # Check for specific error conditions
            if response.status_code == 401:
                raise ValueError("The Google Sheet is private. Please make it public or share it with 'Anyone with the link can view' permissions.")
            elif response.status_code == 404:
                raise ValueError("Google Sheet not found. Please check the URL and ensure the sheet exists.")
            elif response.status_code != 200:
                raise ValueError(f"Failed to access Google Sheet (HTTP {response.status_code}). Please check the URL and sharing permissions.")
            
            # Check if we got actual CSV data
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' in content_type:
                raise ValueError("Received HTML instead of CSV data. The sheet may be private or the URL may be incorrect.")
            
            # Validate CSV content
            csv_content = response.text.strip()
            if not csv_content:
                raise ValueError("The Google Sheet appears to be empty.")
            
            # Basic CSV validation
            try:
                # Try to parse first few lines to validate CSV format
                sample_lines = csv_content.split('\n')[:5]
                csv.reader(sample_lines)
            except csv.Error:
                raise ValueError("The downloaded content doesn't appear to be valid CSV data.")
            
            return csv_content
            
        except requests.RequestException as e:
            if "Unauthorized" in str(e):
                raise ValueError("The Google Sheet is private. Please make it public or share it with 'Anyone with the link can view' permissions.")
            else:
                raise ValueError(f"Network error while fetching Google Sheets data: {str(e)}")

class WebCSVHandler:
    """Handle web-based CSV import with dynamic domain blocking."""
    
    @staticmethod
    async def validate_url(datasette, url):
        """Validate CSV URL using dynamic blocked domains list."""
        try:
            parsed = urlparse(url)
            
            # Allow localhost for development
            if parsed.netloc.startswith('localhost') or parsed.netloc.startswith('127.0.0.1'):
                return True
            
            # Check if domain is blocked
            domain = parsed.netloc.lower()
            if await is_domain_blocked(datasette, domain):
                raise ValueError(f"Domain '{domain}' is blocked by system administrator")
            
            # Check for parent domain blocking (e.g., if evil.com is blocked, block sub.evil.com)
            domain_parts = domain.split('.')
            for i in range(len(domain_parts)):
                parent_domain = '.'.join(domain_parts[i:])
                if await is_domain_blocked(datasette, parent_domain):
                    raise ValueError(f"Domain '{domain}' is blocked (parent domain '{parent_domain}' is blocked)")
            
            # Check file extension
            path_lower = parsed.path.lower()
            if not any(path_lower.endswith(ext) for ext in ['.csv', '.txt', '.tsv']):
                raise ValueError("URL must point to a CSV, TXT, or TSV file")
            
            return True
            
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
    
    @staticmethod
    async def fetch_csv_from_url(datasette, url, encoding='auto'):
        """Fetch CSV data from web URL with dynamic validation."""
        try:
            await WebCSVHandler.validate_url(datasette, url)
            
            headers = {
                'User-Agent': 'EDGI-Portal/1.0 (Environmental Data Portal)',
                'Accept': 'text/csv, text/plain, application/csv, */*'
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Auto-detect encoding if requested
            if encoding == 'auto':
                try:
                    import chardet
                    detected = chardet.detect(response.content)
                    encoding = detected.get('encoding', 'utf-8')
                except ImportError:
                    encoding = 'utf-8'
            
            # Decode content
            if encoding != 'utf-8':
                content = response.content.decode(encoding)
            else:
                content = response.text
            
            return content
            
        except requests.RequestException as e:
            raise ValueError(f"Failed to fetch CSV from URL: {str(e)}")

class ExcelHandler:
    """Handle Excel file processing with better data type handling."""
    
    @staticmethod
    def process_excel_file(file_content, sheet_name=None, first_row_headers=True):
        """Process Excel file and return DataFrame with proper data type conversion."""
        try:
            # Read Excel file using pandas
            if sheet_name:
                df = pd.read_excel(io.BytesIO(file_content), sheet_name=sheet_name, 
                                 header=0 if first_row_headers else None)
            else:
                df = pd.read_excel(io.BytesIO(file_content), 
                                 header=0 if first_row_headers else None)
            
            # If no headers, generate column names
            if not first_row_headers:
                df.columns = [f'column_{i+1}' for i in range(len(df.columns))]
            
            # CRITICAL FIX: Convert all data types to SQLite-compatible types
            df = ExcelHandler.convert_data_types(df)
            
            return df, None
            
        except Exception as e:
            return None, f"Error processing Excel file: {str(e)}"
    
    @staticmethod
    def convert_data_types(df):
        """Convert pandas data types to SQLite-compatible types."""
        for col in df.columns:
            # Convert datetime/timestamp columns to strings
            if df[col].dtype == 'datetime64[ns]' or 'datetime' in str(df[col].dtype).lower():
                df[col] = df[col].astype(str)
                logger.debug(f"Converted datetime column '{col}' to string")
            
            # Convert Timestamp objects to strings
            elif df[col].dtype == 'object':
                # Check if column contains Timestamp objects
                sample = df[col].dropna().head(5)
                if not sample.empty and any(isinstance(x, pd.Timestamp) for x in sample):
                    df[col] = df[col].astype(str)
                    logger.debug(f"Converted Timestamp column '{col}' to string")
            
            # Convert complex numbers to strings
            elif 'complex' in str(df[col].dtype):
                df[col] = df[col].astype(str)
                logger.debug(f"Converted complex column '{col}' to string")
            
            # Replace inf and -inf with None
            if df[col].dtype in ['float64', 'float32']:
                df[col] = df[col].replace([np.inf, -np.inf], None)
        
        return df
    
    @staticmethod
    def get_sheet_names(file_content):
        """Get list of sheet names from Excel file."""
        try:
            xl_file = pd.ExcelFile(io.BytesIO(file_content))
            return xl_file.sheet_names
        except Exception as e:
            logger.error(f"Error getting sheet names: {e}")
            return []

class TableNameManager:
    """Handle table name validation and generation."""
    
    SQL_KEYWORDS = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER',
        'TABLE', 'INDEX', 'VIEW', 'DATABASE', 'SCHEMA', 'TRIGGER', 'FUNCTION',
        'PROCEDURE', 'FROM', 'WHERE', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER',
        'GROUP', 'ORDER', 'BY', 'HAVING', 'LIMIT', 'OFFSET', 'UNION', 'ALL',
        'DISTINCT', 'AS', 'ON', 'AND', 'OR', 'NOT', 'NULL', 'TRUE', 'FALSE'
    }
    
    @staticmethod
    def validate_table_name(name):
        """Validate table name according to SQLite rules."""
        if not name:
            return False, "Table name cannot be empty"
        
        # Check length
        if len(name) > 64:
            return False, "Table name too long (max 64 characters)"
        
        # Check format (must start with letter or underscore)
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            return False, "Table name must start with letter/underscore and contain only letters, numbers, and underscores"
        
        # Check for SQL keywords
        if name.upper() in TableNameManager.SQL_KEYWORDS:
            return False, f"'{name}' is a reserved SQL keyword"
        
        return True, None
    
    @staticmethod
    def sanitize_table_name(raw_name):
        """Generate a valid table name from raw input."""
        # Remove file extension
        name = re.sub(r'\.[^.]*$', '', raw_name)
        
        # Replace invalid characters with underscores
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        
        # Ensure it starts with letter or underscore
        if name and not re.match(r'^[a-zA-Z_]', name):
            name = 'table_' + name
        
        # Truncate if too long
        if len(name) > 64:
            name = name[:60] + '_tbl'
        
        # Fallback for empty names
        if not name:
            name = f'table_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        
        return name
    
    @staticmethod
    async def suggest_unique_name(base_name, datasette, db_name):
        """Generate unique table name by checking existing tables."""
        try:
            target_db = datasette.get_database(db_name)
            existing_tables = await target_db.table_names()
            
            # If base name is available, use it
            if base_name not in existing_tables:
                return base_name
            
            # Generate numbered alternatives
            counter = 1
            while f"{base_name}_{counter}" in existing_tables:
                counter += 1
            
            return f"{base_name}_{counter}"
            
        except Exception as e:
            logger.error(f"Error checking existing tables: {e}")
            return f"{base_name}_{uuid.uuid4().hex[:8]}"

class DataProcessor:
    """Process and clean uploaded data with better type handling."""
    
    @staticmethod
    def process_csv_content(content, table_name, first_row_headers=True):
        """Process CSV content and return cleaned DataFrame."""
        try:
            # Parse CSV
            if first_row_headers:
                df = pd.read_csv(io.StringIO(content))
            else:
                df = pd.read_csv(io.StringIO(content), header=None)
                # Generate column names
                df.columns = [f'column_{i+1}' for i in range(len(df.columns))]
            
            # Clean column names
            df.columns = DataProcessor.clean_column_names(df.columns)
            
            # Basic data cleaning and type conversion
            df = DataProcessor.clean_dataframe(df)
            
            return df, None
            
        except Exception as e:
            return None, f"Error processing CSV: {str(e)}"
    
    @staticmethod
    def clean_column_names(columns):
        """Clean column names for SQLite compatibility."""
        cleaned = []
        for col in columns:
            # Convert to string and strip whitespace
            clean_col = str(col).strip()
            
            # Replace invalid characters
            clean_col = re.sub(r'[^a-zA-Z0-9_]', '_', clean_col)
            
            # Ensure it starts with letter or underscore
            if clean_col and not re.match(r'^[a-zA-Z_]', clean_col):
                clean_col = 'col_' + clean_col
            
            # Handle empty or invalid names
            if not clean_col:
                clean_col = f'column_{len(cleaned) + 1}'
            
            cleaned.append(clean_col)
        
        # Handle duplicates
        seen = set()
        final_columns = []
        for col in cleaned:
            original_col = col
            counter = 1
            while col in seen:
                col = f"{original_col}_{counter}"
                counter += 1
            seen.add(col)
            final_columns.append(col)
        
        return final_columns
    
    @staticmethod
    def clean_dataframe(df):
        """Basic DataFrame cleaning with SQLite compatibility."""
        # Remove completely empty rows
        df = df.dropna(how='all')
        
        # Remove completely empty columns
        df = df.dropna(axis=1, how='all')
        
        # Convert data types for SQLite compatibility
        for col in df.columns:
            # Handle datetime columns
            if df[col].dtype == 'datetime64[ns]':
                df[col] = df[col].astype(str)
            
            # Fill NaN values appropriately
            if df[col].dtype == 'object':
                df[col] = df[col].fillna('')
            elif df[col].dtype in ['float64', 'float32']:
                # Replace inf with None and keep NaN as None for numeric columns
                df[col] = df[col].replace([np.inf, -np.inf], None)
            elif df[col].dtype in ['int64', 'int32']:
                # For integer columns, fill NaN with 0 or convert to nullable int
                df[col] = df[col].fillna(0)
        
        return df

    @staticmethod
    def prepare_for_sqlite(df):
        """Final preparation of DataFrame for SQLite insertion."""
        records = []
        for _, row in df.iterrows():
            record = []
            for col in df.columns:
                value = row[col]
                
                # Handle different data types
                if pd.isna(value) or value is None:
                    record.append(None)
                elif isinstance(value, (pd.Timestamp, datetime)):
                    record.append(str(value))
                elif isinstance(value, (np.int64, np.int32)):
                    record.append(int(value))
                elif isinstance(value, (np.float64, np.float32)):
                    if np.isnan(value) or np.isinf(value):
                        record.append(None)
                    else:
                        record.append(float(value))
                else:
                    record.append(str(value))
            
            records.append(tuple(record))
        
        return records

def parse_multipart_form_data(body, boundary):
    """Parse multipart form data using reliable email parser."""
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

async def enhanced_upload_page(datasette, request):
    """Enhanced upload page with multi-source support."""
    logger.debug(f"Enhanced Upload request: method={request.method}, path={request.path}")

    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired or invalid")

    # Extract database name from path
    path_parts = request.path.strip('/').split('/')
    if len(path_parts) < 2:
        return Response.text("Invalid URL format", status=400)
    
    db_name = path_parts[1]
    logger.debug(f"Database name extracted: {db_name}")
    
    # Verify user owns the database
    if not await user_owns_database(datasette, actor["id"], db_name):
        return Response.text("Access denied", status=403)

    # CRITICAL FIX: Ensure database is registered before upload attempts
    try:
        target_db = datasette.get_database(db_name)
        if not target_db:
            # Database not registered, try to register it
            await ensure_database_registered(datasette, db_name, actor["id"])
    except KeyError:
        # Database not registered, try to register it
        await ensure_database_registered(datasette, db_name, actor["id"])

    if request.method == "POST":
        return await handle_enhanced_upload(datasette, request, db_name, actor)
    
    # GET request - show upload form
    content = await get_portal_content(datasette)
    
    return Response.html(
        await datasette.render_template(
            "upload_table.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "db_name": db_name,
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def ensure_database_registered(datasette, db_name, user_id):
    """Ensure database is registered with Datasette."""
    try:
        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, user_id]
        )
        db_info = result.first()
        
        if not db_info:
            raise ValueError(f"Database {db_name} not found in portal database")
        
        file_path = db_info['file_path']
        if not file_path:
            file_path = os.path.join(DATA_DIR, user_id, f"{db_name}.db")
        
        if not os.path.exists(file_path):
            raise ValueError(f"Database file not found: {file_path}")
        
        # Register database with Datasette
        db_instance = Database(datasette, path=file_path, is_mutable=True)
        datasette.add_database(db_instance, name=db_name)
        logger.info(f"Successfully registered database: {db_name}")
        
    except Exception as e:
        logger.error(f"Error registering database {db_name}: {e}")
        raise

async def handle_enhanced_upload(datasette, request, db_name, actor):
    """Handle enhanced upload form submission."""
    try:
        content_type = request.headers.get('content-type', '').lower()
        logger.debug(f"Content type: {content_type}")
        
        if 'multipart/form-data' in content_type:
            # Handle file upload
            return await handle_file_upload(datasette, request, db_name, actor)
        else:
            # Handle form data (Google Sheets, URL)
            post_vars = await request.post_vars()
            source_type = post_vars.get('source_type')
            logger.debug(f"Source type: {source_type}")
            
            if source_type == 'sheets':
                return await handle_sheets_upload(datasette, request, post_vars, db_name, actor)
            elif source_type == 'url':
                return await handle_url_upload(datasette, request, post_vars, db_name, actor)
            else:
                return Response.redirect(f"/upload-table/{db_name}?error=Invalid source type")
    
    except Exception as e:
        logger.error(f"Enhanced upload error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return Response.redirect(f"/upload-table/{db_name}?error=Upload failed: {str(e)}")

async def handle_file_upload(datasette, request, db_name, actor):
    """Handle traditional file upload with enhanced data type handling."""
    try:
        logger.debug("Starting file upload processing")
        
        # Parse multipart form data
        body = await request.post_body()
        logger.debug(f"Request body size: {len(body)} bytes")
        
        max_file_size = await get_max_file_size(datasette)
        if len(body) > max_file_size:
            return Response.redirect(f"/upload-table/{db_name}?error=File too large (max {max_file_size // (1024*1024)}MB)")
        
        # Parse form data using email parser
        content_type = request.headers.get('content-type', '')
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
        
        if not boundary:
            logger.error("No boundary found in content type")
            return Response.redirect(f"/upload-table/{db_name}?error=Invalid form data - no boundary")
        
        logger.debug(f"Using boundary: {boundary}")
        
        # Parse multipart data
        forms, files = parse_multipart_form_data(body, boundary)
        
        # Process file upload
        if 'file' not in files:
            logger.error("No file found in upload")
            return Response.redirect(f"/upload-table/{db_name}?error=No file uploaded")
        
        file_info = files['file']
        filename = file_info['filename']
        file_content = file_info['content']
        
        logger.debug(f"Processing file: {filename}, size: {len(file_content)} bytes")
        
        # Get form options
        custom_table_name = forms.get('table_name', '').strip()
        replace_existing = 'replace_existing' in forms
        excel_sheet = forms.get('excel_sheet', '').strip()
        
        # Determine file type and process accordingly
        file_ext = os.path.splitext(filename)[1].lower()
        
        if file_ext in ['.xlsx', '.xls']:
            # Process Excel file with enhanced data type handling
            sheet_name = excel_sheet if excel_sheet else None
            df, error = ExcelHandler.process_excel_file(file_content, sheet_name)
            if error:
                return Response.redirect(f"/upload-table/{db_name}?error={error}")
                
        elif file_ext in ['.csv', '.txt', '.tsv']:
            # Process CSV file
            try:
                # Try UTF-8 first, then fall back to other encodings
                try:
                    csv_content = file_content.decode('utf-8-sig')
                except UnicodeDecodeError:
                    try:
                        csv_content = file_content.decode('utf-8')
                    except UnicodeDecodeError:
                        csv_content = file_content.decode('latin-1')
                
                df, error = DataProcessor.process_csv_content(csv_content, custom_table_name or filename)
                if error:
                    return Response.redirect(f"/upload-table/{db_name}?error={error}")
            except Exception as e:
                logger.error(f"Error processing CSV: {e}")
                return Response.redirect(f"/upload-table/{db_name}?error=Error processing CSV: {str(e)}")
        else:
            return Response.redirect(f"/upload-table/{db_name}?error=Unsupported file type. Supported: CSV, TSV, TXT, Excel (.xlsx, .xls)")
        
        logger.debug(f"Processed DataFrame: {len(df)} rows, {len(df.columns)} columns")
        
        # Generate table name
        if custom_table_name:
            table_name = custom_table_name
        else:
            base_name = TableNameManager.sanitize_table_name(filename)
            table_name = await TableNameManager.suggest_unique_name(base_name, datasette, db_name)
        
        # Validate table name
        is_valid, error_msg = TableNameManager.validate_table_name(table_name)
        if not is_valid:
            return Response.redirect(f"/upload-table/{db_name}?error=Invalid table name: {error_msg}")
        
        logger.debug(f"Using table name: {table_name}")
        
        # Insert data into database
        target_db = datasette.get_database(db_name)
        
        # Check if table exists and handle accordingly
        existing_tables = await target_db.table_names()
        if table_name in existing_tables:
            if replace_existing:
                await target_db.execute_write(f"DROP TABLE [{table_name}]")
                logger.debug(f"Dropped existing table: {table_name}")
            else:
                return Response.redirect(f"/upload-table/{db_name}?error=Table '{table_name}' already exists. Enable 'Replace existing table' to overwrite.")
        
        # Data preparation
        records = DataProcessor.prepare_for_sqlite(df)
        logger.debug(f"Prepared {len(records)} records for insertion")
        
        # Create table with proper column definitions
        column_defs = []
        for col in df.columns:
            # Simple type detection with SQLite compatibility
            sample_values = df[col].dropna().head(10)
            if sample_values.empty:
                col_type = "TEXT"
            elif all(isinstance(v, (int, np.integer)) for v in sample_values):
                col_type = "INTEGER"
            elif all(isinstance(v, (int, float, np.integer, np.floating)) and not isinstance(v, bool) for v in sample_values):
                col_type = "REAL" if any(isinstance(v, (float, np.floating)) for v in sample_values) else "INTEGER"
            else:
                col_type = "TEXT"
            column_defs.append(f"[{col}] {col_type}")
        
        create_sql = f"CREATE TABLE [{table_name}] ({', '.join(column_defs)})"
        logger.debug(f"Creating table with SQL: {create_sql}")
        await target_db.execute_write(create_sql)
        
        # Insert data in batches
        batch_size = 1000
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            
            placeholders = ", ".join(["?" for _ in df.columns])
            columns = ", ".join([f"[{col}]" for col in df.columns])
            insert_sql = f"INSERT INTO [{table_name}] ({columns}) VALUES ({placeholders})"
            
            await target_db.execute_write_many(insert_sql, batch)
            logger.debug(f"Inserted batch {i//batch_size + 1}: {len(batch)} rows")
        
        # Update database timestamp
        await update_database_timestamp(datasette, db_name)
        
        # Log activity
        await log_database_action(
            datasette, actor.get("id"), "enhanced_upload", 
            f"Uploaded {len(records)} rows to table '{table_name}' from file '{filename}'",
            {
                "source_type": "file",
                "table_name": table_name,
                "filename": filename,
                "file_type": file_ext,
                "record_count": len(records),
                "column_count": len(df.columns)
            }
        )
        
        logger.info(f"Successfully uploaded {len(records)} rows to table '{table_name}'")
        # return Response.redirect(f"/upload-table/{db_name}?success=Successfully uploaded {len(records)} rows to table '{table_name}'")
        return redirect_after_upload(request, db_name, f"Successfully uploaded {len(records)} rows to table '{table_name}'")

        
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        # return Response.redirect(f"/upload-table/{db_name}?error=File upload failed: {str(e)}")
        return redirect_after_upload(request, db_name, f"Upload failed: {str(e)}", is_error=True)

async def handle_sheets_upload(datasette, request, post_vars, db_name, actor):
    """Handle Google Sheets upload with better error handling."""
    try:
        sheets_url = post_vars.get('sheets_url', '').strip()
        sheet_index = int(post_vars.get('sheet_index', '0'))
        custom_table_name = post_vars.get('table_name', '').strip()
        first_row_headers = 'first_row_headers' in post_vars
        
        logger.debug(f"Google Sheets params: url='{sheets_url}', sheet_index={sheet_index}, table_name='{custom_table_name}', headers={first_row_headers}")
        
        if not sheets_url:
            return Response.redirect(f"/upload-table/{db_name}?error=Google Sheets URL is required")
        
        # Fetch data from Google Sheets with enhanced error handling
        csv_content = GoogleSheetsHandler.fetch_sheet_data(sheets_url, sheet_index)
        
        # Generate table name
        if custom_table_name:
            table_name = custom_table_name
        else:
            base_name = TableNameManager.sanitize_table_name("google_sheet")
            table_name = await TableNameManager.suggest_unique_name(base_name, datasette, db_name)
        
        # Validate table name
        is_valid, error_msg = TableNameManager.validate_table_name(table_name)
        if not is_valid:
            return Response.redirect(f"/upload-table/{db_name}?error=Invalid table name: {error_msg}")
        
        # Process CSV data with first_row_headers parameter
        df, error = DataProcessor.process_csv_content(csv_content, table_name, first_row_headers)
        if error:
            return Response.redirect(f"/upload-table/{db_name}?error={error}")
        
        # Insert data into database
        target_db = datasette.get_database(db_name)
        
        # Use enhanced data preparation
        records = DataProcessor.prepare_for_sqlite(df)
        
        # Create table
        column_defs = [f"[{col}] TEXT" for col in df.columns]
        create_sql = f"CREATE TABLE [{table_name}] ({', '.join(column_defs)})"
        await target_db.execute_write(create_sql)
        
        # Insert data
        placeholders = ", ".join(["?" for _ in df.columns])
        columns = ", ".join([f"[{col}]" for col in df.columns])
        insert_sql = f"INSERT INTO [{table_name}] ({columns}) VALUES ({placeholders})"
        
        await target_db.execute_write_many(insert_sql, records)
        
        # Update database timestamp
        await update_database_timestamp(datasette, db_name)
        
        # Log activity
        await log_database_action(
            datasette, actor.get("id"), "enhanced_upload", 
            f"Imported {len(records)} rows to table '{table_name}' from Google Sheets",
            {
                "source_type": "google_sheets",
                "table_name": table_name,
                "sheets_url": sheets_url,
                "record_count": len(records),
                "column_count": len(df.columns)
            }
        )
        
        # return Response.redirect(f"/upload-table/{db_name}?success=Successfully imported {len(records)} rows from Google Sheets to table '{table_name}'")
        return redirect_after_upload(request, db_name, f"Successfully uploaded {len(records)} rows to table '{table_name}'")

    except Exception as e:
        logger.error(f"Google Sheets upload error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        # return Response.redirect(f"/upload-table/{db_name}?error=Google Sheets import failed: {str(e)}")
        return redirect_after_upload(request, db_name, f"Upload failed: {str(e)}", is_error=True)

async def handle_url_upload(datasette, request, post_vars, db_name, actor):
    """Handle web CSV upload with dynamic domain validation."""
    try:
        csv_url = post_vars.get('csv_url', '').strip()
        custom_table_name = post_vars.get('table_name', '').strip()
        encoding = post_vars.get('encoding', 'auto')
        
        logger.debug(f"Web CSV params: url='{csv_url}', table_name='{custom_table_name}', encoding='{encoding}'")
        
        if not csv_url:
            return Response.redirect(f"/upload-table/{db_name}?error=CSV URL is required")
        
        # Fetch CSV from URL with dynamic domain checking
        csv_content = await WebCSVHandler.fetch_csv_from_url(datasette, csv_url, encoding)
        
        # Generate table name
        if custom_table_name:
            table_name = custom_table_name
        else:
            url_path = urlparse(csv_url).path
            filename = os.path.basename(url_path) or "web_csv"
            base_name = TableNameManager.sanitize_table_name(filename)
            table_name = await TableNameManager.suggest_unique_name(base_name, datasette, db_name)
        
        # Validate table name
        is_valid, error_msg = TableNameManager.validate_table_name(table_name)
        if not is_valid:
            return Response.redirect(f"/upload-table/{db_name}?error=Invalid table name: {error_msg}")
        
        # Process CSV data
        df, error = DataProcessor.process_csv_content(csv_content, table_name, first_row_headers=True)
        if error:
            return Response.redirect(f"/upload-table/{db_name}?error={error}")
        
        # Insert data into database
        target_db = datasette.get_database(db_name)
        
        # Use enhanced data preparation
        records = DataProcessor.prepare_for_sqlite(df)
        
        # Create table
        column_defs = [f"[{col}] TEXT" for col in df.columns]
        create_sql = f"CREATE TABLE [{table_name}] ({', '.join(column_defs)})"
        await target_db.execute_write(create_sql)
        
        # Insert data
        placeholders = ", ".join(["?" for _ in df.columns])
        columns = ", ".join([f"[{col}]" for col in df.columns])
        insert_sql = f"INSERT INTO [{table_name}] ({columns}) VALUES ({placeholders})"
        
        await target_db.execute_write_many(insert_sql, records)
        
        # Update database timestamp
        await update_database_timestamp(datasette, db_name)
        
        # Log activity
        await log_database_action(
            datasette, actor.get("id"), "enhanced_upload", 
            f"Imported {len(records)} rows to table '{table_name}' from web CSV",
            {
                "source_type": "web_csv",
                "table_name": table_name,
                "csv_url": csv_url,
                "record_count": len(records),
                "column_count": len(df.columns)
            }
        )
        
        # return Response.redirect(f"/upload-table/{db_name}?success=Successfully imported {len(records)} rows from web CSV to table '{table_name}'")
        return redirect_after_upload(request, db_name, f"Successfully uploaded {len(records)} rows to table '{table_name}'")

    except Exception as e:
        logger.error(f"Web CSV upload error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        # return Response.redirect(f"/upload-table/{db_name}?error=Web CSV import failed: {str(e)}")
        return redirect_after_upload(request, db_name, f"Upload failed: {str(e)}", is_error=True)

def redirect_after_upload(request, db_name, message, is_error=False):
    """Helper to redirect after upload based on request parameter."""
    redirect_to = request.args.get('redirect', 'upload')
    param = 'error' if is_error else 'success'
    
    if redirect_to == 'manage-databases':
        return Response.redirect(f"/manage-databases?{param}={message}")
    else:
        return Response.redirect(f"/upload-table/{db_name}?{param}={message}")

@hookimpl
def register_routes():
    """Register enhanced upload routes."""
    return [
        (r"^/upload-table/([^/]+)$", enhanced_upload_page),
    ]