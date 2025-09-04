"""
Complete Ultra-High Performance Upload Module - ALL FEATURES INCLUDED + OPTIMIZATIONS
Supports: CSV files, Excel files, Google Sheets, and Web CSV
Memory-efficient streaming, connection pooling, robust CSV parsing
"""

import json
import logging
import uuid
import os
import re
import csv
import io
import requests
import sqlite3
import time
import pandas as pd
import numpy as np
import threading
from datetime import datetime
from urllib.parse import urlparse
from email.parser import BytesParser
from email.policy import default
from queue import Queue, Empty
from contextlib import contextmanager
import certifi

from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database

# SSL configuration
os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()

# Import common utilities
import sys
PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGINS_DIR not in sys.path:
    sys.path.insert(0, PLUGINS_DIR)

from common_utils import (
    get_actor_from_request,
    get_portal_content,
    get_max_file_size,
    user_owns_database,
    get_success_error_from_request,
    update_database_timestamp,
    DATA_DIR,
    is_domain_blocked,
    sync_database_tables_on_upload,
    handle_upload_error_gracefully,
    log_upload_activity_enhanced,
    create_safe_redirect_url,
    sanitize_filename_for_table,
    validate_table_name_enhanced,
    auto_fix_table_name,
    get_system_settings,
)

logger = logging.getLogger(__name__)

# Optional encoding detection
try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False
    logger.warning("chardet not available - using basic encoding detection")

class SQLiteConnectionPool:
    """Thread-safe SQLite connection pool for concurrent operations"""
    
    def __init__(self, db_path, max_connections=3, ultra_pragmas=None):
        self.db_path = db_path
        self.max_connections = max_connections
        self.ultra_pragmas = ultra_pragmas or []
        self.pool = Queue(maxsize=max_connections)
        self.created_connections = 0
        self.lock = threading.Lock()
        
        # Pre-create connections
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Pre-create connections with optimized settings"""
        for _ in range(self.max_connections):
            conn = self._create_connection()
            self.pool.put(conn)
    
    def _create_connection(self):
        """Create a new optimized SQLite connection"""
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.isolation_level = None  # Manual transaction control
        
        # Apply performance pragmas
        for pragma in self.ultra_pragmas:
            try:
                conn.execute(pragma)
            except sqlite3.OperationalError as e:
                logger.warning(f"Failed to apply pragma {pragma}: {e}")
        
        self.created_connections += 1
        logger.debug(f"Created connection #{self.created_connections} for {self.db_path}")
        return conn
    
    @contextmanager
    def get_connection(self, timeout=10.0):
        """Context manager for getting/returning connections safely"""
        conn = None
        try:
            # Try to get existing connection
            try:
                conn = self.pool.get(timeout=timeout)
            except Empty:
                # Pool exhausted, create temporary connection
                logger.warning("Connection pool exhausted, creating temporary connection")
                conn = self._create_connection()
            
            # Test connection
            try:
                conn.execute("SELECT 1").fetchone()
            except sqlite3.Error:
                # Connection is bad, create new one
                logger.warning("Bad connection detected, creating replacement")
                conn.close()
                conn = self._create_connection()
            
            yield conn
            
        except Exception as e:
            # Connection error occurred
            if conn:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass  # Connection might be broken
            raise e
            
        finally:
            # Return connection to pool or close if temporary
            if conn:
                try:
                    # Ensure no active transaction
                    conn.rollback()
                    
                    # Try to return to pool
                    try:
                        self.pool.put_nowait(conn)
                    except:
                        # Pool is full, close this connection
                        conn.close()
                        logger.debug("Closed temporary connection (pool full)")
                except sqlite3.Error:
                    # Connection is broken, don't return to pool
                    try:
                        conn.close()
                    except:
                        pass
                    logger.warning("Discarded broken connection")
    
    def close_all(self):
        """Close all connections in pool"""
        closed_count = 0
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
                closed_count += 1
            except (Empty, sqlite3.Error):
                break
        
        logger.info(f"Closed {closed_count} connections from pool")
    
    def get_pool_stats(self):
        """Get current pool statistics"""
        return {
            'max_connections': self.max_connections,
            'available_connections': self.pool.qsize(),
            'created_connections': self.created_connections
        }

class StreamCSVProcessor:
    """Memory-efficient CSV processor that streams data without loading entire file"""
    
    def __init__(self, db_path, ultra_pragmas):
        self.db_path = db_path
        self.ultra_pragmas = ultra_pragmas
        
    def stream_process_from_response(self, response, table_name, max_file_size, replace_existing=False):
        """Process CSV directly from HTTP response stream"""
        start_time = time.time()
        downloaded_size = 0
        max_mb = max_file_size / (1024 * 1024)
        
        # Create a text stream from response
        lines_buffer = []
        current_line = ""
        headers = None
        total_rows = 0
        
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.isolation_level = None
        
        try:
            # Apply performance pragmas
            for pragma in self.ultra_pragmas:
                try:
                    conn.execute(pragma)
                except sqlite3.OperationalError:
                    continue
            
            # Stream processing
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                if not chunk:
                    continue
                
                downloaded_size += len(chunk.encode('utf-8'))
                
                # Check size limit
                if downloaded_size > max_file_size:
                    current_mb = downloaded_size / (1024 * 1024)
                    raise ValueError(f"File exceeds size limit during processing ({current_mb:.1f}MB). Maximum: {max_mb:.0f}MB")
                
                # Process chunk line by line
                current_line += chunk
                
                while '\n' in current_line:
                    line, current_line = current_line.split('\n', 1)
                    line = line.rstrip('\r')
                    
                    if not line.strip():
                        continue
                    
                    # Parse headers on first data line
                    if headers is None:
                        headers = self._parse_csv_line(line)
                        headers = [self._clean_column_name(h) for h in headers]
                        
                        # Setup database table
                        if replace_existing:
                            conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
                        
                        columns = ', '.join([f'[{header}] TEXT' for header in headers])
                        conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
                        
                        # Start transaction
                        conn.execute("BEGIN IMMEDIATE")
                        
                        # Prepare insert statement
                        placeholders = ','.join(['?' for _ in headers])
                        insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
                        
                        continue
                    
                    # Process data line
                    if headers:
                        row_data = self._parse_csv_line(line)
                        
                        # Normalize row length
                        if len(row_data) < len(headers):
                            row_data.extend([''] * (len(headers) - len(row_data)))
                        elif len(row_data) > len(headers):
                            row_data = row_data[:len(headers)]
                        
                        lines_buffer.append(tuple(row_data))
                        
                        # Batch insert every 10,000 rows
                        if len(lines_buffer) >= 10000:
                            conn.executemany(insert_sql, lines_buffer)
                            total_rows += len(lines_buffer)
                            lines_buffer.clear()
                            
                            if total_rows % 50000 == 0:
                                logger.info(f"STREAM: Processed {total_rows:,} rows")
            
            # Process remaining line
            if current_line.strip() and headers:
                row_data = self._parse_csv_line(current_line.rstrip('\r\n'))
                if len(row_data) < len(headers):
                    row_data.extend([''] * (len(headers) - len(row_data)))
                elif len(row_data) > len(headers):
                    row_data = row_data[:len(headers)]
                lines_buffer.append(tuple(row_data))
            
            # Insert remaining rows
            if lines_buffer and headers:
                conn.executemany(insert_sql, lines_buffer)
                total_rows += len(lines_buffer)
            
            # Commit transaction
            conn.execute("COMMIT")
            
        except Exception as e:
            conn.execute("ROLLBACK")
            raise Exception(f"Stream processing failed: {str(e)}")
        finally:
            conn.close()
        
        elapsed_time = time.time() - start_time
        rows_per_second = int(total_rows / elapsed_time) if elapsed_time > 0 else 0
        file_size_mb = downloaded_size / (1024 * 1024)
        
        logger.info(f"STREAM COMPLETE: {total_rows:,} rows in {elapsed_time:.2f}s = {rows_per_second:,} rows/sec ({file_size_mb:.1f}MB)")
        
        return {
            'table_name': table_name,
            'rows_inserted': total_rows,
            'columns': len(headers) if headers else 0,
            'time_elapsed': elapsed_time,
            'rows_per_second': rows_per_second,
            'strategy': 'memory_efficient_stream',
            'file_size_mb': file_size_mb
        }
    
    def _parse_csv_line(self, line):
        """Robust CSV line parsing using csv.reader"""
        try:
            # Use Python's csv.reader for proper CSV parsing
            reader = csv.reader([line])
            return next(reader)
        except (csv.Error, StopIteration):
            # Fallback to simple split for malformed lines
            return [cell.strip().strip('"\'') for cell in line.split(',')]
    
    def _clean_column_name(self, name):
        """Enhanced column name cleaning for SQL compatibility"""
        import re
        import unicodedata
        
        # Convert to string and handle None/empty values
        if name is None:
            return 'column_unnamed'
        
        name = str(name).strip()
        if not name:
            return 'column_empty'
        
        # Remove or replace problematic characters
        # First, normalize unicode characters
        try:
            name = unicodedata.normalize('NFKD', name)
        except:
            pass
        
        # Replace spaces and common separators with underscores
        name = re.sub(r'[\s\-\.\/\\]+', '_', name)
        
        # Remove or replace SQL-problematic characters
        # Keep only alphanumeric, underscore, and convert others to underscore
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        
        # Remove multiple consecutive underscores
        clean_name = re.sub(r'_+', '_', clean_name)
        
        # Remove leading/trailing underscores
        clean_name = clean_name.strip('_')
        
        # Ensure it starts with a letter or underscore
        if clean_name and not (clean_name[0].isalpha() or clean_name[0] == '_'):
            clean_name = 'col_' + clean_name
        
        # Ensure minimum length
        if not clean_name:
            clean_name = 'column'
        
        # Truncate to reasonable length
        clean_name = clean_name[:64]
        
        # Handle SQL reserved words (add more as needed)
        sql_reserved = {
            'order', 'group', 'select', 'from', 'where', 'insert', 'update', 
            'delete', 'create', 'drop', 'alter', 'table', 'index', 'view',
            'user', 'date', 'time', 'timestamp', 'year', 'month', 'day'
        }
        
        if clean_name.lower() in sql_reserved:
            clean_name = f"{clean_name}_col"
        
        return clean_name

    def _ensure_unique_column_names(self, headers):
        """Ensure all column names are unique"""
        seen = {}
        unique_headers = []
        
        for header in headers:
            clean_header = self._clean_column_name(header)
            
            if clean_header in seen:
                seen[clean_header] += 1
                unique_header = f"{clean_header}_{seen[clean_header]}"
            else:
                seen[clean_header] = 0
                unique_header = clean_header
            
            unique_headers.append(unique_header)
        
        return unique_headers
    
class PooledUltraOptimizedUploader:
    """Ultra-optimized uploader with connection pooling and memory efficiency"""
    
    ULTRA_PRAGMAS = [
        "PRAGMA synchronous = NORMAL",
        "PRAGMA journal_mode = WAL",
        "PRAGMA cache_size = -1000000",  # 1GB cache
        "PRAGMA temp_store = MEMORY",
        "PRAGMA mmap_size = 268435456",  # 256MB memory-mapped I/O
        "PRAGMA threads = 4",  # Enable multi-threading
    ]
    
    def __init__(self, db_path, ultra_mode=False, max_connections=3):
        self.db_path = db_path
        self.ultra_mode = ultra_mode
        self.connection_pool = SQLiteConnectionPool(
            db_path, 
            max_connections=max_connections,
            ultra_pragmas=self.ULTRA_PRAGMAS
        )
        self.stream_processor = StreamCSVProcessor(db_path, self.ULTRA_PRAGMAS)
    
    def stream_csv_ultra_fast_pooled(self, response_or_content, table_name, replace_existing=False, max_file_size=None):
        """Ultra-fast CSV processing with connection pooling and streaming"""
        
        # Handle both streaming response and content string
        if hasattr(response_or_content, 'iter_content'):
            # Streaming response - use memory-efficient processing
            return self.stream_processor.stream_process_from_response(
                response_or_content, table_name, max_file_size or (500 * 1024 * 1024), replace_existing
            )
        else:
            # Content string - use pooled batch processing
            return self._process_content_with_pool(
                response_or_content, table_name, replace_existing
            )
    
    def _process_content_with_pool(self, csv_content, table_name, replace_existing):
        """Process CSV content using connection pool"""
        start_time = time.time()
        
        # Handle different line ending formats (Windows \r\n, Unix \n, Mac \r)
        # Normalize all line endings to \n
        csv_content = csv_content.replace('\r\n', '\n').replace('\r', '\n')
        
        # Remove any null bytes that might interfere
        csv_content = csv_content.replace('\x00', '')
        
        # Strip BOM if present
        if csv_content.startswith('\ufeff'):
            csv_content = csv_content[1:]
        
        content_size_bytes = len(csv_content.encode('utf-8'))
        content_size_mb = content_size_bytes / (1024 * 1024)
        
        # Parse headers efficiently
        first_line_end = csv_content.find('\n')
        if first_line_end == -1:
            # Check if it's a single-line CSV (headers only) or has data with no line breaks
            if ',' in csv_content or '\t' in csv_content:
                # Check if there's actual data beyond potential headers
                potential_headers = self._parse_csv_line(csv_content)
                if len(potential_headers) > 0:
                    # Treat entire content as header row with no data
                    logger.warning("CSV appears to have only headers, no data rows")
                    header_line = csv_content
                    csv_data = ""  # No data rows
                else:
                    raise ValueError("Invalid CSV format - unable to parse")
            else:
                raise ValueError("Invalid CSV - no line breaks or delimiters found")
        else:
            header_line = csv_content[:first_line_end]
            csv_data = csv_content[first_line_end + 1:]
        
        # Parse and clean headers
        headers = [self._clean_column_name(h.strip()) for h in self._parse_csv_line(header_line)]
        
        if not headers:
            raise ValueError("No headers found in CSV file")
        
        # Ensure unique column names
        headers = self._ensure_unique_column_names(headers)
        
        # Determine batch size based on content size
        if content_size_mb > 200:
            batch_size = 100000
        elif content_size_mb > 50:
            batch_size = 50000
        else:
            batch_size = 25000
        
        logger.info(f"Processing {content_size_mb:.1f}MB file with batch size: {batch_size:,} (pooled)")
        
        total_rows = 0
        
        with self.connection_pool.get_connection() as conn:
            try:
                # Handle existing table
                if replace_existing:
                    conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
                
                # Create table
                columns = ', '.join([f'[{header}] TEXT' for header in headers])
                conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
                
                # Only process if there's actual data
                if csv_data and csv_data.strip():
                    # Prepare optimized insert statement
                    placeholders = ','.join(['?' for _ in headers])
                    insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
                    
                    # Manual transaction control
                    conn.execute("BEGIN IMMEDIATE")
                    
                    try:
                        # Process CSV data with robust parsing
                        total_rows = self._process_csv_data_robust(
                            conn, csv_data, insert_sql, 
                            headers, batch_size
                        )
                        
                        # Commit single large transaction
                        conn.execute("COMMIT")
                        
                    except Exception as e:
                        conn.execute("ROLLBACK")
                        raise Exception(f"Pooled insert failed: {str(e)}")
                else:
                    logger.warning("No data rows found in CSV, only headers were processed")
                    
            except Exception as e:
                raise Exception(f"Pooled processing failed: {str(e)}")
        
        elapsed_time = time.time() - start_time
        rows_per_second = int(total_rows / elapsed_time) if elapsed_time > 0 and total_rows > 0 else 0
        
        logger.info(f"POOLED COMPLETE: {total_rows:,} rows in {elapsed_time:.2f}s = {rows_per_second:,} rows/sec")
        
        return {
            'table_name': table_name,
            'rows_inserted': total_rows,
            'columns': len(headers),
            'time_elapsed': elapsed_time,
            'rows_per_second': rows_per_second,
            'strategy': 'pooled_ultra_streaming',
            'batch_size': batch_size,
            'file_size_mb': content_size_mb
        }
    
    def _process_csv_data_robust(self, conn, csv_data, insert_sql, headers, batch_size):
        """Robust CSV data processing with proper CSV parsing"""
        total_rows = 0
        batch_data = []
        num_columns = len(headers)
        
        # Use StringIO and csv.reader for proper CSV parsing
        csv_reader = csv.reader(io.StringIO(csv_data))
        
        for row_data in csv_reader:
            if not any(cell.strip() for cell in row_data):  # Skip empty rows
                continue
            
            # Normalize row length
            if len(row_data) < num_columns:
                row_data.extend([''] * (num_columns - len(row_data)))
            elif len(row_data) > num_columns:
                row_data = row_data[:num_columns]
            
            batch_data.append(tuple(row_data))
            
            if len(batch_data) >= batch_size:
                conn.executemany(insert_sql, batch_data)
                total_rows += len(batch_data)
                batch_data.clear()
                
                if total_rows % (batch_size * 2) == 0:
                    logger.info(f"POOLED: Processed {total_rows:,} rows")
        
        # Insert remaining rows
        if batch_data:
            conn.executemany(insert_sql, batch_data)
            total_rows += len(batch_data)
        
        return total_rows
    
    def process_excel_ultra_fast(self, file_content, table_name, sheet_name=None, replace_existing=False):
        """Excel processing with enhanced column handling and robust error recovery"""
        start_time = time.time()
        file_size_bytes = len(file_content)
        file_size_mb = file_size_bytes / (1024 * 1024)
        total_rows = 0
        headers = []
        
        logger.info(f"Starting Excel processing: {file_size_mb:.1f}MB file")
        
        with self.connection_pool.get_connection() as conn:
            try:
                # Handle existing table
                if replace_existing:
                    try:
                        conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
                        logger.info(f"Dropped existing table: {table_name}")
                    except sqlite3.Error as e:
                        logger.warning(f"Could not drop existing table: {e}")
                
                # Read Excel file with enhanced error handling
                try:
                    excel_file = pd.ExcelFile(io.BytesIO(file_content), engine='openpyxl')
                    logger.info(f"Excel file loaded successfully with {len(excel_file.sheet_names)} sheets")
                    
                    # Determine sheet to process
                    if sheet_name and sheet_name in excel_file.sheet_names:
                        target_sheet = sheet_name
                        logger.info(f"Using specified sheet: {sheet_name}")
                    elif sheet_name:
                        logger.warning(f"Sheet '{sheet_name}' not found, using first sheet")
                        target_sheet = excel_file.sheet_names[0]
                    else:
                        target_sheet = excel_file.sheet_names[0]
                        logger.info(f"Using first sheet: {target_sheet}")
                    
                except Exception as excel_error:
                    logger.error(f"Failed to load Excel file: {str(excel_error)}")
                    raise ValueError(f"Unable to open Excel file. Please ensure it's a valid Excel file and not corrupted.")
                
                # Determine chunk size based on file size
                if file_size_mb > 100:
                    chunk_size = 5000
                    logger.info("Large file detected: using 5K chunk size")
                elif file_size_mb > 50:
                    chunk_size = 10000
                    logger.info("Medium file detected: using 10K chunk size")
                else:
                    chunk_size = 20000
                    logger.info("Standard file: using 20K chunk size")
                
                # ENHANCED: Read and process headers with robust error handling
                try:
                    header_df = pd.read_excel(excel_file, sheet_name=target_sheet, nrows=0)
                    raw_headers = [str(col) for col in header_df.columns]
                    
                    logger.info(f"Raw headers extracted: {len(raw_headers)} columns")
                    logger.debug(f"Sample raw headers: {raw_headers[:5]}")
                    
                    # Check if sheet has no columns/data
                    if not raw_headers:
                        logger.warning(f"Sheet '{target_sheet}' appears to have no columns/headers")
                        
                        # Try to read the first row to check if data exists
                        try:
                            first_row_df = pd.read_excel(excel_file, sheet_name=target_sheet, nrows=1, header=None)
                            if not first_row_df.empty and not first_row_df.columns.empty:
                                # Use first row as headers
                                raw_headers = [str(val) for val in first_row_df.iloc[0]]
                                logger.info(f"Using first row as headers: {len(raw_headers)} columns")
                            else:
                                # Sheet is truly empty, try other sheets
                                logger.warning(f"Sheet '{target_sheet}' is empty, checking other sheets")
                                
                                found_data = False
                                available_sheets = []
                                sheets_with_data = []
                                
                                for alt_sheet in excel_file.sheet_names:
                                    available_sheets.append(alt_sheet)
                                    if alt_sheet != target_sheet:
                                        try:
                                            alt_df = pd.read_excel(excel_file, sheet_name=alt_sheet, nrows=0)
                                            if len(alt_df.columns) > 0:
                                                sheets_with_data.append(alt_sheet)
                                                if not found_data:
                                                    # Use the first sheet with data
                                                    target_sheet = alt_sheet
                                                    raw_headers = [str(col) for col in alt_df.columns]
                                                    logger.info(f"Automatically switched to sheet '{alt_sheet}' which has {len(raw_headers)} columns")
                                                    found_data = True
                                        except Exception as sheet_check_error:
                                            logger.debug(f"Could not check sheet '{alt_sheet}': {sheet_check_error}")
                                            continue
                                
                                # If still no headers found, provide helpful error
                                if not raw_headers:
                                    if sheets_with_data:
                                        # Other sheets have data, suggest them
                                        sheets_list = "', '".join(sheets_with_data[:3])  # Show max 3 sheets
                                        if len(sheets_with_data) > 3:
                                            sheets_list += f"' and {len(sheets_with_data) - 3} more"
                                        error_msg = (
                                            f"The selected sheet '{excel_file.sheet_names[0]}' is empty. "
                                            f"However, data was found in: '{sheets_list}'. "
                                            f"Please specify one of these sheets in the upload form, or let the system auto-select by leaving the sheet field empty."
                                        )
                                    else:
                                        # No sheets have data
                                        error_msg = (
                                            f"This Excel file appears to be empty or contains no readable data. "
                                            f"Found {len(available_sheets)} sheet(s): {', '.join(available_sheets[:5])}, "
                                            f"but none contain data that can be imported. "
                                            f"Please check your file and ensure it contains data in at least one sheet."
                                        )
                                    raise ValueError(error_msg)
                                else:
                                    # We found data and switched sheets - add a note for the user
                                    logger.info(f"Successfully auto-selected sheet '{target_sheet}' with data")
                        except ValueError:
                            raise  # Re-raise our custom error messages
                        except Exception as e:
                            logger.error(f"Error checking for data: {str(e)}")
                            raise ValueError(
                                f"The Excel sheet '{target_sheet}' appears to be empty. "
                                f"The file has {len(excel_file.sheet_names)} sheets: {', '.join(excel_file.sheet_names[:5])}. "
                                f"Try selecting a different sheet or leaving the sheet field empty to auto-select."
                            )
                    
                    # Clean and ensure unique column names
                    headers = self._ensure_unique_column_names(raw_headers)
                    
                    logger.info(f"Processed headers: {len(headers)} unique columns")
                    logger.debug(f"Sample clean headers: {headers[:5]}")
                    
                except ValueError as ve:
                    raise ve  # Re-raise with our user-friendly message
                except Exception as header_error:
                    logger.error(f"Failed to process Excel headers: {str(header_error)}")
                    # Provide user-friendly error
                    raise ValueError(
                        f"Could not read the Excel file properly. "
                        f"This file has {len(excel_file.sheet_names)} sheet(s): {', '.join(excel_file.sheet_names[:3])}. "
                        f"Please ensure the file is not corrupted and contains valid data."
                    )
                
                # ENHANCED: Create table with robust SQL generation
                try:
                    # Final check: ensure we have at least one column
                    if not headers:
                        raise ValueError("Cannot create table with no columns. The Excel sheet appears to be empty.")
                    
                    # Validate all headers are SQL-safe
                    validated_headers = []
                    for i, header in enumerate(headers):
                        if not header or not isinstance(header, str):
                            validated_headers.append(f"column_{i+1}")
                        else:
                            validated_headers.append(header)
                    
                    headers = validated_headers
                    
                    # Build CREATE TABLE statement
                    columns = ', '.join([f'[{header}] TEXT' for header in headers])
                    create_table_sql = f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})"
                    
                    # Log SQL for debugging (truncated)
                    sql_preview = create_table_sql[:200] + '...' if len(create_table_sql) > 200 else create_table_sql
                    logger.debug(f"CREATE TABLE SQL: {sql_preview}")
                    
                    conn.execute(create_table_sql)
                    logger.info(f"Table '{table_name}' created successfully with {len(headers)} columns")
                    
                except sqlite3.Error as sql_error:
                    logger.error(f"SQL Error creating table: {str(sql_error)}")
                    logger.error(f"Problematic headers: {headers}")
                    raise ValueError(f"Failed to create table. The column names may contain invalid characters.")
                
                # Manual transaction control for performance
                conn.execute("BEGIN IMMEDIATE")
                logger.info("Started database transaction")
                
                # Prepare insert statement
                placeholders = ','.join(['?' for _ in headers])
                insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
                
                try:
                    # ENHANCED: Process Excel data in chunks with robust error handling
                    chunk_start = 1  # Skip header row
                    processed_chunks = 0
                    failed_chunks = 0
                    
                    while True:
                        try:
                            logger.debug(f"Processing chunk starting at row {chunk_start}")
                            
                            # Read chunk with error handling
                            try:
                                chunk_df = pd.read_excel(
                                    excel_file,
                                    sheet_name=target_sheet,
                                    skiprows=range(1, chunk_start),
                                    nrows=chunk_size,
                                    header=0
                                )
                            except Exception as read_error:
                                logger.warning(f"Failed to read chunk at row {chunk_start}: {str(read_error)}")
                                failed_chunks += 1
                                
                                # If too many consecutive failures, stop
                                if failed_chunks > 3:
                                    logger.error("Too many consecutive chunk failures, stopping")
                                    break
                                
                                chunk_start += chunk_size
                                continue
                            
                            # Check if chunk is empty
                            if chunk_df.empty:
                                logger.info("Reached end of data")
                                break
                            
                            # Reset failed chunk counter on successful read
                            failed_chunks = 0
                            processed_chunks += 1
                            
                            # ENHANCED: Handle column mismatch
                            try:
                                # Ensure chunk has same number of columns as headers
                                chunk_columns = len(chunk_df.columns)
                                expected_columns = len(headers)
                                
                                if chunk_columns != expected_columns:
                                    logger.warning(f"Column count mismatch: got {chunk_columns}, expected {expected_columns}")
                                    
                                    # Adjust DataFrame columns to match headers
                                    if chunk_columns < expected_columns:
                                        # Add missing columns
                                        for i in range(chunk_columns, expected_columns):
                                            chunk_df[f'missing_col_{i}'] = ''
                                    elif chunk_columns > expected_columns:
                                        # Remove extra columns
                                        chunk_df = chunk_df.iloc[:, :expected_columns]
                                
                                # Set column names to match our headers
                                chunk_df.columns = headers
                                
                            except Exception as column_error:
                                logger.warning(f"Column adjustment failed: {str(column_error)}")
                                chunk_start += chunk_size
                                continue
                            
                            # ENHANCED: Optimize DataFrame types and handle problematic data
                            try:
                                chunk_df = self._optimize_dataframe_types(chunk_df)
                            except Exception as optimize_error:
                                logger.warning(f"DataFrame optimization failed: {str(optimize_error)}")
                                # Continue without optimization
                            
                            # Convert to records and batch insert
                            try:
                                records = []
                                for row in chunk_df.values:
                                    # Convert row to tuple, handling any problematic values
                                    clean_row = []
                                    for value in row:
                                        if pd.isna(value):
                                            clean_row.append('')
                                        elif isinstance(value, (int, float, str)):
                                            clean_row.append(str(value))
                                        else:
                                            clean_row.append(str(value))
                                    records.append(tuple(clean_row))
                                
                                # Batch insert
                                conn.executemany(insert_sql, records)
                                total_rows += len(records)
                                
                                # Progress logging
                                if total_rows % (chunk_size * 2) == 0:
                                    logger.info(f"EXCEL POOLED: Processed {total_rows:,} rows in {processed_chunks} chunks")
                                
                            except sqlite3.Error as insert_error:
                                logger.error(f"Insert error for chunk at row {chunk_start}: {str(insert_error)}")
                                # Continue with next chunk rather than failing completely
                                failed_chunks += 1
                            
                            chunk_start += chunk_size
                            
                            # Safety check: prevent infinite loops
                            if processed_chunks > 10000:  # Arbitrary large number
                                logger.warning("Processed maximum number of chunks, stopping")
                                break
                        
                        except Exception as chunk_error:
                            logger.error(f"Unexpected error processing chunk at row {chunk_start}: {str(chunk_error)}")
                            failed_chunks += 1
                            
                            if failed_chunks > 3:
                                logger.error("Too many consecutive failures, stopping")
                                break
                            
                            chunk_start += chunk_size
                            continue
                    
                    # Commit transaction
                    conn.execute("COMMIT")
                    logger.info(f"Transaction committed successfully: {total_rows:,} rows, {processed_chunks} chunks processed")
                    
                except Exception as processing_error:
                    logger.error(f"Excel chunk processing failed: {str(processing_error)}")
                    try:
                        conn.execute("ROLLBACK")
                        logger.info("Transaction rolled back")
                    except:
                        pass
                    raise ValueError(f"Failed to process Excel data: {str(processing_error)}")
            
            except ValueError as ve:
                # These are our user-friendly errors
                raise ve
            except Exception as e:
                logger.error(f"Excel processing error: {str(e)}")
                try:
                    conn.execute("ROLLBACK")
                except:
                    pass
                raise ValueError(f"Excel processing failed: {str(e)}")
        
        # Calculate performance metrics
        elapsed_time = time.time() - start_time
        rows_per_second = int(total_rows / elapsed_time) if elapsed_time > 0 else 0
        
        logger.info(f"EXCEL POOLED COMPLETE: {total_rows:,} rows in {elapsed_time:.2f}s = {rows_per_second:,} rows/sec")
        
        return {
            'table_name': table_name,
            'rows_inserted': total_rows,
            'columns': len(headers),
            'time_elapsed': elapsed_time,
            'rows_per_second': rows_per_second,
            'strategy': 'excel_pooled_optimized',
            'file_size_mb': file_size_mb
        }
    
    def _optimize_dataframe_types(self, df):
        """Optimize pandas DataFrame for SQLite insertion"""
        for col in df.columns:
            if df[col].dtype == 'datetime64[ns]':
                df[col] = df[col].astype(str)
            elif df[col].dtype == 'object':
                df[col] = df[col].fillna('')
            elif df[col].dtype in ['float64', 'float32']:
                df[col] = df[col].replace([np.inf, -np.inf], None)
        return df
    
    def _parse_csv_line(self, line):
        """Robust CSV line parsing"""
        try:
            reader = csv.reader([line])
            return next(reader)
        except (csv.Error, StopIteration):
            return [cell.strip().strip('"\'') for cell in line.split(',')]
    
    def _clean_column_name(self, name):
        """Fast column name cleaning"""
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', str(name).strip())
        if clean_name and not clean_name[0].isalpha() and clean_name[0] != '_':
            clean_name = 'col_' + clean_name
        return clean_name[:64] or 'column'
    
    def _ensure_unique_column_names(self, headers):
        """Ensure all column names are unique"""
        seen = {}
        unique_headers = []
        
        for header in headers:
            clean_header = self._clean_column_name(header)
            
            if clean_header in seen:
                seen[clean_header] += 1
                unique_header = f"{clean_header}_{seen[clean_header]}"
            else:
                seen[clean_header] = 0
                unique_header = clean_header
            
            unique_headers.append(unique_header)
        
        return unique_headers
    
    def close_pool(self):
        """Close connection pool"""
        self.connection_pool.close_all()

def get_optimal_uploader(file_size, db_path, use_ultra_mode=False):
    """Choose optimal uploader with connection pooling"""
    max_connections = 3 if file_size > 100 * 1024 * 1024 else 2
    return PooledUltraOptimizedUploader(db_path, ultra_mode=use_ultra_mode, max_connections=max_connections)

# Size validation functions
async def validate_and_check_size(csv_url, max_file_size, headers):
    """Size checking with better error handling"""
    max_size_mb = max_file_size / (1024 * 1024)  # Float division
    
    try:
        head_response = requests.head(csv_url, headers=headers, allow_redirects=True, timeout=10)
        head_response.raise_for_status()
        
        content_length = head_response.headers.get('content-length')
        
        if content_length:
            try:
                size_bytes = int(content_length)
                actual_mb = size_bytes / (1024 * 1024)  # FIXED: Float division
                
                if size_bytes > max_file_size:
                    raise ValueError(f"File too large ({actual_mb:.1f}MB). Maximum: {max_size_mb:.0f}MB")
                
                logger.info(f"File size check passed: {actual_mb:.1f}MB")
                return size_bytes
                
            except (ValueError, TypeError):
                logger.warning("Invalid content-length header, will monitor during download")
        else:
            logger.warning("No content-length header, will monitor during download")
            
    except requests.RequestException as e:
        logger.warning(f"HEAD request failed: {e}, will monitor size during download")
    
    return None  # Size unknown, will check during download

async def download_with_size_limit(csv_url, max_file_size, headers):
    """Download with strict size enforcement"""
    downloaded_size = 0
    chunks = []
    max_mb = max_file_size / (1024 * 1024)
    
    response = requests.get(csv_url, headers=headers, allow_redirects=True, stream=True, timeout=30)
    response.raise_for_status()
    
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:
            # FIXED: Check BEFORE adding chunk to prevent exceeding limit
            if downloaded_size + len(chunk) > max_file_size:
                current_mb = downloaded_size / (1024 * 1024)
                raise ValueError(f"File size limit reached during download ({current_mb:.1f}MB). Maximum: {max_mb:.0f}MB")
            
            downloaded_size += len(chunk)
            chunks.append(chunk)
            
            # Progress logging every 5MB
            if downloaded_size % (5 * 1024 * 1024) < len(chunk):
                mb_downloaded = downloaded_size / (1024 * 1024)
                logger.info(f"Downloaded {mb_downloaded:.1f}MB")
    
    return b''.join(chunks), downloaded_size

async def decode_content_safely(content_bytes, encoding='auto'):
    """Content decoding with better error handling"""
    if encoding == 'auto':
        if CHARDET_AVAILABLE:
            try:
                detected = chardet.detect(content_bytes[:10000])
                encoding = detected.get('encoding', 'utf-8') if detected.get('confidence', 0) > 0.7 else 'utf-8'
                logger.info(f"Auto-detected encoding: {encoding}")
            except Exception:
                encoding = 'utf-8'
                logger.info("Chardet detection failed, using UTF-8")
        else:
            encoding = 'utf-8'
            logger.info("Chardet not available, using UTF-8")
    
    # Try the specified/detected encoding first
    try:
        content = content_bytes.decode(encoding)
        logger.info(f"Successfully decoded with {encoding}")
        return content
    except UnicodeDecodeError:
        logger.warning(f"Failed to decode with {encoding}, trying fallbacks")
    
    # Try fallback encodings
    fallback_encodings = ['utf-8', 'latin-1', 'cp1252', 'utf-16', 'ascii']
    for fallback in fallback_encodings:
        if fallback == encoding:  # Skip if already tried
            continue
        try:
            content = content_bytes.decode(fallback)
            logger.info(f"Successfully decoded with fallback encoding: {fallback}")
            return content
        except UnicodeDecodeError:
            continue
    
    # Last resort: decode with errors='replace'
    content = content_bytes.decode('utf-8', errors='replace')
    logger.warning("Used UTF-8 with error replacement - some characters may be corrupted")
    return content

async def fetch_csv_from_url_stream(datasette, csv_url, encoding='auto'):
    """Stream-based CSV fetching without loading entire file into memory"""
    try:
        await validate_csv_url(datasette, csv_url)
        
        headers = {
            'User-Agent': 'EDGI-Portal/1.0 (Environmental Data Portal)',
            'Accept': 'text/csv, text/plain, application/csv, */*'
        }
        
        max_file_size = await get_max_file_size(datasette)
        max_size_mb = max_file_size / (1024 * 1024)
        
        logger.info(f"Starting STREAM download: {csv_url} (max size: {max_size_mb:.0f}MB)")
        
        # Validate size with HEAD request first
        await validate_and_check_size(csv_url, max_file_size, headers)
        
        # Get streaming response
        response = requests.get(csv_url, headers=headers, allow_redirects=True, stream=True, timeout=30)
        response.raise_for_status()
        
        # Set encoding for text decoding
        if encoding != 'auto':
            response.encoding = encoding
        elif not response.encoding or response.encoding == 'ISO-8859-1':
            # requests often defaults to ISO-8859-1, try to detect better encoding
            response.encoding = 'utf-8'
        
        return response  # Return response object for streaming
        
    except requests.RequestException as e:
        raise ValueError(f"Network error: {str(e)}")
    except Exception as e:
        logger.error(f"Stream setup error: {str(e)}")
        raise ValueError(f"Stream setup failed: {str(e)}")

async def fetch_csv_from_url_with_progress(datasette, csv_url, encoding='auto'):
    """Size checking with proper validation before download"""
    try:
        await validate_csv_url(datasette, csv_url)
        
        headers = {
            'User-Agent': 'EDGI-Portal/1.0 (Environmental Data Portal)',
            'Accept': 'text/csv, text/plain, application/csv, */*'
        }
        
        max_file_size = await get_max_file_size(datasette)
        max_size_mb = max_file_size / (1024 * 1024)  # FIXED: Use float division
        
        logger.info(f"Starting URL download: {csv_url} (max size: {max_size_mb:.0f}MB)")
        
        # Better size checking with proper error handling
        predicted_size = await validate_and_check_size(csv_url, max_file_size, headers)
        
        # Download with strict size monitoring
        content_bytes, final_size = await download_with_size_limit(csv_url, max_file_size, headers)
        
        final_size_mb = final_size / (1024 * 1024)  # FIXED: Use float division
        logger.info(f"Download complete: {final_size_mb:.1f}MB")
        
        # Better encoding detection and handling
        content = await decode_content_safely(content_bytes, encoding)
        
        logger.info(f"CSV processed: {len(content)} characters")
        return content
        
    except requests.RequestException as e:
        raise ValueError(f"Network error: {str(e)}")
    except Exception as e:
        logger.error(f"URL fetch error: {str(e)}")
        raise ValueError(f"Download failed: {str(e)}")

async def fetch_sheet_data(sheet_url, sheet_index=0, datasette=None):
    """Google Sheets fetching with enhanced URL parsing and fixed requests parameters"""
    try:
        sheet_url = sheet_url.rstrip('/')
        
        # Enhanced URL parsing patterns
        patterns = [
            # Standard spreadsheet URLs
            r'docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]{44})',
            # Published web URLs  
            r'docs\.google\.com/spreadsheets/d/e/([a-zA-Z0-9-_]{56})',
            # Drive sharing URLs
            r'drive\.google\.com/file/d/([a-zA-Z0-9-_]+)',
            # Alternative formats
            r'/spreadsheets/d/([a-zA-Z0-9-_]{30,60})'
        ]
        
        sheet_id = None
        for pattern in patterns:
            match = re.search(pattern, sheet_url)
            if match:
                sheet_id = match.group(1)
                # Validate sheet ID length
                if len(sheet_id) >= 30:  # Valid sheet IDs are typically 44+ chars
                    break
                else:
                    sheet_id = None  # Continue searching
        
        if not sheet_id:
            raise ValueError("Invalid Google Sheets URL format. Please use the sharing URL from Google Sheets.")
        
        logger.info(f"Extracted sheet ID: {sheet_id}")
        
        # Better GID extraction
        gid = 0
        if '#gid=' in sheet_url:
            try:
                gid = int(sheet_url.split('#gid=')[1].split('&')[0])
                logger.info(f"Using GID from URL: {gid}")
            except (ValueError, IndexError):
                gid = sheet_index
        else:
            gid = sheet_index
        
        # More export URL formats with better error handling
        export_urls = [
            # Standard export URLs
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}",
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv",
            
            # Published web URLs (for public sheets)
            f"https://docs.google.com/spreadsheets/d/e/{sheet_id}/pub?output=csv&gid={gid}",
            f"https://docs.google.com/spreadsheets/d/e/{sheet_id}/pub?output=csv",
            
            # Query API URLs
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&gid={gid}",
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv"
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/csv, text/plain, application/csv, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
        
        max_file_size = await get_max_file_size(datasette)
        max_size_mb = max_file_size / (1024 * 1024)
        last_error = None
        
        for i, csv_url in enumerate(export_urls):
            try:
                logger.info(f"Attempting export method {i+1}: {csv_url}")

                # Size checking with timeout - FIXED: removed max_redirects
                try:
                    head_response = requests.head(
                        csv_url, 
                        timeout=10, 
                        headers=headers, 
                        allow_redirects=True
                    )
                    
                    # Better status code handling
                    if head_response.status_code == 200:
                        content_length = head_response.headers.get('content-length')
                        if content_length:
                            try:
                                size_bytes = int(content_length)
                                size_mb = size_bytes / (1024 * 1024)
                                
                                if size_bytes > max_file_size:
                                    raise ValueError(f"Google Sheet too large ({size_mb:.1f}MB). Maximum size: {max_size_mb:.0f}MB")
                                
                                logger.info(f"Google Sheet size check passed: {size_mb:.1f}MB")
                            except (ValueError, TypeError) as e:
                                if "too large" in str(e):
                                    raise  # Re-raise size limit errors
                                logger.warning(f"Invalid content-length: {content_length}")
                    
                    elif head_response.status_code in [302, 307]:
                        # Check if redirecting to login page
                        location = head_response.headers.get('Location', '')
                        if 'accounts.google.com' in location or 'ServiceLogin' in location:
                            last_error = "Google Sheet is private. Please make it publicly accessible."
                            continue
                
                except requests.RequestException:
                    logger.warning("HEAD request failed, will try direct download")

                # Download with better error handling - FIXED: removed max_redirects
                try:
                    response = requests.get(
                        csv_url, 
                        timeout=30, 
                        headers=headers, 
                        allow_redirects=True, 
                        stream=True
                    )
                    
                    # Better status code handling
                    if response.status_code == 401:
                        last_error = "Google Sheet access denied - make sure the sheet is publicly accessible"
                        continue
                    elif response.status_code == 400:
                        last_error = "Google Sheet access denied - sheet may be private or GID invalid"
                        continue
                    elif response.status_code == 404:
                        last_error = f"Google Sheet not found with this URL format (method {i+1})"
                        continue
                    elif response.status_code not in [200]:
                        last_error = f"Failed to access Google Sheet (HTTP {response.status_code})"
                        continue
                    
                    # Check if response is redirecting to login
                    if response.url and 'accounts.google.com' in response.url:
                        last_error = "Google Sheet is private - redirected to login page"
                        continue
                    
                    # Download with size limit enforcement
                    downloaded_size = 0
                    chunks = []
                    
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            # Check size before adding chunk
                            if downloaded_size + len(chunk) > max_file_size:
                                current_mb = downloaded_size / (1024 * 1024)
                                raise ValueError(f"Google Sheet exceeds size limit during download ({current_mb:.1f}MB). Maximum: {max_size_mb:.0f}MB")
                            
                            downloaded_size += len(chunk)
                            chunks.append(chunk)
                    
                    # Enhanced content validation
                    csv_content = b''.join(chunks).decode('utf-8-sig', errors='replace')
                    
                    if not csv_content.strip():
                        last_error = f"Google Sheet appears to be empty (method {i+1})"
                        continue
                    
                    # Check if content is actually HTML (error page)
                    if csv_content.strip().startswith('<!DOCTYPE html') or '<html' in csv_content:
                        last_error = f"Received HTML instead of CSV - sheet may be private (method {i+1})"
                        continue
                    
                    if not (',' in csv_content or '\t' in csv_content):
                        last_error = f"Google Sheet doesn't contain valid CSV data (method {i+1})"
                        continue
                    
                    final_size_mb = downloaded_size / (1024 * 1024)
                    logger.info(f"Successfully retrieved CSV data using export method {i+1} ({final_size_mb:.1f}MB)")
                    return csv_content
                    
                except requests.RequestException as req_error:
                    last_error = f"Network error accessing Google Sheets (method {i+1}): {str(req_error)}"
                    continue
                
            except ValueError as val_error:
                if "too large" in str(val_error) or "exceeds size limit" in str(val_error):
                    raise  # Re-raise size limit errors immediately
                last_error = f"Export method {i+1} failed: {str(val_error)}"
                continue
            except Exception as method_error:
                last_error = f"Export method {i+1} failed: {str(method_error)}"
                continue
        
        # More specific error messages
        if last_error:
            if "private" in last_error.lower() or "access denied" in last_error.lower():
                raise ValueError(
                    "Google Sheet is not publicly accessible. "
                    "Please make it public by clicking Share > Anyone with the link can view."
                )
            elif "too large" in last_error.lower():
                raise ValueError(last_error)
            else:
                raise ValueError(f"Unable to import from Google Sheet: {last_error}")
        else:
            raise ValueError("Unable to export data from Google Sheet using any method")
            
    except Exception as e:
        logger.error(f"Google Sheets fetch error: {str(e)}")
        raise ValueError(f"Google Sheets import failed: {str(e)}")
        
async def enhanced_upload_page(datasette, request):
    """Upload page with ALL upload types"""
    actor = get_actor_from_request(request)
    if not actor:
        return Response.redirect("/login?error=Session expired")

    path_parts = request.path.strip('/').split('/')
    if len(path_parts) < 2:
        return Response.text("Invalid URL", status=400)
    
    db_name = path_parts[1]
    
    if not await user_owns_database(datasette, actor["id"], db_name):
        return Response.text("Access denied", status=403)

    if request.method == "POST":
        return await handle_enhanced_upload(datasette, request, db_name, actor)
    
    # GET request - show form
    content = await get_portal_content(datasette)
    system_settings = await get_system_settings(datasette)

    return Response.html(
        await datasette.render_template(
            "upload_table.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor,
                "db_name": db_name,
                "system_settings": system_settings,
                **get_success_error_from_request(request)
            },
            request=request
        )
    )

async def handle_enhanced_upload(datasette, request, db_name, actor):
    """Handle ALL upload types with proper routing"""
    try:
        max_file_size = await get_max_file_size(datasette)
        content_type = request.headers.get('content-type', '').lower()
        
        if 'multipart/form-data' in content_type:
            return await handle_file_upload_optimized(datasette, request, db_name, actor, max_file_size)
        else:
            post_vars = await request.post_vars()
            source_type = post_vars.get('source_type')
            
            if source_type == 'sheets':
                return await handle_sheets_upload_optimized(datasette, request, post_vars, db_name, actor)
            elif source_type == 'url':
                return await handle_url_upload_optimized(datasette, request, post_vars, db_name, actor)
            else:
                error_msg = "Invalid source type"
                return create_redirect_response(request, db_name, error_msg, is_error=True)
    
    except Exception as e:
        logger.error(f"Enhanced upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "enhanced_upload")
        return create_redirect_response(request, db_name, error_msg, is_error=True)

async def handle_file_upload_optimized(datasette, request, db_name, actor, max_file_size):
    """Optimized file upload with robust AJAX detection and proper response handling"""
    try:
        # ROBUST AJAX detection with multiple fallbacks
        is_ajax = (
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            '/ajax-upload-file/' in request.path or
            request.headers.get('Accept', '').startswith('application/json')
        )
        
        # Debug logging to understand request type
        logger.info(f"Request path: {request.path}")
        logger.info(f"X-Requested-With: {request.headers.get('X-Requested-With')}")
        logger.info(f"Accept header: {request.headers.get('Accept')}")
        logger.info(f"AJAX detection result: {is_ajax}")
        
        body = await request.post_body()
        
        # Early size validation
        if len(body) > max_file_size:
            size_mb = max_file_size / (1024*1024)
            error_msg = f"File too large (max {size_mb}MB)"
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=400)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        # Parse form data
        content_type = request.headers.get('content-type', '')
        boundary = content_type.split('boundary=')[-1].split(';')[0].strip() if 'boundary=' in content_type else None
        
        if not boundary:
            error_msg = "Invalid form data"
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=400)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        forms, files = parse_multipart_form_data(body, boundary)
        
        if 'file' not in files:
            error_msg = "No file uploaded"
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=400)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        file_info = files['file']
        filename = file_info['filename']
        file_content = file_info['content']
        
        # Log file information
        file_size = len(file_content)
        file_size_mb = file_size / (1024 * 1024)
        logger.info(f"Processing file: {filename} ({file_size_mb:.1f}MB)")
        
        # Get form options
        custom_table_name = forms.get('table_name', '').strip()
        replace_existing = 'replace_existing' in forms
        excel_sheet = forms.get('excel_sheet', '').strip()

        # Table name handling
        if custom_table_name:
            is_valid, validation_error = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                base_table_name = auto_fixed_name
                logger.info(f"Auto-fixed table name: '{custom_table_name}' -> '{auto_fixed_name}'")
            else:
                base_table_name = custom_table_name
        else:
            base_table_name = sanitize_filename_for_table(filename)
        
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        logger.info(f"Final table name: {table_name}")
        
        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        if not db_info:
            error_msg = "Database not found"
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=404)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        file_path = db_info['file_path'] or os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # Process file with optimized uploader
        file_ext = os.path.splitext(filename)[1].lower()
        use_ultra_mode = file_size > 50 * 1024 * 1024  # 50MB+
        uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
        
        logger.info(f"Using uploader mode: {'ultra' if use_ultra_mode else 'standard'}")
        
        try:
            if file_ext in ['.xlsx', '.xls']:
                logger.info(f"Processing Excel file with sheet: {excel_sheet or 'default'}")
                result = uploader.process_excel_ultra_fast(file_content, table_name, excel_sheet, replace_existing)
                
            elif file_ext in ['.csv', '.txt', '.tsv']:
                logger.info("Processing CSV/text file")
                csv_content = None
                encodings_tried = []
                successful_encoding = None
                
                # Try multiple encodings with BOM handling
                for encoding in ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'windows-1252', 'ascii']:
                    try:
                        test_content = file_content.decode(encoding)
                        # Verify we actually decoded something meaningful
                        if test_content and len(test_content.strip()) > 0:
                            # Check if content has reasonable structure
                            # (has commas/tabs or newlines)
                            if (',' in test_content or '\t' in test_content or 
                                '\n' in test_content or '\r' in test_content):
                                csv_content = test_content
                                successful_encoding = encoding
                                logger.info(f"Successfully decoded with encoding: {encoding}")
                                break
                    except (UnicodeDecodeError, AttributeError):
                        encodings_tried.append(encoding)
                        continue
                
                if csv_content is None:
                    # Last resort: try with error replacement
                    try:
                        csv_content = file_content.decode('utf-8', errors='replace')
                        successful_encoding = 'utf-8 (with replacements)'
                        logger.warning(f"Could not decode file cleanly. Tried: {', '.join(encodings_tried)}. Using UTF-8 with error replacement.")
                    except Exception as e:
                        raise ValueError(f"Unable to decode file content: {str(e)}")
                
                # Clean the content
                # Remove null bytes that might interfere with processing
                csv_content = csv_content.replace('\x00', '')
                
                # Strip BOM if present
                if csv_content.startswith('\ufeff'):
                    csv_content = csv_content[1:]
                
                # Normalize line endings
                csv_content = csv_content.replace('\r\n', '\n').replace('\r', '\n')
                
                # Validate that we have actual CSV content
                if not csv_content.strip():
                    raise ValueError("File appears to be empty after decoding")
                
                # Check for basic CSV structure
                lines = csv_content.split('\n')
                non_empty_lines = [line for line in lines if line.strip()]
                
                if len(non_empty_lines) == 0:
                    raise ValueError("No data found in file")
                
                # Check if first line has delimiters
                first_line = non_empty_lines[0]
                if ',' not in first_line and '\t' not in first_line:
                    # Maybe it's a single-column CSV
                    logger.warning("No obvious delimiters found, may be single-column data")
                
                logger.info(f"CSV prepared for processing: {len(non_empty_lines)} non-empty lines, encoding: {successful_encoding}")
                
                result = uploader.stream_csv_ultra_fast_pooled(csv_content, table_name, replace_existing)
            else:
                raise ValueError(f"Unsupported file type: {file_ext}. Use CSV, TSV, TXT, or Excel files")
        
        except ValueError as ve:
            # ValueError usually contains our user-friendly messages
            logger.error(f"File processing ValueError: {str(ve)}")
            error_msg = str(ve)
            
            # Clean up connection pool
            try:
                uploader.close_pool()
            except:
                pass
            
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=400)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
                
        except Exception as processing_error:
            logger.error(f"File processing error: {str(processing_error)}")
            
            # Clean up connection pool
            try:
                uploader.close_pool()
            except:
                pass
            
            # Check if the error message is already user-friendly
            error_str = str(processing_error)
            if any(phrase in error_str.lower() for phrase in ['empty', 'no data', 'sheet', 'select', 'columns', 'appears to be']):
                # It's already a user-friendly message from our processing
                error_msg = error_str
            else:
                # Generic error, make it more user-friendly
                if file_ext in ['.xlsx', '.xls']:
                    error_msg = (
                        f"Failed to process Excel file. "
                        f"Please ensure the file is not corrupted and contains data in at least one sheet."
                    )
                elif file_ext in ['.csv', '.txt', '.tsv']:
                    error_msg = (
                        f"Failed to process CSV file. "
                        f"Please ensure the file is properly formatted with consistent delimiters."
                    )
                else:
                    error_msg = f"Failed to process file: {error_str}"
            
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=500)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        finally:
            # Always close connection pool
            try:
                uploader.close_pool()
                logger.info("Connection pool closed successfully")
            except Exception as close_error:
                logger.warning(f"Error closing connection pool: {str(close_error)}")
        
        # Update database timestamp
        try:
            await update_database_timestamp(datasette, db_name)
        except Exception as timestamp_error:
            logger.warning(f"Failed to update database timestamp: {str(timestamp_error)}")
        
        # Sync with database_tables
        try:
            portal_db = datasette.get_database('portal')
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ? AND status != 'Deleted'", [db_name]
            )
            db_record = db_result.first()
            if db_record:
                await sync_database_tables_on_upload(datasette, db_record['db_id'], table_name)
                logger.info(f"Synced table visibility for: {table_name}")
        except Exception as sync_error:
            logger.error(f"Error syncing table visibility: {str(sync_error)}")

        # Log upload activity
        try:
            await log_upload_activity_enhanced(
                datasette, actor.get("id"), "optimized_upload", 
                f"Uploaded {result['rows_inserted']:,} rows to table '{table_name}' from '{filename}' using {result['strategy']}",
                {
                    "source_type": "file_optimized",
                    "table_name": table_name,
                    "filename": filename,
                    "file_type": file_ext,
                    "record_count": result['rows_inserted'],
                    "column_count": result['columns'],
                    "processing_strategy": result['strategy'],
                    "file_size_mb": file_size_mb,
                    "processing_time": result['time_elapsed']
                }
            )
        except Exception as log_error:
            logger.warning(f"Failed to log upload activity: {str(log_error)}")

        # Prepare success message
        success_msg = f"SUCCESS: Uploaded {result['rows_inserted']:,} rows to table '{table_name}' in {result['time_elapsed']:.1f}s ({result['rows_per_second']:,} rows/sec) - {result['strategy']}"
        
        logger.info(f"Upload completed successfully: {success_msg}")
        logger.info(f"Returning response type: {'JSON (AJAX)' if is_ajax else 'Redirect (Form)'}")
        
        # CRITICAL: Return appropriate response type based on request
        if is_ajax:
            return Response.json({
                "success": True,
                "message": success_msg,
                "redirect_url": "/manage-databases",
                "stats": {
                    "rows": result['rows_inserted'],
                    "columns": result.get('columns', 0),
                    "time": result['time_elapsed'],
                    "speed": result['rows_per_second'],
                    "strategy": result['strategy'],
                    "file_size_mb": file_size_mb
                },
                "table_info": {
                    "name": table_name,
                    "database": db_name,
                    "source": "file_upload"
                }
            })
        else:
            return create_redirect_response(request, db_name, success_msg)
        
    except Exception as e:
        logger.error(f"File upload handler error: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        
        error_msg = await handle_upload_error_gracefully(datasette, e, "file_upload_optimized")
        
        # CRITICAL: Ensure error responses also respect request type
        is_ajax_for_error = (
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            '/ajax-upload-file/' in request.path or
            request.headers.get('Accept', '').startswith('application/json')
        )
        
        logger.info(f"Error response type: {'JSON (AJAX)' if is_ajax_for_error else 'Redirect (Form)'}")
        
        if is_ajax_for_error:
            return Response.json({
                "success": False, 
                "error": error_msg
            }, status=500)
        else:
            return create_redirect_response(request, db_name, error_msg, is_error=True)
                                        
async def handle_sheets_upload_optimized(datasette, request, post_vars, db_name, actor):
    """Google Sheets upload with optimized processing"""
    try:
        sheets_url = post_vars.get('sheets_url', '').strip()
        sheet_index = int(post_vars.get('sheet_index', '0'))
        custom_table_name = post_vars.get('table_name', '').strip()
        first_row_headers = 'first_row_headers' in post_vars
        
        if not sheets_url:
            return create_redirect_response(request, db_name, "Google Sheets URL is required", is_error=True)
        
        # Fetch data from Google Sheets
        csv_content = await fetch_sheet_data(sheets_url, sheet_index, datasette)
        
        # Table name handling
        if custom_table_name:
            is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                base_table_name = auto_fixed_name
            else:
                base_table_name = custom_table_name
        else:
            if sheet_index > 0:
                base_table_name = f"google_sheet_{sheet_index}"
            else:
                base_table_name = "google_sheet"
        
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)

        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        file_path = db_info['file_path'] if db_info else os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # Process with optimized uploader
        file_size = len(csv_content.encode('utf-8'))
        use_ultra_mode = file_size > 50 * 1024 * 1024
        uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
        
        try:
            result = uploader.stream_csv_ultra_fast_pooled(csv_content, table_name)
        finally:
            uploader.close_pool()
        
        # Update database timestamp
        await update_database_timestamp(datasette, db_name)
        
        # Sync with database_tables
        try:
            portal_db = datasette.get_database('portal')
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ? AND status != 'Deleted'", [db_name]
            )
            db_record = db_result.first()
            if db_record:
                await sync_database_tables_on_upload(datasette, db_record['db_id'], table_name)
        except Exception as sync_error:
            logger.error(f"Error syncing table visibility: {sync_error}")

        # Log activity
        await log_upload_activity_enhanced(
            datasette, actor.get("id"), "sheets_upload_optimized", 
            f"Imported {result['rows_inserted']:,} rows from Google Sheets to table '{table_name}' using {result['strategy']}",
            {
                "source_type": "google_sheets_optimized",
                "table_name": table_name,
                "sheets_url": sheets_url,
                "record_count": result['rows_inserted'],
                "processing_strategy": result['strategy']
            }
        )
        
        success_msg = f"SUCCESS: Imported {result['rows_inserted']:,} rows from Google Sheets to table '{table_name}' in {result['time_elapsed']:.1f}s ({result['rows_per_second']:,} rows/sec) - {result['strategy']}"
        return create_redirect_response(request, db_name, success_msg)

    except Exception as e:
        logger.error(f"Optimized sheets upload error: {e}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "sheets_upload_optimized")
        return create_redirect_response(request, db_name, error_msg, is_error=True)
    
async def handle_url_upload_optimized(datasette, request, post_vars, db_name, actor):
    """Memory-efficient web CSV upload with streaming"""
    try:
        csv_url = post_vars.get('csv_url', '').strip()
        custom_table_name = post_vars.get('table_name', '').strip()
        encoding = post_vars.get('encoding', 'auto')
        
        if not csv_url:
            return create_redirect_response(request, db_name, "CSV URL is required", is_error=True)
        
        # Validate URL domain
        await validate_csv_url(datasette, csv_url)
        
        # Get streaming response instead of loading content
        response = await fetch_csv_from_url_stream(datasette, csv_url, encoding)
        
        # Table name handling
        if custom_table_name:
            is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                base_table_name = auto_fixed_name
            else:
                base_table_name = custom_table_name
        else:
            url_path = urlparse(csv_url).path
            filename = os.path.basename(url_path) or "web_csv"
            base_table_name = sanitize_filename_for_table(filename)
        
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        
        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        file_path = db_info['file_path'] if db_info else os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # Use optimized uploader with streaming
        max_file_size = await get_max_file_size(datasette)
        uploader = get_optimal_uploader(0, file_path, use_ultra_mode=True)  # Always use ultra mode for URL
        
        try:
            # Stream process directly from response
            result = uploader.stream_csv_ultra_fast_pooled(
                response, table_name, replace_existing=False, max_file_size=max_file_size
            )
        finally:
            # Close connection pool
            uploader.close_pool()
        
        # Update database timestamp
        await update_database_timestamp(datasette, db_name)
        
        # Sync with database_tables
        try:
            portal_db = datasette.get_database('portal')
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ? AND status != 'Deleted'", [db_name]
            )
            db_record = db_result.first()
            if db_record:
                await sync_database_tables_on_upload(datasette, db_record['db_id'], table_name)
        except Exception as sync_error:
            logger.error(f"Error syncing table visibility: {sync_error}")
        
        # Log activity
        await log_upload_activity_enhanced(
            datasette, actor.get("id"), "url_upload_optimized", 
            f"Stream imported {result['rows_inserted']:,} rows from web CSV to table '{table_name}' using {result['strategy']}",
            {
                "source_type": "web_csv_stream",
                "table_name": table_name,
                "csv_url": csv_url,
                "record_count": result['rows_inserted'],
                "processing_strategy": result['strategy']
            }
        )
        
        success_msg = f"SUCCESS: Stream imported {result['rows_inserted']:,} rows from web CSV to table '{table_name}' in {result['time_elapsed']:.1f}s ({result['rows_per_second']:,} rows/sec) - {result['strategy']}"
        return create_redirect_response(request, db_name, success_msg)
        
    except Exception as e:
        logger.error(f"Optimized web CSV upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "url_upload_optimized")
        return create_redirect_response(request, db_name, error_msg, is_error=True)

# Utility functions
async def suggest_unique_name(base_name, datasette, db_name):
    """Generate unique table name"""
    try:
        target_db = datasette.get_database(db_name)
        existing_tables = await target_db.table_names()
        
        if base_name not in existing_tables:
            return base_name
        
        counter = 1
        while f"{base_name}_{counter}" in existing_tables:
            counter += 1
        
        return f"{base_name}_{counter}"
        
    except Exception as e:
        logger.error(f"Error checking tables: {e}")
        return f"{base_name}_{uuid.uuid4().hex[:8]}"

def parse_multipart_form_data(body, boundary):
    """Simplified multipart parser using email parser"""
    try:
        headers = f'Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n'
        msg = BytesParser(policy=default).parsebytes(headers.encode() + body)
        
        forms = {}
        files = {}
        
        for part in msg.iter_parts():
            if not part.is_multipart():
                content_disposition = part.get('Content-Disposition', '')
                
                name_match = re.search(r'name="([^"]+)"', content_disposition)
                filename_match = re.search(r'filename="([^"]*)"', content_disposition)
                
                if name_match:
                    field_name = name_match.group(1)
                    content = part.get_payload(decode=True)
                    
                    if filename_match and filename_match.group(1):
                        files[field_name] = {
                            'filename': filename_match.group(1),
                            'content': content or b''
                        }
                    else:
                        forms[field_name] = content.decode('utf-8', errors='ignore') if content else ''
        
        return forms, files
        
    except Exception as e:
        logger.error(f"Multipart parsing failed: {e}")
        return {}, {}

def create_redirect_response(request, db_name, message, is_error=False):
    """Create safe redirect response"""
    try:
        param = 'error' if is_error else 'success'
        base_url = f"/upload-table/{db_name}"
        redirect_url = create_safe_redirect_url(base_url, param, message, is_error)
        return Response.redirect(redirect_url)
    except Exception as e:
        logger.error(f"Error creating redirect: {e}")
        fallback_msg = "Upload failed" if is_error else "Upload completed"
        return Response.redirect(f"/upload-table/{db_name}?error={fallback_msg}")

async def validate_csv_url(datasette, url):
    """Validate CSV URL using blocked domains list"""
    try:
        parsed = urlparse(url)
        
        if parsed.netloc.startswith('localhost') or parsed.netloc.startswith('127.0.0.1'):
            return True
        
        domain = parsed.netloc.lower()
        if await is_domain_blocked(datasette, domain):
            raise ValueError(f"Domain '{domain}' is blocked by system administrator")
        
        domain_parts = domain.split('.')
        for i in range(len(domain_parts)):
            parent_domain = '.'.join(domain_parts[i:])
            if await is_domain_blocked(datasette, parent_domain):
                raise ValueError(f"Domain '{domain}' is blocked")
        
        path_lower = parsed.path.lower()
        if not any(path_lower.endswith(ext) for ext in ['.csv', '.txt', '.tsv']):
            raise ValueError("URL must point to a CSV, TXT, or TSV file")
        
        try:
            head_response = requests.head(url, timeout=5, allow_redirects=True)
            content_length = head_response.headers.get('content-length')
            if content_length:
                size_mb = int(content_length) / (1024 * 1024)
                max_file_size = await get_max_file_size(datasette)
                max_mb = max_file_size // (1024 * 1024)
                if size_mb > max_mb:
                    raise ValueError(f"File too large ({size_mb:.1f}MB). Maximum: {max_mb}MB")
        except requests.RequestException:
            logger.warning(f"Could not check file size for {url}")
            
        return True
        
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")

# AJAX handlers
async def ajax_file_upload_handler(datasette, request):
    """AJAX-only file upload handler"""
    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required"}, status=401)

        path_parts = request.path.strip('/').split('/')
        if len(path_parts) < 2:
            return Response.json({"success": False, "error": "Invalid URL"}, status=400)
        
        db_name = path_parts[1]
        
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"success": False, "error": "Access denied"}, status=403)

        max_file_size = await get_max_file_size(datasette)
        
        return await handle_file_upload_optimized(datasette, request, db_name, actor, max_file_size)

    except Exception as e:
        logger.error(f"AJAX file upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "ajax_file_upload")
        return Response.json({"success": False, "error": error_msg}, status=500)
    
async def ajax_sheets_upload_handler(datasette, request):
    """AJAX Google Sheets upload handler with enhanced error handling and validation"""
    try:
        # Authentication check
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required"}, status=401)

        # Extract database name from URL
        path_parts = request.path.strip('/').split('/')
        if len(path_parts) < 2:
            return Response.json({"success": False, "error": "Invalid URL format"}, status=400)
        
        db_name = path_parts[1]
        
        # Authorization check
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"success": False, "error": "Access denied"}, status=403)

        # Parse form data from AJAX request
        content_type = request.headers.get('content-type', '')
        body = await request.post_body()
        
        forms, files = parse_multipart_form_data_from_ajax(body, content_type)
        
        # Extract form parameters
        sheets_url = forms.get('sheets_url', '').strip()
        sheet_index = int(forms.get('sheet_index', '0') or '0')
        custom_table_name = forms.get('table_name', '').strip()
        
        # Validate required parameters
        if not sheets_url:
            return Response.json({"success": False, "error": "Google Sheets URL is required"}, status=400)
        
        # Enhanced URL validation
        valid_domains = ['docs.google.com/spreadsheets/', 'drive.google.com/file/']
        if not any(domain in sheets_url.lower() for domain in valid_domains):
            return Response.json({
                "success": False, 
                "error": "Please enter a valid Google Sheets URL. Use the Share link from your Google Sheet."
            }, status=400)

        # Process Google Sheets import with enhanced error handling
        try:
            logger.info(f"Starting Google Sheets import from: {sheets_url}")
            csv_content = await fetch_sheet_data(sheets_url, sheet_index, datasette)
            
        except ValueError as sheet_error:
            error_msg = str(sheet_error)
            logger.error(f"Google Sheets fetch error: {error_msg}")
            
            # Enhanced user-friendly error messages
            if "Invalid Google Sheets URL format" in error_msg:
                user_msg = "Invalid Google Sheets URL. Please use the sharing link from your Google Sheet."
            elif "not publicly accessible" in error_msg or "private" in error_msg.lower() or "access denied" in error_msg.lower():
                user_msg = "This Google Sheet is private. To fix this:\n1. Open your Google Sheet\n2. Click 'Share' (top right)\n3. Change to 'Anyone with the link can view'\n4. Copy the new link and try again"
            elif "too large" in error_msg:
                user_msg = error_msg  # Keep the detailed size error
            elif "empty" in error_msg:
                user_msg = "The Google Sheet appears to be empty. Please check that it contains data."
            elif "not found" in error_msg or "404" in error_msg:
                user_msg = "Google Sheet not found. Please check the URL and make sure the sheet exists."
            elif "timeout" in error_msg.lower() or "network" in error_msg.lower():
                user_msg = "Network timeout while accessing Google Sheets. Please try again."
            else:
                user_msg = f"Failed to import from Google Sheets: {error_msg}"
            
            return Response.json({"success": False, "error": user_msg}, status=400)
        
        except Exception as unexpected_error:
            logger.error(f"Unexpected error during Google Sheets fetch: {str(unexpected_error)}")
            return Response.json({
                "success": False, 
                "error": f"Unexpected error accessing Google Sheet: {str(unexpected_error)}"
            }, status=500)
        
        # Handle table name generation
        if custom_table_name:
            is_valid, validation_error = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                base_table_name = auto_fixed_name
                logger.info(f"Auto-fixed table name from '{custom_table_name}' to '{auto_fixed_name}'")
            else:
                base_table_name = custom_table_name
        else:
            # Generate default table name based on sheet index
            if sheet_index > 0:
                base_table_name = f"google_sheet_{sheet_index}"
            else:
                base_table_name = "google_sheet"
        
        # Ensure unique table name
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        logger.info(f"Using table name: {table_name}")
        
        # Get database file path
        portal_db = datasette.get_database('portal')
        try:
            result = await portal_db.execute(
                "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor["id"]]
            )
            db_info = result.first()
            
            if not db_info:
                return Response.json({"success": False, "error": "Database not found"}, status=404)
            
            file_path = db_info['file_path'] or os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
            
        except Exception as db_error:
            logger.error(f"Database lookup error: {str(db_error)}")
            return Response.json({"success": False, "error": "Database access error"}, status=500)
        
        # Process with optimized uploader
        file_size = len(csv_content.encode('utf-8'))
        file_size_mb = file_size / (1024 * 1024)
        use_ultra_mode = file_size > 50 * 1024 * 1024
        
        logger.info(f"Processing Google Sheets data: {file_size_mb:.1f}MB, ultra_mode: {use_ultra_mode}")
        
        uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
        
        try:
            # Process the CSV content with optimized uploader
            upload_result = uploader.stream_csv_ultra_fast_pooled(csv_content, table_name)
            logger.info(f"Upload completed: {upload_result['rows_inserted']:,} rows in {upload_result['time_elapsed']:.1f}s")
            
        except Exception as upload_error:
            logger.error(f"Upload processing error: {str(upload_error)}")
            return Response.json({
                "success": False, 
                "error": f"Failed to process data: {str(upload_error)}"
            }, status=500)
            
        finally:
            # Always close the connection pool
            try:
                uploader.close_pool()
            except Exception as close_error:
                logger.warning(f"Error closing connection pool: {str(close_error)}")
        
        # Update database timestamp
        try:
            await update_database_timestamp(datasette, db_name)
        except Exception as timestamp_error:
            logger.warning(f"Failed to update database timestamp: {str(timestamp_error)}")

        # Sync with database_tables for visibility management
        try:
            portal_db = datasette.get_database('portal')
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ? AND status != 'Deleted'", [db_name]
            )
            db_record = db_result.first()
            if db_record:
                await sync_database_tables_on_upload(datasette, db_record['db_id'], table_name)
                logger.info(f"Synced table '{table_name}' visibility for database {db_record['db_id']}")
        except Exception as sync_error:
            logger.error(f"Error syncing table visibility: {str(sync_error)}")
            # Don't fail the request for sync errors
        
        # Log upload activity for audit trail
        try:
            await log_upload_activity_enhanced(
                datasette, 
                actor.get("id"), 
                "ajax_sheets_upload_optimized", 
                f"AJAX: Imported {upload_result['rows_inserted']:,} rows from Google Sheets to table '{table_name}' using {upload_result['strategy']}",
                {
                    "source_type": "google_sheets_ajax_optimized",
                    "table_name": table_name,
                    "sheets_url": sheets_url,
                    "sheet_index": sheet_index,
                    "record_count": upload_result['rows_inserted'],
                    "processing_strategy": upload_result['strategy'],
                    "file_size_mb": file_size_mb,
                    "processing_time": upload_result['time_elapsed']
                }
            )
        except Exception as log_error:
            logger.warning(f"Failed to log upload activity: {str(log_error)}")
        
        # Prepare success response
        success_msg = f"SUCCESS: Imported {upload_result['rows_inserted']:,} rows from Google Sheets to table '{table_name}' in {upload_result['time_elapsed']:.1f}s ({upload_result['rows_per_second']:,} rows/sec) - {upload_result['strategy']}"
        
        logger.info(f"Google Sheets import completed successfully: {success_msg}")
        
        return Response.json({
            "success": True,
            "message": success_msg,
            "redirect_url": "/manage-databases",
            "stats": {
                "rows": upload_result['rows_inserted'],
                "columns": upload_result.get('columns', 0),
                "time": upload_result['time_elapsed'],
                "speed": upload_result['rows_per_second'],
                "strategy": upload_result['strategy'],
                "file_size_mb": file_size_mb,
                "table_name": table_name
            },
            "table_info": {
                "name": table_name,
                "database": db_name,
                "source": "google_sheets"
            }
        })
        
    except Exception as e:
        # Catch-all error handler
        logger.error(f"AJAX sheets upload handler error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "ajax_sheets_upload_optimized")
        
        return Response.json({
            "success": False, 
            "error": f"Upload failed: {error_msg}"
        }, status=500)
    
async def enhanced_size_validation_and_estimation(csv_url, max_file_size, headers, datasette=None):
    """Enhanced size validation with multiple estimation methods and user-friendly messages"""
    max_size_mb = max_file_size / (1024 * 1024)
    size_info = {
        'estimated_size': None,
        'confidence': 'unknown',
        'method': 'none',
        'can_proceed': False,
        'warning_message': None,
        'error_message': None
    }
    
    try:
        logger.info(f"Starting size validation for: {csv_url}")
        logger.info(f"Maximum allowed size: {max_size_mb:.0f}MB")
        
        # Method 1: Standard HEAD request
        try:
            head_response = requests.head(csv_url, headers=headers, allow_redirects=True, timeout=10)
            
            if head_response.status_code == 200:
                content_length = head_response.headers.get('content-length')
                if content_length:
                    try:
                        size_bytes = int(content_length)
                        size_mb = size_bytes / (1024 * 1024)
                        
                        size_info.update({
                            'estimated_size': size_bytes,
                            'confidence': 'high',
                            'method': 'content-length',
                            'can_proceed': size_bytes <= max_file_size
                        })
                        
                        if size_bytes > max_file_size:
                            size_info['error_message'] = (
                                f"File is too large ({size_mb:.1f}MB). "
                                f"Maximum allowed size is {max_size_mb:.0f}MB. "
                                f"Please try a smaller file or contact your administrator to increase the limit."
                            )
                        else:
                            logger.info(f"Size check passed: {size_mb:.1f}MB via content-length")
                            
                        return size_info
                        
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid content-length header: {content_length}")
        
        except requests.RequestException as e:
            logger.warning(f"HEAD request failed: {e}")
        
        # Method 2: Partial download estimation
        try:
            logger.info("Attempting partial download for size estimation")
            
            # Download first 1MB to estimate compression ratio and structure
            sample_headers = {**headers, 'Range': 'bytes=0-1048575'}  # First 1MB
            sample_response = requests.get(csv_url, headers=sample_headers, timeout=15, stream=True)
            
            if sample_response.status_code in [200, 206]:  # 206 = Partial Content
                sample_data = b''
                downloaded = 0
                
                for chunk in sample_response.iter_content(chunk_size=8192):
                    if chunk:
                        sample_data += chunk
                        downloaded += len(chunk)
                        if downloaded >= 1024 * 1024:  # 1MB sample
                            break
                
                if downloaded > 0:
                    # Analyze sample for estimation
                    try:
                        # Try to decode and count lines in sample
                        sample_text = sample_data.decode('utf-8-sig', errors='ignore')
                        sample_lines = sample_text.count('\n')
                        
                        if sample_lines > 10:  # Meaningful sample
                            # Estimate based on average line length
                            avg_line_length = len(sample_text) / sample_lines
                            
                            # Make conservative estimates
                            if avg_line_length < 100:
                                # Short lines, likely small to medium dataset
                                estimated_total_lines = sample_lines * 10  # Conservative multiplier
                            else:
                                # Long lines, likely larger dataset
                                estimated_total_lines = sample_lines * 5
                            
                            estimated_size = int(estimated_total_lines * avg_line_length)
                            estimated_mb = estimated_size / (1024 * 1024)
                            
                            size_info.update({
                                'estimated_size': estimated_size,
                                'confidence': 'medium',
                                'method': 'partial_sampling',
                                'can_proceed': estimated_size <= max_file_size * 1.2  # Add 20% buffer
                            })
                            
                            if estimated_size > max_file_size:
                                size_info['error_message'] = (
                                    f"File appears to be approximately {estimated_mb:.1f}MB (estimated from sample). "
                                    f"Maximum allowed size is {max_size_mb:.0f}MB. "
                                    f"This estimate may not be exact, but the file is likely too large."
                                )
                            else:
                                size_info['warning_message'] = (
                                    f"Estimated file size: ~{estimated_mb:.1f}MB (based on sample analysis). "
                                    f"Actual size may vary. Processing will be monitored during download."
                                )
                                
                            logger.info(f"Estimated size via sampling: ~{estimated_mb:.1f}MB")
                            return size_info
                            
                    except Exception as analysis_error:
                        logger.warning(f"Sample analysis failed: {analysis_error}")
                        
        except requests.RequestException as e:
            logger.warning(f"Partial download failed: {e}")
        
        # Method 3: Domain-based estimation
        parsed_url = urlparse(csv_url)
        domain = parsed_url.netloc.lower()
        
        # Known patterns for common data sources
        size_hints = {
            'data.cityofnewyork.us': {'typical_size': '5-50MB', 'max_likely': 100},
            'data.wa.gov': {'typical_size': '10-100MB', 'max_likely': 200},
            'data.gov': {'typical_size': '1-20MB', 'max_likely': 50},
            'github.com': {'typical_size': '1-10MB', 'max_likely': 25},
            'githubusercontent.com': {'typical_size': '1-10MB', 'max_likely': 25}
        }
        
        for known_domain, info in size_hints.items():
            if known_domain in domain:
                max_likely_mb = info['max_likely']
                
                size_info.update({
                    'estimated_size': None,
                    'confidence': 'low',
                    'method': 'domain_heuristic',
                    'can_proceed': max_likely_mb <= max_size_mb
                })
                
                if max_likely_mb > max_size_mb:
                    size_info['error_message'] = (
                        f"Files from {domain} typically range {info['typical_size']} "
                        f"which may exceed your {max_size_mb:.0f}MB limit. "
                        f"Consider requesting a size limit increase from your administrator."
                    )
                else:
                    size_info['warning_message'] = (
                        f"Files from {domain} typically range {info['typical_size']}. "
                        f"Download will be monitored and stopped if it exceeds {max_size_mb:.0f}MB."
                    )
                    
                logger.info(f"Domain-based estimation for {domain}: {info['typical_size']}")
                return size_info
        
        # Method 4: Fallback - allow with warning
        size_info.update({
            'estimated_size': None,
            'confidence': 'unknown',
            'method': 'fallback',
            'can_proceed': True,
            'warning_message': (
                f"Could not determine file size in advance. "
                f"Download will be monitored and stopped if it exceeds {max_size_mb:.0f}MB. "
                f"Large files may take several minutes to process."
            )
        })
        
        logger.info("Using fallback approach - size monitoring during download")
        return size_info
        
    except Exception as e:
        logger.error(f"Size validation failed: {str(e)}")
        
        # Error fallback
        size_info.update({
            'estimated_size': None,
            'confidence': 'unknown',
            'method': 'error_fallback',
            'can_proceed': True,
            'warning_message': (
                f"Size validation encountered an error. "
                f"Download will proceed with monitoring (max {max_size_mb:.0f}MB). "
                f"Please ensure your file is not too large."
            )
        })
        
        return size_info

async def ajax_url_upload_handler(datasette, request):
    """Enhanced URL upload with better size estimation and user messages"""
    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required"}, status=401)

        path_parts = request.path.strip('/').split('/')
        db_name = path_parts[1]
        
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"success": False, "error": "Access denied"}, status=403)

        # Parse form data
        content_type = request.headers.get('content-type', '')
        body = await request.post_body()
        forms, files = parse_multipart_form_data_from_ajax(body, content_type)
        
        csv_url = forms.get('csv_url', '').strip()
        if not csv_url:
            return Response.json({"success": False, "error": "CSV URL is required"}, status=400)

        custom_table_name = forms.get('table_name', '').strip()
        encoding = forms.get('encoding', 'auto')
        
        # Enhanced size validation with user-friendly messages
        try:
            await validate_csv_url(datasette, csv_url)
            
            headers = {
                'User-Agent': 'EDGI-Portal/1.0 (Environmental Data Portal)',
                'Accept': 'text/csv, text/plain, application/csv, */*'
            }
            
            max_file_size = await get_max_file_size(datasette)
            
            # ENHANCED: Comprehensive size validation
            size_info = await enhanced_size_validation_and_estimation(
                csv_url, max_file_size, headers, datasette
            )
            
            # Handle size validation results
            if size_info['error_message']:
                return Response.json({
                    "success": False, 
                    "error": size_info['error_message']
                }, status=400)
            
            # If we have a warning, we'll include it in the success response
            warning_message = size_info.get('warning_message')
            
            logger.info(f"Size validation result: {size_info['method']} - {size_info['confidence']} confidence")
            
        except ValueError as validation_error:
            return Response.json({
                "success": False, 
                "error": str(validation_error)
            }, status=400)

        # Process URL upload with streaming
        response = await fetch_csv_from_url_stream(datasette, csv_url, encoding)
        
        # Handle table name
        if custom_table_name:
            is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                base_table_name = auto_fixed_name
            else:
                base_table_name = custom_table_name
        else:
            url_path = urlparse(csv_url).path
            filename = os.path.basename(url_path) or "web_csv"
            base_table_name = sanitize_filename_for_table(filename)
        
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        
        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        if not db_info:
            return Response.json({"success": False, "error": "Database not found"}, status=404)
        
        file_path = db_info['file_path'] or os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # Process with streaming uploader
        uploader = get_optimal_uploader(0, file_path, use_ultra_mode=True)
        
        try:
            upload_result = uploader.stream_csv_ultra_fast_pooled(
                response, table_name, replace_existing=False, max_file_size=max_file_size
            )
        except Exception as processing_error:
            error_str = str(processing_error)
            if "exceeds size limit" in error_str or "File size limit reached" in error_str:
                # Extract actual size from error message if possible
                size_match = re.search(r'(\d+\.?\d*)\s*MB', error_str)
                actual_size = size_match.group(1) if size_match else "unknown"
                max_size_mb = max_file_size / (1024 * 1024)
                
                user_friendly_error = (
                    f"File size limit exceeded during download. "
                    f"The file was larger than the {max_size_mb:.0f}MB limit"
                )
                if actual_size != "unknown":
                    user_friendly_error += f" (approximately {actual_size}MB)"
                user_friendly_error += ". Please try a smaller file or contact your administrator to increase the size limit."
                
                return Response.json({
                    "success": False, 
                    "error": user_friendly_error
                }, status=400)
            else:
                raise processing_error
                
        finally:
            uploader.close_pool()
        
        # Update database and log
        await update_database_timestamp(datasette, db_name)
        
        # Sync with database_tables
        try:
            portal_db = datasette.get_database('portal')
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ? AND status != 'Deleted'", [db_name]
            )
            db_record = db_result.first()
            if db_record:
                await sync_database_tables_on_upload(datasette, db_record['db_id'], table_name)
        except Exception as sync_error:
            logger.error(f"Error syncing table visibility: {sync_error}")
        
        await log_upload_activity_enhanced(
            datasette, actor.get("id"), "ajax_url_upload_enhanced", 
            f"Enhanced stream import: {upload_result['rows_inserted']:,} rows from web CSV to table '{table_name}'",
            {
                "source_type": "web_csv_stream_enhanced",
                "table_name": table_name,
                "csv_url": csv_url,
                "record_count": upload_result['rows_inserted'],
                "processing_strategy": upload_result['strategy'],
                "size_estimation_method": size_info['method']
            }
        )
        
        # Prepare success message
        success_msg = f"SUCCESS: Stream imported {upload_result['rows_inserted']:,} rows from web CSV to table '{table_name}' in {upload_result['time_elapsed']:.1f}s ({upload_result['rows_per_second']:,} rows/sec) - {upload_result['strategy']}"
        
        # Include warning if we had size estimation issues
        if warning_message:
            success_msg += f" (Note: {warning_message})"
        
        return Response.json({
            "success": True,
            "message": success_msg,
            "redirect_url": "/manage-databases",
            "stats": {
                "rows": upload_result['rows_inserted'],
                "time": upload_result['time_elapsed'],
                "speed": upload_result['rows_per_second'],
                "strategy": upload_result['strategy']
            }
        })
            
    except Exception as e:
        logger.error(f"Enhanced AJAX URL upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "ajax_url_upload_enhanced")
        return Response.json({"success": False, "error": error_msg}, status=500)
    
def parse_multipart_form_data_from_ajax(body, content_type):
    """Parse multipart form data from AJAX requests"""
    try:
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
        
        if not boundary:
            return {}, {}
        
        forms, files = parse_multipart_form_data(body, boundary)
        
        processed_forms = {}
        for key, value in forms.items():
            if isinstance(value, list) and len(value) > 0:
                processed_forms[key] = value[0]
            else:
                processed_forms[key] = value if isinstance(value, str) else str(value)
        
        return processed_forms, files
        
    except Exception as e:
        logger.error(f"Error parsing multipart data from AJAX: {e}")
        return {}, {}

@hookimpl
def register_routes():
    """Register ALL upload routes with optimized handlers"""
    return [
        (r"^/upload-table/([^/]+)$", enhanced_upload_page),
        (r"^/ajax-upload-file/([^/]+)$", ajax_file_upload_handler),
        (r"^/ajax-upload-sheets/([^/]+)$", ajax_sheets_upload_handler),
        (r"^/ajax-upload-url/([^/]+)$", ajax_url_upload_handler),
    ]