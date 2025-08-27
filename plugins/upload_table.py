"""
Ultra-High Performance Upload Module - Optimized for 200MB+ files
Integrates ultra-optimized SQLite performance improvements
Target: 150,000+ rows/sec (2.5x faster than previous version)
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
import urllib.parse
import psutil
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from email.parser import BytesParser
from email.policy import default
from contextlib import contextmanager
from typing import Iterator, Tuple, List, Dict, Any, Optional

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
    get_portal_content,
    get_max_file_size,
    user_owns_database,
    get_success_error_from_request,
    update_database_timestamp,
    DATA_DIR,
    is_domain_blocked,
    sync_database_tables_on_upload,
    get_system_settings,
    create_safe_redirect_url,
    handle_upload_error_gracefully,
    log_upload_activity_enhanced,
)

logger = logging.getLogger(__name__)


class UltraOptimizedUploader:
    """
    Ultra-high performance SQLite uploader targeting 150,000+ rows/sec
    Implements aggressive optimizations based on SQLite performance research
    """
    
    # AGGRESSIVE SQLite optimization settings for maximum speed with improved safety
    ULTRA_PRAGMAS = [
        "PRAGMA synchronous = NORMAL",        # Safer than OFF, still very fast
        "PRAGMA journal_mode = WAL",          # WAL mode instead of OFF - crash protection
        "PRAGMA cache_size = -2000000",       # 2GB cache (negative = KB)
        "PRAGMA temp_store = MEMORY",         # Memory for temp storage
        "PRAGMA mmap_size = 536870912",       # 512MB memory-mapped I/O
        "PRAGMA page_size = 65536",           # Larger page size for bulk ops
        "PRAGMA locking_mode = EXCLUSIVE",    # Exclusive lock mode
        "PRAGMA count_changes = OFF",         # Disable row counting
        "PRAGMA auto_vacuum = NONE",          # Disable auto vacuum during inserts
    ]
    
    # Conservative SQLite settings (safer but still very fast)
    SAFE_PRAGMAS = [
        "PRAGMA synchronous = NORMAL",        # Safer sync mode
        "PRAGMA journal_mode = WAL",          # WAL mode for concurrency
        "PRAGMA cache_size = -1000000",       # 1GB cache
        "PRAGMA temp_store = MEMORY",
        "PRAGMA mmap_size = 268435456",       # 256MB memory-mapped I/O
        "PRAGMA optimize",                    # Enable query optimization
    ]
    
    # Ultra-optimized batch sizes
    ULTRA_BATCH_SIZE = 50000              # Larger batches for fewer transactions
    MEGA_BATCH_SIZE = 100000              # For very large files
    
    def __init__(self, db_path: str, ultra_mode: bool = False):
        """
        Initialize with ultra or safe mode
        ultra_mode: True for maximum speed (risky), False for safe optimization
        """
        self.db_path = db_path
        self.ultra_mode = ultra_mode
        self.pragmas = self.ULTRA_PRAGMAS if ultra_mode else self.SAFE_PRAGMAS
        
    @contextmanager
    def ultra_optimized_connection(self):
        """Create ultra-optimized connection with aggressive settings"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)  # Add timeout
        
        # Disable automatic transactions for manual control
        conn.isolation_level = None
        
        try:
            # Apply performance pragmas
            for pragma in self.pragmas:
                try:
                    conn.execute(pragma)
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e):
                        logger.warning(f"Skipping pragma due to lock: {pragma}")
                        continue
                    raise
            
            yield conn
            
        finally:
            # CRITICAL: Restore safe settings and release locks before closing
            try:
                if self.ultra_mode:
                    conn.execute("PRAGMA locking_mode = NORMAL")  # Release exclusive lock
                    conn.execute("PRAGMA synchronous = NORMAL")
                    conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA optimize")  # Cleanup
            except sqlite3.OperationalError:
                pass  # Ignore errors during cleanup
            finally:
                conn.close()
    
    def stream_csv_ultra_fast(self, file_content: str, table_name: str, 
                             replace_existing: bool = False) -> Dict[str, Any]:
        """
        Ultra-fast CSV streaming with maximum performance optimizations
        Target: 150,000+ rows/sec
        """
        start_time = time.time()
        
        # Parse headers efficiently
        first_line_end = file_content.find('\n')
        if first_line_end == -1:
            raise ValueError("Invalid CSV - no line breaks found")
        
        header_line = file_content[:first_line_end]
        headers = [self._clean_column_name(h.strip().strip('"\'')) 
                  for h in header_line.split(',')]
        
        # Skip header for data processing
        data_start = first_line_end + 1
        
        with self.ultra_optimized_connection() as conn:
            # Handle existing table
            if replace_existing:
                conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
            
            # Create table without indexes initially
            columns = ', '.join([f'[{header}] TEXT' for header in headers])
            conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
            
            # Prepare optimized insert statement
            placeholders = ','.join(['?' for _ in headers])
            insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
            
            # Determine optimal batch size based on file size
            file_size = len(file_content)
            if file_size > 200 * 1024 * 1024:  # >200MB
                batch_size = self.MEGA_BATCH_SIZE
            elif file_size > 50 * 1024 * 1024:   # >50MB
                batch_size = self.ULTRA_BATCH_SIZE
            else:
                batch_size = 25000
            
            logger.info(f"ULTRA MODE: Using batch size: {batch_size:,} for file size: {file_size:,} bytes")
            
            # Manual transaction control for maximum performance
            conn.execute("BEGIN IMMEDIATE")
            
            try:
                # Process CSV data with optimized parsing
                total_rows = self._process_csv_data_ultra_fast(
                    conn, file_content[data_start:], insert_sql, 
                    headers, batch_size
                )
                
                # Commit single large transaction
                conn.execute("COMMIT")
                
                # Create indexes after all data is inserted (much faster)
                self._create_optimized_indexes(conn, table_name, headers)
                
            except Exception as e:
                conn.execute("ROLLBACK")
                raise Exception(f"Ultra-fast insert failed: {str(e)}")
        
        elapsed_time = time.time() - start_time
        rows_per_second = int(total_rows / elapsed_time) if elapsed_time > 0 else 0
        
        logger.info(f"ULTRA-FAST COMPLETE: {total_rows:,} rows in {elapsed_time:.2f}s = {rows_per_second:,} rows/sec")
        
        return {
            'table_name': table_name,
            'rows_inserted': total_rows,
            'columns': len(headers),
            'time_elapsed': elapsed_time,
            'rows_per_second': rows_per_second,
            'strategy': 'ultra_streaming',
            'batch_size': batch_size,
            'ultra_mode': self.ultra_mode
        }
    
    def _process_csv_data_ultra_fast(self, conn: sqlite3.Connection, 
                                   csv_data: str, insert_sql: str,
                                   headers: List[str], batch_size: int) -> int:
        """
        Ultra-fast CSV data processing with minimal overhead
        Uses string operations instead of csv.reader for maximum speed
        """
        total_rows = 0
        batch_data = []
        num_columns = len(headers)
        
        # Process lines directly without CSV reader overhead
        for line_num, line in enumerate(csv_data.split('\n')):
            if not line.strip():  # Skip empty lines
                continue
                
            # Fast CSV parsing (simple comma splitting)
            # Note: This assumes no escaped commas in data
            row_data = [cell.strip().strip('"\'') for cell in line.split(',')]
            
            # Pad or truncate to match column count
            if len(row_data) < num_columns:
                row_data.extend([''] * (num_columns - len(row_data)))
            elif len(row_data) > num_columns:
                row_data = row_data[:num_columns]
            
            batch_data.append(tuple(row_data))
            
            # Execute batch when size reached
            if len(batch_data) >= batch_size:
                conn.executemany(insert_sql, batch_data)
                total_rows += len(batch_data)
                batch_data.clear()
                
                # Progress logging for large files
                if total_rows % (batch_size * 5) == 0:
                    logger.info(f"ULTRA: Processed {total_rows:,} rows")
        
        # Insert remaining rows
        if batch_data:
            conn.executemany(insert_sql, batch_data)
            total_rows += len(batch_data)
        
        return total_rows
    
    def process_excel_ultra_fast(self, file_content: bytes, table_name: str,
                                sheet_name: str = None, replace_existing: bool = False) -> Dict[str, Any]:
        """Excel processing with ultra-fast SQLite operations"""
        start_time = time.time()
        
        # Determine optimal chunk size based on file size
        file_size = len(file_content)
        if file_size > 100 * 1024 * 1024:  # 100MB+
            chunk_size = 10000
        elif file_size > 50 * 1024 * 1024:   # 50MB+
            chunk_size = 20000
        else:
            chunk_size = 25000
        
        total_rows = 0
        
        with self.ultra_optimized_connection() as conn:
            # Handle existing table
            if replace_existing:
                conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
            
            # Read Excel in chunks
            excel_file = pd.ExcelFile(io.BytesIO(file_content))
            sheet_name = sheet_name or excel_file.sheet_names[0]
            
            # Get headers from first row
            temp_df = pd.read_excel(excel_file, sheet_name=sheet_name, nrows=1)
            headers = [self._clean_column_name(col) for col in temp_df.columns]
            
            # Create table without indexes initially
            columns = ', '.join([f'[{header}] TEXT' for header in headers])
            conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
            
            # Manual transaction control
            conn.execute("BEGIN IMMEDIATE")
            
            try:
                # Process in chunks with ultra-fast settings
                for chunk_df in pd.read_excel(excel_file, sheet_name=sheet_name, chunksize=chunk_size):
                    # Clean column names
                    chunk_df.columns = headers
                    
                    # Convert data types for SQLite compatibility
                    chunk_df = self._optimize_dataframe_types(chunk_df)
                    
                    # Convert to records and batch insert
                    records = [tuple(row) for row in chunk_df.values]
                    placeholders = ','.join(['?' for _ in headers])
                    insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
                    
                    conn.executemany(insert_sql, records)
                    total_rows += len(records)
                    
                    if total_rows % (chunk_size * 3) == 0:
                        logger.info(f"EXCEL ULTRA: Processed {total_rows:,} rows")
                
                conn.execute("COMMIT")
                self._create_optimized_indexes(conn, table_name, headers)
                
            except Exception as e:
                conn.execute("ROLLBACK")
                raise Exception(f"Excel ultra processing failed: {str(e)}")
        
        elapsed_time = time.time() - start_time
        rows_per_second = int(total_rows / elapsed_time) if elapsed_time > 0 else 0
        
        logger.info(f"EXCEL ULTRA COMPLETE: {total_rows:,} rows in {elapsed_time:.2f}s = {rows_per_second:,} rows/sec")
        
        return {
            'table_name': table_name,
            'rows_inserted': total_rows,
            'columns': len(headers),
            'time_elapsed': elapsed_time,
            'rows_per_second': rows_per_second,
            'strategy': 'excel_ultra'
        }
    
    def _create_optimized_indexes(self, conn: sqlite3.Connection, 
                                table_name: str, headers: List[str]):
        """Create minimal indexes after data insertion"""
        # Only create index on first column (likely primary key)
        if headers:
            try:
                index_sql = f"CREATE INDEX IF NOT EXISTS idx_{table_name}_main ON [{table_name}] ([{headers[0]}])"
                conn.execute(index_sql)
            except Exception as e:
                logger.warning(f"Could not create index: {e}")
    
    def _clean_column_name(self, name: str) -> str:
        """Fast column name cleaning"""
        # Basic cleaning - remove non-alphanumeric except underscore
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', str(name).strip())
        
        # Ensure starts with letter/underscore
        if clean_name and not clean_name[0].isalpha() and clean_name[0] != '_':
            clean_name = 'col_' + clean_name
        
        return clean_name[:64] or 'column'
    
    def _optimize_dataframe_types(self, df: pd.DataFrame) -> pd.DataFrame:
        """Optimize pandas DataFrame for SQLite insertion"""
        for col in df.columns:
            # Convert datetime objects to strings
            if df[col].dtype == 'datetime64[ns]':
                df[col] = df[col].astype(str)
            # Handle NaN values
            elif df[col].dtype == 'object':
                df[col] = df[col].fillna('')
            # Replace inf values in numeric columns
            elif df[col].dtype in ['float64', 'float32']:
                df[col] = df[col].replace([np.inf, -np.inf], None)
        return df


class RobustCSVProcessor:
    """
    Robust CSV processor with optimized performance
    Handles complex CSV files correctly while maintaining speed
    Target: 80,000-120,000 rows/sec
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def process_csv_robust_fast(self, file_content: str, table_name: str,
                               replace_existing: bool = False) -> Dict[str, Any]:
        """Process CSV with proper parsing but optimized for performance"""
        start_time = time.time()
        
        # Use optimized CSV reader
        csv_file = io.StringIO(file_content)
        reader = csv.reader(csv_file, delimiter=',', quotechar='"')
        headers = [self._clean_column_name(h) for h in next(reader)]
        
        # Reset for data reading
        csv_file.seek(0)
        reader = csv.reader(csv_file, delimiter=',', quotechar='"')
        next(reader)  # Skip header row
        
        with sqlite3.connect(self.db_path) as conn:
            # Apply performance pragmas
            conn.isolation_level = None  # Manual transaction control
            
            pragmas = [
                "PRAGMA synchronous = NORMAL",
                "PRAGMA journal_mode = WAL", 
                "PRAGMA cache_size = -1000000",  # 1GB cache
                "PRAGMA temp_store = MEMORY",
                "PRAGMA mmap_size = 268435456",  # 256MB mmap
            ]
            
            for pragma in pragmas:
                conn.execute(pragma)
            
            # Handle existing table
            if replace_existing:
                conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
            
            # Create table
            columns = ', '.join([f'[{header}] TEXT' for header in headers])
            conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
            
            # Optimized batch processing
            insert_sql = f"INSERT INTO [{table_name}] VALUES ({','.join(['?' for _ in headers])})"
            
            batch_size = 30000  # Optimal for robust processing
            batch_data = []
            total_rows = 0
            
            # Single transaction for all data
            conn.execute("BEGIN IMMEDIATE")
            
            try:
                for row in reader:
                    # Process row to match column count
                    processed_row = self._process_row(row, len(headers))
                    batch_data.append(processed_row)
                    
                    if len(batch_data) >= batch_size:
                        conn.executemany(insert_sql, batch_data)
                        total_rows += len(batch_data)
                        batch_data.clear()
                        
                        if total_rows % (batch_size * 4) == 0:
                            logger.info(f"ROBUST: Processed {total_rows:,} rows")
                
                # Insert remaining rows
                if batch_data:
                    conn.executemany(insert_sql, batch_data)
                    total_rows += len(batch_data)
                
                conn.execute("COMMIT")
                
            except Exception as e:
                conn.execute("ROLLBACK")
                raise Exception(f"Robust processing failed: {str(e)}")
        
        elapsed_time = time.time() - start_time
        rows_per_second = int(total_rows / elapsed_time) if elapsed_time > 0 else 0
        
        logger.info(f"ROBUST COMPLETE: {total_rows:,} rows in {elapsed_time:.2f}s = {rows_per_second:,} rows/sec")
        
        return {
            'table_name': table_name,
            'rows_inserted': total_rows,
            'columns': len(headers),
            'time_elapsed': elapsed_time,
            'rows_per_second': rows_per_second,
            'strategy': 'robust_optimized'
        }
    
    def _process_row(self, row: List[str], expected_length: int) -> List[str]:
        """Process row to match expected column count"""
        if len(row) < expected_length:
            row.extend([''] * (expected_length - len(row)))
        elif len(row) > expected_length:
            row = row[:expected_length]
        return [str(cell) for cell in row]
    
    def _clean_column_name(self, name: str) -> str:
        """Clean column name for SQLite"""
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', str(name).strip())
        if clean_name and not clean_name[0].isalpha() and clean_name[0] != '_':
            clean_name = 'col_' + clean_name
        return clean_name[:64] or 'column'


def get_optimal_uploader(file_size: int, db_path: str, use_ultra_mode: bool = False):
    """
    Choose optimal uploader with lock detection
    use_ultra_mode: True for maximum speed (some risk), False for safe optimization
    """
    
    # Test if database is locked before choosing ultra mode
    if use_ultra_mode and file_size > 50 * 1024 * 1024:
        try:
            # Test exclusive lock availability
            test_conn = sqlite3.connect(db_path, timeout=5.0)
            test_conn.execute("PRAGMA locking_mode = EXCLUSIVE")
            test_conn.execute("SELECT 1")  # Test if we can actually use it
            test_conn.execute("PRAGMA locking_mode = NORMAL")  # Release immediately
            test_conn.close()
            
            logger.debug("Database lock test passed, using ultra mode")
            return UltraOptimizedUploader(db_path, ultra_mode=True)
            
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                logger.warning("Database locked, falling back to robust processor")
                return RobustCSVProcessor(db_path)
            raise
    
    # Original logic for other cases
    if file_size > 50 * 1024 * 1024:
        return UltraOptimizedUploader(db_path, ultra_mode=use_ultra_mode)
    else:
        return RobustCSVProcessor(db_path)

def monitor_performance_detailed(func):
    """Enhanced performance monitoring with detailed metrics for both sync and async functions"""
    import asyncio
    import functools
    
    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            process = psutil.Process(os.getpid())
            
            # Before metrics
            start_memory = process.memory_info().rss / 1024 / 1024  # MB
            start_cpu_times = process.cpu_times()
            start_time = time.time()
            
            # Execute the async function
            result = await func(*args, **kwargs)
            
            # After metrics
            end_time = time.time()
            end_memory = process.memory_info().rss / 1024 / 1024  # MB
            end_cpu_times = process.cpu_times()
            
            # Calculate detailed metrics
            total_time = end_time - start_time
            memory_delta = end_memory - start_memory
            cpu_time = (end_cpu_times.user - start_cpu_times.user) + (end_cpu_times.system - start_cpu_times.system)
            cpu_efficiency = (cpu_time / total_time * 100) if total_time > 0 else 0
            
            # For async functions that return Response objects, log separately
            # since we can't modify the Response object easily
            logger.info(f"ASYNC PERFORMANCE SUMMARY:")
            logger.info(f"  Function: {func.__name__}")
            logger.info(f"  Total Time: {total_time:.2f}s")
            logger.info(f"  Memory Delta: {memory_delta:.1f}MB")
            logger.info(f"  CPU Time: {cpu_time:.2f}s")
            logger.info(f"  CPU Efficiency: {cpu_efficiency:.1f}%")
            logger.info(f"  Memory Start: {start_memory:.1f}MB")
            logger.info(f"  Memory End: {end_memory:.1f}MB")
            
            return result
        
        return async_wrapper
    
    else:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            process = psutil.Process(os.getpid())
            
            # Before metrics
            start_memory = process.memory_info().rss / 1024 / 1024  # MB
            start_cpu_times = process.cpu_times()
            start_time = time.time()
            
            # Execute the sync function
            result = func(*args, **kwargs)
            
            # After metrics
            end_time = time.time()
            end_memory = process.memory_info().rss / 1024 / 1024  # MB
            end_cpu_times = process.cpu_times()
            
            # Calculate detailed metrics
            total_time = end_time - start_time
            memory_delta = end_memory - start_memory
            cpu_time = (end_cpu_times.user - start_cpu_times.user) + (end_cpu_times.system - start_cpu_times.system)
            cpu_efficiency = (cpu_time / total_time * 100) if total_time > 0 else 0
            
            # Add performance metrics to result if it's a dictionary
            if isinstance(result, dict):
                result.update({
                    'performance_metrics': {
                        'memory_start_mb': start_memory,
                        'memory_end_mb': end_memory,
                        'memory_delta_mb': memory_delta,
                        'cpu_time_seconds': cpu_time,
                        'cpu_efficiency_percent': cpu_efficiency,
                        'total_wall_time': total_time
                    }
                })
            
            # Log performance summary
            if isinstance(result, dict) and 'rows_inserted' in result:
                logger.info(f"SYNC PERFORMANCE SUMMARY:")
                logger.info(f"  Rows: {result['rows_inserted']:,}")
                logger.info(f"  Time: {total_time:.2f}s")
                logger.info(f"  Speed: {result.get('rows_per_second', 0):,} rows/sec")
                logger.info(f"  Memory: {memory_delta:.1f}MB delta")
                logger.info(f"  CPU Efficiency: {cpu_efficiency:.1f}%")
                logger.info(f"  Strategy: {result.get('strategy', 'unknown')}")
            else:
                logger.info(f"SYNC PERFORMANCE: {func.__name__} completed in {total_time:.2f}s")
            
            return result
        
        return sync_wrapper
    

# Helper functions for table name validation
def validate_table_name(name):
    """Validate table name format - matches common_utils validation"""
    if not name:
        return False, "Table name cannot be empty"
    
    # Check length
    if len(name) > 64:
        return False, "Table name too long (max 64 characters)"
    
    # Check format (must start with letter or underscore)
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False, "Table name must start with letter/underscore and contain only letters, numbers, and underscores"
    
    # Check for SQL keywords
    sql_keywords = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER',
        'TABLE', 'INDEX', 'VIEW', 'DATABASE', 'FROM', 'WHERE', 'ORDER', 'GROUP'
    }
    
    if name.upper() in sql_keywords:
        return False, f"'{name}' is a reserved SQL keyword"
    
    return True, None


def sanitize_table_name(raw_name):
    """Generate a valid table name from raw input"""
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


async def suggest_unique_name(base_name, datasette, db_name):
    """Generate unique table name by checking existing tables"""
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
        return {}, {}


async def enhanced_upload_page(datasette, request):
    """Enhanced upload page with ultra-high performance processing"""
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

    # Ensure database is registered before upload attempts
    try:
        target_db = datasette.get_database(db_name)
        if not target_db:
            await ensure_database_registered(datasette, db_name, actor["id"])
    except KeyError:
        await ensure_database_registered(datasette, db_name, actor["id"])

    if request.method == "POST":
        return await handle_enhanced_upload(datasette, request, db_name, actor)
    
    # GET request - show upload form
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


async def ensure_database_registered(datasette, db_name, user_id):
    """Ensure database is registered with Datasette"""
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
    """Handle enhanced upload form submission with ultra-optimized processing"""
    try:
        # Get max file size for validation
        max_file_size = await get_max_file_size(datasette)
        
        content_type = request.headers.get('content-type', '').lower()
        logger.debug(f"Content type: {content_type}")
        
        if 'multipart/form-data' in content_type:
            return await handle_file_upload_ultra_optimized(datasette, request, db_name, actor, max_file_size)
        else:
            post_vars = await request.post_vars()
            source_type = post_vars.get('source_type')
            logger.debug(f"Source type: {source_type}")
            
            if source_type == 'sheets':
                return await handle_sheets_upload(datasette, request, post_vars, db_name, actor)
            elif source_type == 'url':
                return await handle_url_upload(datasette, request, post_vars, db_name, actor)
            else:
                error_msg = "Invalid source type"
                return create_redirect_response(request, db_name, error_msg, is_error=True)
    
    except Exception as e:
        logger.error(f"Enhanced upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "enhanced_upload")
        return create_redirect_response(request, db_name, error_msg, is_error=True)

@monitor_performance_detailed
async def handle_file_upload_ultra_optimized(datasette, request, db_name, actor, max_file_size):
    """Handle file upload with ultra-high performance processing"""
    try:
        logger.debug("Starting ULTRA-OPTIMIZED file upload processing")
        
        # Parse multipart form data
        body = await request.post_body()
        logger.debug(f"Request body size: {len(body)} bytes")
        
        # Validate file size early
        if len(body) > max_file_size:
            size_mb = max_file_size // (1024*1024)
            error_msg = f"File too large (max {size_mb}MB)"
            return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        # Parse form data
        content_type = request.headers.get('content-type', '')
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
        
        if not boundary:
            logger.error("No boundary found in content type")
            return create_redirect_response(request, db_name, "Invalid form data", is_error=True)
        
        logger.debug(f"Using boundary: {boundary}")
        
        # Parse multipart data
        forms, files = parse_multipart_form_data(body, boundary)
        
        # Process file upload
        if 'file' not in files:
            logger.error("No file found in upload")
            return create_redirect_response(request, db_name, "No file uploaded", is_error=True)
        
        file_info = files['file']
        filename = file_info['filename']
        file_content = file_info['content']
        
        logger.debug(f"Processing file: {filename}, size: {len(file_content)} bytes")
        
        # Get form options
        custom_table_name = forms.get('table_name', '').strip()
        replace_existing = 'replace_existing' in forms
        excel_sheet = forms.get('excel_sheet', '').strip()
        
        # Generate table name
        if custom_table_name:
            table_name = custom_table_name
            is_valid, error_msg = validate_table_name(table_name)
            if not is_valid:
                return create_redirect_response(request, db_name, f"Invalid table name: {error_msg}", is_error=True)
        else:
            base_name = sanitize_table_name(filename)
            table_name = await suggest_unique_name(base_name, datasette, db_name)
        
        # Get database file path for uploader
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        if not db_info:
            return create_redirect_response(request, db_name, "Database not found", is_error=True)
        
        file_path = db_info['file_path']
        if not file_path:
            file_path = os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # ULTRA-OPTIMIZED PROCESSING LOGIC
        file_size = len(file_content)
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Choose optimal uploader with ultra mode for large files
        use_ultra_mode = file_size > 100 * 1024 * 1024  # Use ultra mode for files >100MB
        
        def process_with_monitoring():
            """Process file with detailed performance monitoring"""
            if file_ext in ['.xlsx', '.xls']:
                # Excel processing
                if isinstance(uploader, UltraOptimizedUploader):
                    return uploader.process_excel_ultra_fast(file_content, table_name, excel_sheet, replace_existing)
                else:
                    return process_excel_fallback(file_content, table_name, excel_sheet, replace_existing, file_path)
            
            elif file_ext in ['.csv', '.txt', '.tsv']:
                # CSV processing
                csv_content = None
                for encoding in ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']:
                    try:
                        csv_content = file_content.decode(encoding)
                        logger.debug(f"Successfully decoded with {encoding}")
                        break
                    except UnicodeDecodeError:
                        continue
                
                if csv_content is None:
                    raise ValueError("Could not decode file - unsupported encoding")
                
                # Process with optimal strategy
                if isinstance(uploader, UltraOptimizedUploader):
                    return uploader.stream_csv_ultra_fast(csv_content, table_name, replace_existing)
                else:
                    return uploader.process_csv_robust_fast(csv_content, table_name, replace_existing)
            
            else:
                raise ValueError("Unsupported file type. Use CSV, TSV, TXT, or Excel files")

        # Retry logic for database locks
        max_retries = 2
        last_exception = None

        for attempt in range(max_retries):
            try:
                uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
                logger.info(f"Selected uploader: {type(uploader).__name__} (ultra_mode={getattr(uploader, 'ultra_mode', False)}) - Attempt {attempt + 1}")
                
                # Execute with monitoring
                result = process_with_monitoring()
                
                # If we get here, upload was successful
                logger.info(f"Upload successful on attempt {attempt + 1}")
                break
                
            except sqlite3.OperationalError as e:
                last_exception = e
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    logger.warning(f"Database locked, retrying in 3s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(3)
                    use_ultra_mode = False  # Fall back to safe mode on retry
                    continue
                else:
                    logger.error(f"Database lock error on final attempt: {e}")
                    raise
                    
            except Exception as e:
                last_exception = e
                logger.error(f"Upload error on attempt {attempt + 1}: {type(e).__name__}: {str(e)}")
                
                # For non-lock errors, don't retry unless it's the first attempt
                if attempt == 0 and use_ultra_mode:
                    logger.warning("First attempt failed, trying with safe mode")
                    use_ultra_mode = False
                    continue
                else:
                    raise

        # Check if we have a result (success case is handled above with break)
        if 'result' not in locals():
            if last_exception:
                raise last_exception
            else:
                raise Exception("Upload failed for unknown reason")       
        
        logger.info(f"ULTRA-OPTIMIZED COMPLETE: {result['rows_inserted']:,} rows in {result['time_elapsed']:.2f}s ({result['rows_per_second']:,} rows/sec)")
        
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

        # Enhanced logging with performance metrics
        metadata = {
            "source_type": "file",
            "table_name": table_name,
            "filename": filename,
            "file_type": file_ext,
            "record_count": result['rows_inserted'],
            "column_count": result['columns'],
            "processing_strategy": result['strategy'],
            "time_elapsed": result['time_elapsed'],
            "rows_per_second": result['rows_per_second'],
            "file_size_bytes": file_size,
            "uploader_type": type(uploader).__name__,
            "ultra_mode": use_ultra_mode
        }
        
        # Add performance metrics if available
        if 'performance_metrics' in result:
            metadata.update(result['performance_metrics'])
        
        await log_upload_activity_enhanced(
            datasette, actor.get("id"), "ultra_upload", 
            f"ULTRA: Uploaded {result['rows_inserted']:,} rows to table '{table_name}' from file '{filename}' in {result['time_elapsed']:.1f}s",
            metadata
        )
        
        success_msg = f"ULTRA-FAST: Successfully uploaded {result['rows_inserted']:,} rows to table '{table_name}' in {result['time_elapsed']:.1f}s ({result['rows_per_second']:,} rows/sec)"
        return create_redirect_response(request, db_name, success_msg)
        
    except Exception as e:
        logger.error(f"Ultra file upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "ultra_file_upload")
        return create_redirect_response(request, db_name, error_msg, is_error=True)


def process_excel_fallback(file_content: bytes, table_name: str, sheet_name: str, replace_existing: bool, file_path: str):
    """Fallback Excel processing for robust processor"""
    # Basic Excel processing without ultra optimizations
    excel_file = pd.ExcelFile(io.BytesIO(file_content))
    sheet_name = sheet_name or excel_file.sheet_names[0]
    
    # Read entire sheet (for smaller files this is acceptable)
    df = pd.read_excel(excel_file, sheet_name=sheet_name)
    
    # Basic processing
    headers = [re.sub(r'[^a-zA-Z0-9_]', '_', str(col)) for col in df.columns]
    df.columns = headers
    
    # Convert to SQLite
    with sqlite3.connect(file_path) as conn:
        if replace_existing:
            conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
        
        df.to_sql(table_name, conn, if_exists='append', index=False, chunksize=10000)
    
    return {
        'table_name': table_name,
        'rows_inserted': len(df),
        'columns': len(headers),
        'time_elapsed': 0,  # Not measured in fallback
        'rows_per_second': 0,
        'strategy': 'excel_fallback'
    }


async def handle_sheets_upload(datasette, request, post_vars, db_name, actor):
    """Handle Google Sheets upload with ultra-optimized processing"""
    try:
        sheets_url = post_vars.get('sheets_url', '').strip()
        sheet_index = int(post_vars.get('sheet_index', '0'))
        custom_table_name = post_vars.get('table_name', '').strip()
        first_row_headers = 'first_row_headers' in post_vars
        
        logger.debug(f"Google Sheets params: url='{sheets_url}', sheet_index={sheet_index}, table_name='{custom_table_name}', headers={first_row_headers}")
        
        if not sheets_url:
            return create_redirect_response(request, db_name, "Google Sheets URL is required", is_error=True)
        
        # Fetch data from Google Sheets
        csv_content = await fetch_sheet_data(sheets_url, sheet_index)
        
        # Generate table name
        if custom_table_name:
            table_name = custom_table_name
            is_valid, error_msg = validate_table_name(table_name)
            if not is_valid:
                return create_redirect_response(request, db_name, f"Invalid table name: {error_msg}", is_error=True)
        else:
            base_name = sanitize_table_name("google_sheet")
            table_name = await suggest_unique_name(base_name, datasette, db_name)
        
        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        file_path = db_info['file_path'] if db_info else os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # Process with ultra-optimized uploader
        file_size = len(csv_content.encode('utf-8'))
        use_ultra_mode = file_size > 50 * 1024 * 1024  # Ultra mode for large sheets
        uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
        
        @monitor_performance_detailed
        def process_sheets_with_monitoring():
            if isinstance(uploader, UltraOptimizedUploader):
                return uploader.stream_csv_ultra_fast(csv_content, table_name)
            else:
                return uploader.process_csv_robust_fast(csv_content, table_name)
        
        result = process_sheets_with_monitoring()
        
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
            datasette, actor.get("id"), "ultra_sheets_upload", 
            f"Imported {result['rows_inserted']:,} rows to table '{table_name}' from Google Sheets in {result['time_elapsed']:.1f}s",
            {
                "source_type": "google_sheets",
                "table_name": table_name,
                "sheets_url": sheets_url,
                "record_count": result['rows_inserted'],
                "column_count": result['columns'],
                "processing_strategy": result['strategy'],
                "rows_per_second": result['rows_per_second']
            }
        )
        
        success_msg = f"Successfully uploaded {result['rows_inserted']:,} rows to table '{table_name}' in {result['time_elapsed']:.1f}s"
        return create_redirect_response(request, db_name, success_msg)

    except Exception as e:
        logger.error(f"Google Sheets upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "sheets_upload")
        return create_redirect_response(request, db_name, error_msg, is_error=True)


async def handle_url_upload(datasette, request, post_vars, db_name, actor):
    """Handle web CSV upload with ultra-optimized processing"""
    try:
        csv_url = post_vars.get('csv_url', '').strip()
        custom_table_name = post_vars.get('table_name', '').strip()
        encoding = post_vars.get('encoding', 'auto')
        
        logger.debug(f"Web CSV params: url='{csv_url}', table_name='{custom_table_name}', encoding='{encoding}'")
        
        if not csv_url:
            return create_redirect_response(request, db_name, "CSV URL is required", is_error=True)
        
        # Validate URL domain
        await validate_csv_url(datasette, csv_url)
        
        # Fetch CSV from URL
        csv_content = await fetch_csv_from_url(datasette, csv_url, encoding)
        
        # Generate table name
        if custom_table_name:
            table_name = custom_table_name
            is_valid, error_msg = validate_table_name(table_name)
            if not is_valid:
                return create_redirect_response(request, db_name, f"Invalid table name: {error_msg}", is_error=True)
        else:
            url_path = urlparse(csv_url).path
            filename = os.path.basename(url_path) or "web_csv"
            base_name = sanitize_table_name(filename)
            table_name = await suggest_unique_name(base_name, datasette, db_name)
        
        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        file_path = db_info['file_path'] if db_info else os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # Process with ultra-optimized uploader
        file_size = len(csv_content.encode('utf-8'))
        use_ultra_mode = file_size > 50 * 1024 * 1024  # Ultra mode for large CSVs
        uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
        
        @monitor_performance_detailed
        def process_url_with_monitoring():
            if isinstance(uploader, UltraOptimizedUploader):
                return uploader.stream_csv_ultra_fast(csv_content, table_name)
            else:
                return uploader.process_csv_robust_fast(csv_content, table_name)
        
        result = process_url_with_monitoring()
        
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
            datasette, actor.get("id"), "ultra_url_upload", 
            f"Imported {result['rows_inserted']:,} rows to table '{table_name}' from web CSV in {result['time_elapsed']:.1f}s",
            {
                "source_type": "web_csv",
                "table_name": table_name,
                "csv_url": csv_url,
                "record_count": result['rows_inserted'],
                "column_count": result['columns'],
                "processing_strategy": result['strategy'],
                "rows_per_second": result['rows_per_second']
            }
        )
        
        success_msg = f"Successfully uploaded {result['rows_inserted']:,} rows to table '{table_name}' in {result['time_elapsed']:.1f}s"
        return create_redirect_response(request, db_name, success_msg)
        
    except Exception as e:
        logger.error(f"Web CSV upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "url_upload")
        return create_redirect_response(request, db_name, error_msg, is_error=True)


async def fetch_sheet_data(sheet_url, sheet_index=0):
    """Fetch data from Google Sheets as CSV with validation"""
    try:
        # Extract sheet ID from URL
        patterns = [
            r'docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]+)',
            r'drive\.google\.com/file/d/([a-zA-Z0-9-_]+)'
        ]
        
        sheet_id = None
        for pattern in patterns:
            match = re.search(pattern, sheet_url)
            if match:
                sheet_id = match.group(1)
                break
        
        if not sheet_id:
            raise ValueError("Invalid Google Sheets URL format")
        
        # Try to extract gid from URL if present
        gid = 0
        if '#gid=' in sheet_url:
            try:
                gid = int(sheet_url.split('#gid=')[1].split('&')[0])
            except (ValueError, IndexError):
                gid = sheet_index
        else:
            gid = sheet_index
        
        # Generate CSV export URL
        csv_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}"
        
        # Fetch CSV data with proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(csv_url, timeout=30, headers=headers)
        
        # Check for specific error conditions
        if response.status_code == 401:
            raise ValueError("Google Sheet is private - please make it publicly accessible")
        elif response.status_code == 404:
            raise ValueError("Google Sheet not found - please check the URL")
        elif response.status_code != 200:
            raise ValueError(f"Failed to access Google Sheet (HTTP {response.status_code})")
        
        # Check if we got actual CSV data
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' in content_type:
            raise ValueError("Sheet appears to be private or URL is incorrect")
        
        # Validate CSV content
        csv_content = response.text.strip()
        if not csv_content:
            raise ValueError("The Google Sheet appears to be empty")
        
        return csv_content
        
    except requests.RequestException as e:
        raise ValueError(f"Network error accessing Google Sheets: connection failed")


async def validate_csv_url(datasette, url):
    """Validate CSV URL using dynamic blocked domains list"""
    try:
        parsed = urlparse(url)
        
        # Allow localhost for development
        if parsed.netloc.startswith('localhost') or parsed.netloc.startswith('127.0.0.1'):
            return True
        
        # Check if domain is blocked
        domain = parsed.netloc.lower()
        if await is_domain_blocked(datasette, domain):
            raise ValueError(f"Domain '{domain}' is blocked by system administrator")
        
        # Check for parent domain blocking
        domain_parts = domain.split('.')
        for i in range(len(domain_parts)):
            parent_domain = '.'.join(domain_parts[i:])
            if await is_domain_blocked(datasette, parent_domain):
                raise ValueError(f"Domain '{domain}' is blocked")
        
        # Check file extension
        path_lower = parsed.path.lower()
        if not any(path_lower.endswith(ext) for ext in ['.csv', '.txt', '.tsv']):
            raise ValueError("URL must point to a CSV, TXT, or TSV file")
        
        return True
        
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")


async def fetch_csv_from_url(datasette, url, encoding='auto'):
    """Fetch CSV data from web URL with validation"""
    try:
        await validate_csv_url(datasette, url)
        
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
        raise ValueError(f"Failed to fetch CSV from URL: connection error")


def create_redirect_response(request, db_name, message, is_error=False):
    """Create redirect response with properly encoded message"""
    try:
        # Use the enhanced redirect URL creation from common_utils
        redirect_to = request.args.get('redirect', 'upload')
        param = 'error' if is_error else 'success'
        
        if redirect_to == 'manage-databases':
            base_url = "/manage-databases"
        else:
            base_url = f"/upload-table/{db_name}"
        
        redirect_url = create_safe_redirect_url(base_url, param, message, is_error)
        return Response.redirect(redirect_url)
        
    except Exception as e:
        logger.error(f"Error creating redirect: {e}")
        # Fallback redirect
        param = 'error' if is_error else 'success'
        fallback_msg = "Upload failed" if is_error else "Upload completed"
        return Response.redirect(f"/upload-table/{db_name}?{param}={fallback_msg}")


@hookimpl
def register_routes():
    """Register enhanced upload routes"""
    return [
        (r"^/upload-table/([^/]+)$", enhanced_upload_page),
    ]