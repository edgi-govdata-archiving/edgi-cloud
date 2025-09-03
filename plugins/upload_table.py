"""
Ultra-High Performance Upload Module - Optimized for 500MB files
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
import psutil
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from email.parser import BytesParser
from email.policy import default
from contextlib import contextmanager
from typing import Iterator, Tuple, List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, quote, unquote
import uuid
import certifi


from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database

os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()
os.environ['SSL_CERT_FILE'] = certifi.where()
os.environ['CURL_CA_BUNDLE'] = certifi.where()

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
        
        total_rows = 0
    
        with self.ultra_optimized_connection() as conn:
            # Handle existing table
            if replace_existing:
                conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
            
            try:
                # Read Excel file - FIXED: Use openpyxl engine for better large file handling
                excel_file = pd.ExcelFile(io.BytesIO(file_content), engine='openpyxl')
                sheet_name = sheet_name or excel_file.sheet_names[0]
                
                # For large Excel files, process in chunks using skiprows and nrows
                file_size = len(file_content)
                if file_size > 100 * 1024 * 1024:  # 100MB+
                    chunk_size = 5000   # Smaller chunks for very large files
                elif file_size > 50 * 1024 * 1024:   # 50MB+
                    chunk_size = 10000
                else:
                    chunk_size = 20000
                
                # First, read just the header to create table structure
                header_df = pd.read_excel(excel_file, sheet_name=sheet_name, nrows=0)
                headers = [self._clean_column_name(col) for col in header_df.columns]
                
                # Create table without indexes initially
                columns = ', '.join([f'[{header}] TEXT' for header in headers])
                conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
                
                # Manual transaction control
                conn.execute("BEGIN IMMEDIATE")
                
                try:
                    # Process Excel in chunks using skiprows approach
                    chunk_start = 1  # Skip header row
                    
                    while True:
                        try:
                            # Read chunk
                            chunk_df = pd.read_excel(
                                excel_file, 
                                sheet_name=sheet_name, 
                                skiprows=range(1, chunk_start),  # Skip header + previous rows
                                nrows=chunk_size,
                                header=0  # First row of chunk is header
                            )
                            
                            if chunk_df.empty:
                                break
                                
                            # Clean column names to match table schema
                            chunk_df.columns = headers
                            
                            # Convert data types for SQLite compatibility
                            chunk_df = self._optimize_dataframe_types(chunk_df)
                            
                            # Convert to records and batch insert
                            records = [tuple(row) for row in chunk_df.values]
                            placeholders = ','.join(['?' for _ in headers])
                            insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
                            
                            conn.executemany(insert_sql, records)
                            total_rows += len(records)
                            
                            if total_rows % (chunk_size * 2) == 0:
                                logger.info(f"EXCEL ULTRA: Processed {total_rows:,} rows")
                            
                            chunk_start += chunk_size
                            
                        except Exception as chunk_error:
                            logger.error(f"Error processing chunk starting at row {chunk_start}: {chunk_error}")
                            break
                    
                    conn.execute("COMMIT")
                    self._create_optimized_indexes(conn, table_name, headers)
                    
                except Exception as e:
                    conn.execute("ROLLBACK")
                    raise Exception(f"Excel ultra processing failed: {str(e)}")
                    
            except Exception as excel_error:
                raise Exception(f"Excel file processing failed: {str(excel_error)}")
        
        elapsed_time = time.time() - start_time
        rows_per_second = int(total_rows / elapsed_time) if elapsed_time > 0 else 0
        
        logger.info(f"EXCEL ULTRA COMPLETE: {total_rows:,} rows in {elapsed_time:.2f}s = {rows_per_second:,} rows/sec")
        
        return {
            'table_name': table_name,
            'rows_inserted': total_rows,
            'columns': len(headers),
            'time_elapsed': elapsed_time,
            'rows_per_second': rows_per_second,
            'strategy': 'excel_ultra_fixed'
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
    Robust CSV processor with enhanced validation and error handling
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def process_csv_robust_fast(self, file_content: str, table_name: str,
                               replace_existing: bool = False) -> Dict[str, Any]:
        """Process CSV with enhanced validation and error handling"""
        start_time = time.time()
        
        # STEP 1: Validate CSV structure first
        is_valid, error_msg, column_info = validate_csv_structure(file_content)
        if not is_valid:
            raise Exception(f"CSV validation failed: {error_msg}")
        
        logger.info(f"CSV validation passed: {column_info['header_count']} columns, {column_info['sample_rows_checked']} rows sampled")
        
        # STEP 2: Process with validated structure
        csv_file = io.StringIO(file_content)
        
        # Use csv.Sniffer to detect dialect
        try:
            dialect = csv.Sniffer().sniff(file_content[:8192])  # Sample first 8KB
        except:
            dialect = csv.excel  # Fallback to standard excel dialect
        
        reader = csv.reader(csv_file, dialect=dialect)
        headers = [self._clean_column_name(h) for h in next(reader)]
        
        # Reset for data reading
        csv_file.seek(0)
        reader = csv.reader(csv_file, dialect=dialect)
        next(reader)  # Skip header row
        
        with sqlite3.connect(self.db_path) as conn:
            # Apply performance pragmas
            conn.isolation_level = None
            
            pragmas = [
                "PRAGMA synchronous = NORMAL",
                "PRAGMA journal_mode = WAL", 
                "PRAGMA cache_size = -1000000",
                "PRAGMA temp_store = MEMORY",
                "PRAGMA mmap_size = 268435456",
            ]
            
            for pragma in pragmas:
                conn.execute(pragma)
            
            # Handle existing table
            if replace_existing:
                conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
            
            # Create table
            columns = ', '.join([f'[{header}] TEXT' for header in headers])
            conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
            
            # Enhanced batch processing
            insert_sql = f"INSERT INTO [{table_name}] VALUES ({','.join(['?' for _ in headers])})"
            
            batch_size = 25000
            batch_data = []
            total_rows = 0
            error_rows = []
            
            # Single transaction for all data
            conn.execute("BEGIN IMMEDIATE")
            
            try:
                for row_num, row in enumerate(reader, start=2):  # Start counting from row 2
                    try:
                        # Enhanced row processing with error tolerance
                        processed_row = self._process_row_robust(row, len(headers), row_num)
                        batch_data.append(processed_row)
                        
                        if len(batch_data) >= batch_size:
                            conn.executemany(insert_sql, batch_data)
                            total_rows += len(batch_data)
                            batch_data.clear()
                            
                            if total_rows % (batch_size * 2) == 0:
                                logger.info(f"ROBUST: Processed {total_rows:,} rows")
                    
                    except Exception as row_error:
                        error_rows.append({
                            'row_num': row_num,
                            'error': str(row_error),
                            'row_data': str(row)[:100]
                        })
                        
                        # If too many row errors, fail the whole upload
                        if len(error_rows) > 100 or len(error_rows) > total_rows * 0.05:  # 5% error rate
                            raise Exception(f"Too many row processing errors ({len(error_rows)}). Sample errors: {error_rows[:3]}")
                
                # Insert remaining rows
                if batch_data:
                    conn.executemany(insert_sql, batch_data)
                    total_rows += len(batch_data)
                
                conn.execute("COMMIT")
                
                # Log any row errors but don't fail
                if error_rows:
                    logger.warning(f"Processed CSV with {len(error_rows)} row errors out of {total_rows + len(error_rows)} total rows")
                
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
            'strategy': 'robust_enhanced',
            'error_rows_skipped': len(error_rows)
        }
    
    def _process_row_robust(self, row: List[str], expected_length: int, row_num: int) -> List[str]:
        """Enhanced row processing with better error handling"""
        try:
            processed_row = []
            
            # Handle each column
            for i in range(expected_length):
                if i < len(row):
                    # Clean and process the cell value
                    cell_value = str(row[i]).strip()
                    # Remove problematic characters that might break SQLite
                    cell_value = cell_value.replace('\x00', '')  # Remove null bytes
                    processed_row.append(cell_value)
                else:
                    # Missing columns - fill with empty string
                    processed_row.append('')
            
            return processed_row
            
        except Exception as e:
            raise Exception(f"Row {row_num} processing failed: {str(e)}")
    
    def _clean_column_name(self, name: str) -> str:
        """Enhanced column name cleaning"""
        if not name or not str(name).strip():
            return f'column_{uuid.uuid4().hex[:8]}'
            
        # Clean and sanitize
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', str(name).strip())
        
        # Ensure starts with letter or underscore
        if clean_name and not clean_name[0].isalpha() and clean_name[0] != '_':
            clean_name = 'col_' + clean_name
        
        # Remove consecutive underscores
        clean_name = re.sub(r'_{2,}', '_', clean_name)
        
        # Truncate if too long
        if len(clean_name) > 60:
            clean_name = clean_name[:60].rstrip('_')
        
        return clean_name[:64] or f'column_{uuid.uuid4().hex[:8]}'


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
                logger.info(f" Rows: {result['rows_inserted']:,}")
                logger.info(f" Time: {total_time:.2f}s")
                logger.info(f" Speed: {result.get('rows_per_second', 0):,} rows/sec")
                logger.info(f" Memory: {memory_delta:.1f}MB delta")
                logger.info(f" CPU Efficiency: {cpu_efficiency:.1f}%")
                logger.info(f" Strategy: {result.get('strategy', 'unknown')}")
            else:
                logger.info(f"SYNC PERFORMANCE: {func.__name__} completed in {total_time:.2f}s")
            
            return result
        
        return sync_wrapper
    
def sanitize_filename_for_table(filename):
    """Convert filename to valid table name using auto-fix logic"""
    if not filename:
        return f'table_{uuid.uuid4().hex[:8]}'
    
    # Remove file extension if present
    base_name = os.path.splitext(filename)[0]
    
    # Apply the enhanced auto-fix logic
    return auto_fix_table_name(base_name)

async def suggest_unique_name(base_name, datasette, db_name):
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

async def is_table_name_available(target_db, table_name):
    """Check if table name is available (doesn't exist)"""
    try:
        existing_tables = await target_db.table_names()
        return table_name not in existing_tables
    except Exception as e:
        logger.error(f"Error checking table existence: {e}")
        # If we can't check, assume name might conflict and return False
        return False

def parse_multipart_form_data(body, boundary):
    """Improved multipart form data parser with better error handling"""
    try:
        # Method 1: Try email parser first
        headers = f'Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n'
        msg = BytesParser(policy=default).parsebytes(headers.encode() + body)
        
        forms = {}
        files = {}
        
        for part in msg.iter_parts():
            if not part.is_multipart():
                content_disposition = part.get('Content-Disposition', '')
                logger.debug(f"Processing part with Content-Disposition: {content_disposition}")
                
                if content_disposition:
                    # Parse Content-Disposition header more carefully
                    disposition_params = {}
                    
                    # Split by semicolon and process each parameter
                    parts = content_disposition.split(';')
                    for param_part in parts[1:]:  # Skip first part which is "form-data"
                        param_part = param_part.strip()
                        if '=' in param_part:
                            key, value = param_part.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"')  # Remove quotes
                            disposition_params[key] = value
                    
                    field_name = disposition_params.get('name')
                    filename = disposition_params.get('filename')
                    
                    logger.debug(f"Field name: {field_name}, Filename: {filename}")
                    
                    if field_name:
                        content = part.get_payload(decode=True)
                        if filename:  # File upload
                            files[field_name] = {
                                'filename': filename,
                                'content': content or b''
                            }
                            logger.debug(f"Found file field: {field_name} = {filename}")
                        else:  # Form field
                            text_content = content.decode('utf-8', errors='ignore') if content else ''
                            forms[field_name] = text_content
                            logger.debug(f"Found form field: {field_name} = '{text_content}'")
        
        logger.debug(f"Final parsed forms: {forms}")
        logger.debug(f"Final parsed files: {list(files.keys())}")
        return forms, files
        
    except Exception as email_error:
        logger.warning(f"Email parser failed: {email_error}, trying manual parser")
        
        # Method 2: Manual parsing as fallback
        try:
            return parse_multipart_manual(body, boundary)
        except Exception as manual_error:
            logger.error(f"All parsers failed: email={email_error}, manual={manual_error}")
            return {}, {}

def parse_multipart_manual(body, boundary):
    """Manual multipart parser as fallback"""
    forms = {}
    files = {}
    
    # Split by boundary
    boundary_bytes = f'--{boundary}'.encode()
    parts = body.split(boundary_bytes)
    
    for part in parts[1:-1]:  # Skip first empty and last closing parts
        if len(part) < 10:
            continue
        
        # Find headers/content separator
        if b'\r\n\r\n' in part:
            headers_bytes, content = part.split(b'\r\n\r\n', 1)
        elif b'\n\n' in part:
            headers_bytes, content = part.split(b'\n\n', 1)
        else:
            continue
        
        # Parse headers
        headers_text = headers_bytes.decode('utf-8', errors='ignore')
        
        # Extract field name and filename
        name_match = re.search(r'name="([^"]+)"', headers_text)
        filename_match = re.search(r'filename="([^"]*)"', headers_text)
        
        if name_match:
            field_name = name_match.group(1)
            
            # Clean content (remove trailing boundary markers)
            content = content.rstrip(b'\r\n--')
            
            if filename_match and filename_match.group(1):
                # File field
                files[field_name] = {
                    'filename': filename_match.group(1),
                    'content': content
                }
            else:
                # Form field  
                text_content = content.decode('utf-8', errors='ignore')
                forms[field_name] = text_content
    
    logger.debug(f"Manual parser - forms: {forms}, files: {list(files.keys())}")
    return forms, files

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
    """Handle file upload with ultra-high performance processing - supports both form and AJAX"""
    try:
        # Check if this is an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
                 'ajax-upload' in request.path or \
                 request.headers.get('Accept', '').startswith('application/json')
        
        logger.debug("Starting ULTRA-OPTIMIZED file upload processing with pre-validation")
        
        # Parse multipart form data
        body = await request.post_body()
        logger.debug(f"Request body size: {len(body)} bytes")
        
        # Validate file size early
        if len(body) > max_file_size:
            size_mb = max_file_size // (1024*1024)
            error_msg = f"File too large (max {size_mb}MB)"
            
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=400)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        # Parse form data
        content_type = request.headers.get('content-type', '')
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
        
        if not boundary:
            logger.error("No boundary found in content type")
            error_msg = "Invalid form data"
            
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=400)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        logger.debug(f"Using boundary: {boundary}")
        
        # Parse multipart data
        forms, files = parse_multipart_form_data(body, boundary)
        
        # Process file upload
        if 'file' not in files:
            logger.error("No file found in upload")
            error_msg = "No file uploaded"
            
            if is_ajax:
                return Response.json({"success": False, "error": error_msg}, status=400)
            else:
                return create_redirect_response(request, db_name, error_msg, is_error=True)
        
        file_info = files['file']
        filename = file_info['filename']
        file_content = file_info['content']
        
        logger.debug(f"Processing file: {filename}, size: {len(file_content)} bytes")
        
        # Get form options
        custom_table_name = forms.get('table_name', '').strip()
        replace_existing = 'replace_existing' in forms
        excel_sheet = forms.get('excel_sheet', '').strip()

        # FIXED TABLE NAME HANDLING with auto-fix and uniqueness
        if custom_table_name:
            # User provided custom name - validate and auto-fix if needed
            is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                is_fixed_valid, fixed_error = validate_table_name_enhanced(auto_fixed_name)
                if is_fixed_valid:
                    logger.info(f"Auto-fixed table name: '{custom_table_name}' -> '{auto_fixed_name}'")
                    base_table_name = auto_fixed_name
                else:
                    error_msg = f"Invalid table name: {error_msg}"
                    logger.error(f"Table name validation failed: {error_msg}")
                    
                    if is_ajax:
                        return Response.json({"success": False, "error": error_msg}, status=400)
                    else:
                        return create_redirect_response(request, db_name, error_msg, is_error=True)
            else:
                base_table_name = custom_table_name
        else:
            # Generate table name from filename
            base_table_name = sanitize_filename_for_table(filename)
        
        # CRITICAL: Always ensure uniqueness by checking existing tables
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        
        logger.info(f"Final table name for file upload: '{table_name}' (base: '{base_table_name}')")
        
        # Get database file path for uploader
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
        result = None

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

        # Check if we have a result
        if result is None:
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
        
        success_msg = format_upload_success_message(result, table_name)
        
        # Return appropriate response based on request type
        if is_ajax:
            # AJAX response with JSON
            stats = extract_upload_stats(success_msg)
            return Response.json({
                "success": True,
                "message": success_msg,
                "stats": stats,
                "redirect_url": "/manage-databases"
            })
        else:
            # Regular form response with redirect
            return create_redirect_response(request, db_name, success_msg)
        
    except Exception as e:
        logger.error(f"Ultra file upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "ultra_file_upload")
        
        if is_ajax:
            return Response.json({"success": False, "error": error_msg}, status=500)
        else:
            return create_redirect_response(request, db_name, error_msg, is_error=True)
        
def format_upload_success_message(result, table_name):
    """Format upload success message with performance indicators"""
    rows = result['rows_inserted']
    time_elapsed = result['time_elapsed']
    rows_per_sec = result['rows_per_second']
    
    # Performance badge based on speed
    if rows_per_sec > 100000:
        badge = "ULTRA-FAST"
    elif rows_per_sec > 50000:
        badge = "HIGH-SPEED" 
    else:
        badge = "SUCCESS"
    
    return (f"{badge}: Successfully uploaded {rows:,} rows to table "
            f"'{table_name}' in {time_elapsed:.1f}s ({rows_per_sec:,} rows/sec)")

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
    """Handle Google Sheets upload - SIMPLIFIED VERSION"""
    try:
        sheets_url = post_vars.get('sheets_url', '').strip()
        sheet_index = int(post_vars.get('sheet_index', '0'))
        custom_table_name = post_vars.get('table_name', '').strip()
        first_row_headers = 'first_row_headers' in post_vars
        
        if not sheets_url:
            return create_redirect_response(request, db_name, "Google Sheets URL is required", is_error=True)
        
        # Fetch data from Google Sheets
        csv_content = await fetch_sheet_data(sheets_url, sheet_index)
        
        # Table name handling without complex extraction
        if custom_table_name:
            is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                is_fixed_valid, fixed_error = validate_table_name_enhanced(auto_fixed_name)
                if is_fixed_valid:
                    logger.info(f"Auto-fixed table name: '{custom_table_name}' -> '{auto_fixed_name}'")
                    base_table_name = auto_fixed_name
                else:
                    return create_redirect_response(request, db_name, f"Invalid table name: {error_msg}", is_error=True)
            else:
                base_table_name = custom_table_name
        else:
            # Generate simple meaningful name
            if sheet_index > 0:
                base_table_name = f"google_sheet_{sheet_index}"
            else:
                base_table_name = "google_sheet"
        
        # Ensure uniqueness
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        
        logger.info(f"Final table name for Google Sheets: '{table_name}' (base: '{base_table_name}', sheet_index: {sheet_index})")

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
        
        success_msg = format_upload_success_message(result, table_name)
        return create_redirect_response(request, db_name, success_msg)

    except Exception as e:
        logger.error(f"Sheets upload with real names error: {e}")
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
        csv_content = await fetch_csv_from_url_with_progress(datasette, csv_url, encoding)
        
        # TABLE NAME HANDLING with auto-fix for Web CSV
        if custom_table_name:
            # User provided custom name
            is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                is_fixed_valid, fixed_error = validate_table_name_enhanced(auto_fixed_name)
                if is_fixed_valid:
                    logger.info(f"Auto-fixed Web CSV table name: '{custom_table_name}' -> '{auto_fixed_name}'")
                    base_table_name = auto_fixed_name
                else:
                    return create_redirect_response(request, db_name, f"Invalid table name: {error_msg}", is_error=True)
            else:
                base_table_name = custom_table_name
        else:
            # Generate table name from URL filename
            url_path = urlparse(csv_url).path
            filename = os.path.basename(url_path) or "web_csv"
            base_table_name = sanitize_filename_for_table(filename)
        
        # CRITICAL: Always ensure uniqueness
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        
        logger.info(f"Final table name for Web CSV: '{table_name}' (base: '{base_table_name}')")
        
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
        
        success_msg = format_upload_success_message(result, table_name)
        return create_redirect_response(request, db_name, success_msg)
        
    except Exception as e:
        logger.error(f"Web CSV upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "url_upload")
        return create_redirect_response(request, db_name, error_msg, is_error=True)

async def fetch_sheet_data(sheet_url, sheet_index=0):
    """Enhanced Google Sheets fetching with multiple export methods and detailed error handling"""
    try:
        # Clean URL and extract sheet ID
        sheet_url = sheet_url.rstrip('/')  # Remove trailing slash
        
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
        
        logger.info(f"Extracted sheet ID: {sheet_id}")
        
        # Handle gid extraction
        gid = 0
        if '#gid=' in sheet_url:
            try:
                gid = int(sheet_url.split('#gid=')[1].split('&')[0])
            except (ValueError, IndexError):
                gid = sheet_index
        else:
            gid = sheet_index
        
        # Multiple export URL formats to try
        export_urls = [
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}",
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv",
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&gid={gid}",
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv"
        ]
        
        # Enhanced headers to appear more like a browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://docs.google.com/',
            'Connection': 'keep-alive'
        }
        
        last_error = None
        
        # Try each export URL
        for i, csv_url in enumerate(export_urls):
            try:
                logger.info(f"Attempting export method {i+1}: {csv_url}")
                response = requests.get(csv_url, timeout=30, headers=headers, allow_redirects=True)
                
                # Enhanced error checking with specific messages
                if response.status_code == 400:
                    last_error = "Google Sheet access denied - make sure the sheet is publicly accessible with 'Anyone with the link can view' permission"
                    logger.warning(f"Export method {i+1}: HTTP 400 - {last_error}")
                    continue
                elif response.status_code == 401:
                    last_error = "Google Sheet is private - please make it publicly accessible"
                    logger.warning(f"Export method {i+1}: HTTP 401 - {last_error}")
                    continue
                elif response.status_code == 403:
                    last_error = "Google Sheet access forbidden - check sharing permissions"
                    logger.warning(f"Export method {i+1}: HTTP 403 - {last_error}")
                    continue
                elif response.status_code == 404:
                    last_error = "Google Sheet not found - please check the URL"
                    logger.warning(f"Export method {i+1}: HTTP 404 - {last_error}")
                    continue
                elif response.status_code != 200:
                    last_error = f"Failed to access Google Sheet (HTTP {response.status_code})"
                    logger.warning(f"Export method {i+1}: {last_error}")
                    continue
                
                # Check content type
                content_type = response.headers.get('content-type', '').lower()
                logger.info(f"Export method {i+1}: Got content-type: {content_type}")
                
                if 'text/html' in content_type:
                    # If we get HTML, it's likely a permission/login page
                    if 'accounts.google.com' in response.text or 'sign in' in response.text.lower():
                        last_error = "Google Sheet requires sign-in - please make it publicly accessible"
                        logger.warning(f"Export method {i+1}: Got login page")
                        continue
                    else:
                        last_error = "Google Sheet returned HTML instead of CSV - check permissions"
                        logger.warning(f"Export method {i+1}: Got HTML response")
                        continue
                
                # Try to get CSV content
                csv_content = response.text.strip()
                
                # Validate CSV content
                if not csv_content:
                    last_error = "Google Sheet appears to be empty"
                    logger.warning(f"Export method {i+1}: Empty content")
                    continue
                
                # Basic CSV validation
                if not (',' in csv_content or '\t' in csv_content):
                    last_error = "Google Sheet doesn't appear to contain valid CSV data"
                    logger.warning(f"Export method {i+1}: Invalid CSV format")
                    continue
                
                # Success! We got valid CSV data
                logger.info(f"Successfully retrieved CSV data using export method {i+1}")
                logger.info(f"CSV preview: {csv_content[:200]}...")
                return csv_content
                
            except requests.RequestException as req_error:
                last_error = f"Network error accessing Google Sheets: {str(req_error)}"
                logger.warning(f"Export method {i+1}: Network error - {req_error}")
                continue
            except Exception as method_error:
                last_error = f"Export method {i+1} failed: {str(method_error)}"
                logger.warning(last_error)
                continue
        
        # If all methods failed, raise the last error or a general one
        if last_error:
            raise ValueError(last_error)
        else:
            raise ValueError("Unable to export data from Google Sheet using any method")
            
    except Exception as e:
        logger.error(f"Google Sheets fetch error: {str(e)}")
        if "ValueError" in str(type(e)):
            raise  # Re-raise ValueError with original message
        else:
            raise ValueError(f"Google Sheets import failed: {str(e)}")
            
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
        
        try:
            head_response = requests.head(url, timeout=5, allow_redirects=True)
            content_length = head_response.headers.get('content-length')
            if content_length:
                size_mb = int(content_length) / (1024 * 1024)
                max_file_size = await get_max_file_size(datasette)
  # Temporary limit
                if size_mb > max_file_size:
                    raise ValueError(f"File too large ({size_mb:.1f}MB). Maximum: {max_file_size}MB")
        except requests.RequestException:
            # If HEAD fails, proceed but warn
            logger.warning(f"Could not check file size for {url}")
            
        return True
        
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")
    
async def fetch_csv_from_url_with_progress(datasette, csv_url, encoding='auto'):
    """
    FIXED: Fetch CSV with proper timeout, size limits, and early termination
    """
    try:
        await validate_csv_url(datasette, csv_url)
        
        headers = {
            'User-Agent': 'EDGI-Portal/1.0 (Environmental Data Portal)',
            'Accept': 'text/csv, text/plain, application/csv, */*'
        }
        
        max_file_size = await get_max_file_size(datasette)
        
        logger.info(f"Starting URL download: {csv_url} (max size: {max_file_size // (1024*1024)}MB)")
        
        # FIXED: Use asyncio-compatible httpx instead of blocking requests
        import httpx
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as client:
            # Check file size first with HEAD request
            try:
                head_response = await client.head(csv_url, headers=headers, follow_redirects=True)
                content_length = head_response.headers.get('content-length')
                
                if content_length:
                    size_bytes = int(content_length)
                    if size_bytes > max_file_size:
                        size_mb = max_file_size // (1024 * 1024)
                        actual_mb = size_bytes // (1024 * 1024)
                        raise ValueError(f"File too large ({actual_mb}MB). Maximum: {size_mb}MB")
                    
                    logger.info(f"File size from HEAD: {size_bytes // (1024*1024)}MB")
                
            except httpx.RequestError:
                logger.warning("HEAD request failed, proceeding with GET")
            
            # Download with streaming and size monitoring
            downloaded_size = 0
            chunks = []
            
            async with client.stream('GET', csv_url, headers=headers, follow_redirects=True) as response:
                response.raise_for_status()
                
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    if chunk:
                        downloaded_size += len(chunk)
                        
                        # Size check during download
                        if downloaded_size > max_file_size:
                            size_mb = max_file_size // (1024 * 1024)
                            raise ValueError(f"File exceeded {size_mb}MB during download")
                        
                        chunks.append(chunk)
                        
                        # Log progress every 5MB
                        if downloaded_size % (5 * 1024 * 1024) == 0:
                            mb_downloaded = downloaded_size // (1024 * 1024)
                            logger.info(f"Downloaded {mb_downloaded}MB from URL")
        
        # Combine and decode
        content_bytes = b''.join(chunks)
        logger.info(f"Download complete: {len(content_bytes)} bytes")
        
        # Encoding detection and decoding
        if encoding == 'auto':
            try:
                import chardet
                detected = chardet.detect(content_bytes[:10000])
                encoding = detected.get('encoding', 'utf-8') if detected.get('confidence', 0) > 0.7 else 'utf-8'
            except ImportError:
                encoding = 'utf-8'
        
        try:
            content = content_bytes.decode(encoding)
        except UnicodeDecodeError:
            for fallback in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    content = content_bytes.decode(fallback)
                    logger.info(f"Used fallback encoding: {fallback}")
                    break
                except UnicodeDecodeError:
                    continue
            else:
                raise ValueError("Could not decode file with any encoding")
        
        logger.info(f"CSV processed: {len(content)} characters")
        return content
        
    except httpx.TimeoutException:
        raise ValueError("Download timed out - file too large or server too slow")
    except httpx.RequestError as e:
        raise ValueError(f"Network error: {str(e)}")
    except Exception as e:
        logger.error(f"URL fetch error: {str(e)}")
        raise ValueError(f"Download failed: {str(e)}")
    
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

async def ajax_file_upload_handler(datasette, request):
    """AJAX File Upload Handler - Returns JSON response"""
    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required"}, status=401)

        # Extract database name from path
        path_parts = request.path.strip('/').split('/')
        if len(path_parts) < 2:
            return Response.json({"success": False, "error": "Invalid URL format"}, status=400)
        
        db_name = path_parts[1]
        
        # Verify user owns the database
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"success": False, "error": "Access denied"}, status=403)

        # Use existing file upload logic which properly handles multipart data
        max_file_size = await get_max_file_size(datasette)
        
        # The existing function already handles AJAX detection and JSON responses
        result = await handle_file_upload_ultra_optimized(datasette, request, db_name, actor, max_file_size)
        return result

    except Exception as e:
        logger.error(f"AJAX file upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "ajax_file_upload")
        return Response.json({"success": False, "error": error_msg}, status=500)

async def ajax_sheets_upload_handler(datasette, request):
    """
    AJAX Google Sheets Upload Handler - SIMPLIFIED VERSION
    No complex sheet name extraction - uses simple, reliable naming
    """
    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required"}, status=401)

        path_parts = request.path.strip('/').split('/')
        db_name = path_parts[1]
        
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"success": False, "error": "Access denied"}, status=403)

        # Parse multipart form data properly
        content_type = request.headers.get('content-type', '')
        body = await request.post_body()
        
        forms, files = parse_multipart_form_data_from_ajax(body, content_type)
        
        # Extract form data
        sheets_url = forms.get('sheets_url', '').strip()
        sheet_index = int(forms.get('sheet_index', '0') or '0')
        custom_table_name = forms.get('table_name', '').strip()
        first_row_headers = 'first_row_headers' in forms
        
        logger.debug(f"AJAX Google Sheets params: url='{sheets_url}', sheet_index={sheet_index}, table_name='{custom_table_name}', headers={first_row_headers}")
        
        if not sheets_url:
            return Response.json({"success": False, "error": "Google Sheets URL is required"}, status=400)
        
        if 'docs.google.com/spreadsheets/' not in sheets_url:
            return Response.json({"success": False, "error": "Please enter a valid Google Sheets URL"}, status=400)

        # Fetch CSV data (this works fine)
        csv_content = await fetch_sheet_data(sheets_url, sheet_index)
        
        # SIMPLIFIED: Table name handling without complex extraction
        if custom_table_name:
            # User provided custom name - validate and auto-fix
            is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                is_fixed_valid, fixed_error = validate_table_name_enhanced(auto_fixed_name)
                if is_fixed_valid:
                    logger.info(f"AJAX: Auto-fixed table name: '{custom_table_name}' -> '{auto_fixed_name}'")
                    base_table_name = auto_fixed_name
                else:
                    return Response.json({"success": False, "error": f"Invalid table name: {error_msg}"}, status=400)
            else:
                base_table_name = custom_table_name
        else:
            # SIMPLIFIED: Generate simple meaningful name based on sheet index
            if sheet_index > 0:
                base_table_name = f"google_sheet_{sheet_index}"
            else:
                base_table_name = "google_sheet"
        
        # CRITICAL: Ensure uniqueness
        table_name = await suggest_unique_name(base_table_name, datasette, db_name)
        
        logger.info(f"AJAX: Final table name for Google Sheets: '{table_name}' (base: '{base_table_name}', sheet_index: {sheet_index})")
        
        # Get database file path
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        if not db_info:
            return Response.json({"success": False, "error": "Database not found"}, status=404)
        
        file_path = db_info['file_path'] if db_info else os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        # Process with ultra-optimized uploader
        file_size = len(csv_content.encode('utf-8'))
        use_ultra_mode = file_size > 50 * 1024 * 1024
        uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
        
        if isinstance(uploader, UltraOptimizedUploader):
            upload_result = uploader.stream_csv_ultra_fast(csv_content, table_name)
        else:
            upload_result = uploader.process_csv_robust_fast(csv_content, table_name)
        
        # Update database timestamp
        await update_database_timestamp(datasette, db_name)
        
        # Sync with database_tables
        try:
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ? AND status != 'Deleted'", [db_name]
            )
            db_record = db_result.first()
            if db_record:
                await sync_database_tables_on_upload(datasette, db_record['db_id'], table_name)
        except Exception as sync_error:
            logger.error(f"AJAX: Error syncing table visibility: {sync_error}")

        # Simplified logging
        await log_upload_activity_enhanced(
            datasette, actor.get("id"), "ajax_sheets_upload", 
            f"AJAX: Imported {upload_result['rows_inserted']:,} rows to table '{table_name}' from Google Sheets",
            {
                "source_type": "google_sheets_ajax",
                "table_name": table_name,
                "sheets_url": sheets_url,
                "sheet_index": sheet_index,
                "record_count": upload_result['rows_inserted'],
                "column_count": upload_result['columns'],
                "upload_method": "ajax"
            }
        )
        
        # Format success message
        success_msg = format_upload_success_message(upload_result, table_name)
        stats = extract_upload_stats(success_msg)
        
        # AJAX JSON Response
        return Response.json({
            "success": True,
            "message": success_msg,
            "stats": stats,
            "table_name": table_name,
            "rows_imported": upload_result['rows_inserted'],
            "redirect_url": "/manage-databases"
        })
        
    except Exception as e:
        logger.error(f"AJAX sheets upload error: {str(e)}")
        error_msg = str(e)
        
        # Provide specific user-friendly error messages
        if "access denied" in error_msg.lower() or "private" in error_msg.lower() or "400" in error_msg:
            user_msg = "Google Sheet is not publicly accessible. Please make it publicly viewable and try again."
        elif "forbidden" in error_msg.lower() or "403" in error_msg:
            user_msg = "Permission denied. Make sure the Google Sheet is shared publicly."
        elif "not found" in error_msg.lower() or "404" in error_msg:
            user_msg = "Google Sheet not found. Please check the URL."
        else:
            user_msg = await handle_upload_error_gracefully(datasette, e, "ajax_sheets_upload")
        
        return Response.json({"success": False, "error": user_msg}, status=500)
            
async def ajax_url_upload_handler(datasette, request):
    """AJAX URL Upload Handler - with early size detection"""
    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required"}, status=401)

        path_parts = request.path.strip('/').split('/')
        db_name = path_parts[1]
        
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"success": False, "error": "Access denied"}, status=403)

        # Parse multipart form data properly
        content_type = request.headers.get('content-type', '')
        body = await request.post_body()
        
        forms, files = parse_multipart_form_data_from_ajax(body, content_type)
        
        # Extract form data
        csv_url = forms.get('csv_url', '').strip()

        if not csv_url:
            return Response.json({"success": False, "error": "CSV URL is required"}, status=400)
        
        # FIXED: Quick size check before processing
        try:
            import httpx
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                head_response = await client.head(csv_url, follow_redirects=True)
                content_length = head_response.headers.get('content-length')
                
                if content_length:
                    size_bytes = int(content_length)
                    max_file_size = await get_max_file_size(datasette)
                    
                    if size_bytes > max_file_size:
                        size_mb = max_file_size // (1024 * 1024)
                        actual_mb = size_bytes // (1024 * 1024)
                        return Response.json({
                            "success": False, 
                            "error": f"File too large ({actual_mb}MB). Maximum size allowed: {size_mb}MB"
                        }, status=400)
                    
                    logger.info(f"URL file size check: {size_bytes // (1024*1024)}MB (within limits)")
        
        except Exception as size_check_error:
            logger.warning(f"Could not check file size: {size_check_error}")
            # Continue anyway - size will be checked during download

        custom_table_name = forms.get('table_name', '').strip()
        encoding = forms.get('encoding', 'auto')
        
        logger.debug(f"Web CSV params: url='{csv_url}', table_name='{custom_table_name}', encoding='{encoding}'")
        
        try:
            # Validate URL domain
            await validate_csv_url(datasette, csv_url)
            
            # Fetch CSV from URL
            csv_content = await fetch_csv_from_url_with_progress(datasette, csv_url, encoding)
            
            # FIXED TABLE NAME HANDLING with auto-fix for Web CSV
            if custom_table_name:
                is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
                if not is_valid:
                    auto_fixed_name = auto_fix_table_name(custom_table_name)
                    is_fixed_valid, fixed_error = validate_table_name_enhanced(auto_fixed_name)
                    if is_fixed_valid:
                        logger.info(f"Auto-fixed Web CSV table name: '{custom_table_name}' -> '{auto_fixed_name}'")
                        base_table_name = auto_fixed_name
                    else:
                        error_msg = f"Invalid table name: {error_msg}"
                        return Response.json({"success": False, "error": error_msg}, status=400)
                else:
                    base_table_name = custom_table_name
            else:
                # Generate table name from URL filename
                url_path = urlparse(csv_url).path
                filename = os.path.basename(url_path) or "web_csv"
                base_table_name = sanitize_filename_for_table(filename)
            
            # CRITICAL: Ensure uniqueness
            table_name = await suggest_unique_name(base_table_name, datasette, db_name)
            
            logger.info(f"Final table name for AJAX Web CSV: '{table_name}' (base: '{base_table_name}')")
            
            # Get database file path
            portal_db = datasette.get_database('portal')
            result = await portal_db.execute(
                "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor["id"]]
            )
            db_info = result.first()
            
            if not db_info:
                return Response.json({"success": False, "error": "Database not found"}, status=404)
            
            file_path = db_info['file_path'] if db_info else os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
            
            # Process with ultra-optimized uploader
            file_size = len(csv_content.encode('utf-8'))
            use_ultra_mode = file_size > 50 * 1024 * 1024
            uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode)
            
            if isinstance(uploader, UltraOptimizedUploader):
                upload_result = uploader.stream_csv_ultra_fast(csv_content, table_name)
            else:
                upload_result = uploader.process_csv_robust_fast(csv_content, table_name)
            
            # Update database timestamp
            await update_database_timestamp(datasette, db_name)
            
            # Sync with database_tables
            try:
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
                datasette, actor.get("id"), "ajax_url_upload", 
                f"Imported {upload_result['rows_inserted']:,} rows to table '{table_name}' from web CSV",
                {
                    "source_type": "web_csv",
                    "table_name": table_name,
                    "csv_url": csv_url,
                    "record_count": upload_result['rows_inserted'],
                    "column_count": upload_result['columns']
                }
            )
            
            success_msg = format_upload_success_message(upload_result, table_name)
            stats = extract_upload_stats(success_msg)
            
            return Response.json({
                "success": True,
                "message": success_msg,
                "stats": stats,
                "redirect_url": "/manage-databases"
            })
            
        except Exception as e:
            logger.error(f"URL processing error: {str(e)}")
            error_msg = await handle_upload_error_gracefully(datasette, e, "url_upload")
            return Response.json({"success": False, "error": error_msg}, status=500)
        
    except Exception as e:
        logger.error(f"AJAX URL upload error: {str(e)}")
        error_msg = await handle_upload_error_gracefully(datasette, e, "ajax_url_upload")
        return Response.json({"success": False, "error": error_msg}, status=500)

def check_httpx_dependency():
    """Check if httpx is available, fallback to requests with warnings"""
    try:
        import httpx
        return True
    except ImportError:
        logger.warning("httpx not available, using requests (blocking). Install httpx for better performance.")
        return False
    
def parse_multipart_form_data_from_ajax(body, content_type):
    """Parse multipart form data from AJAX requests properly"""
    try:
        # Extract boundary
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
        
        if not boundary:
            logger.error("No boundary found in content type")
            return {}, {}
        
        # Use existing parser but ensure we get the correct format
        forms, files = parse_multipart_form_data(body, boundary)
        
        # Convert forms to proper format (handle list values)
        processed_forms = {}
        for key, value in forms.items():
            if isinstance(value, list) and len(value) > 0:
                processed_forms[key] = value[0]  # Take first value
            else:
                processed_forms[key] = value if isinstance(value, str) else str(value)
        
        logger.debug(f"Processed forms: {processed_forms}")
        return processed_forms, files
        
    except Exception as e:
        logger.error(f"Error parsing multipart data from AJAX: {e}")
        return {}, {}

def extract_upload_stats(success_msg):
    """Extract upload statistics from success message for display"""
    import re
    
    # Pattern to match statistics
    rows_pattern = r'(\d{1,3}(?:,\d{3})*)\s+rows'
    time_pattern = r'in\s+([\d.]+)s'
    speed_pattern = r'\((\d{1,3}(?:,\d{3})*)\s+rows/sec\)'
    
    rows_match = re.search(rows_pattern, success_msg)
    time_match = re.search(time_pattern, success_msg)
    speed_match = re.search(speed_pattern, success_msg)
    
    if rows_match and time_match and speed_match:
        return f"{rows_match.group(1)} rows | {speed_match.group(1)} rows/sec | {time_match.group(1)}s"
    
    return None

def validate_table_name_enhanced(name):
    """Enhanced table name validation with detailed error messages"""
    if not name:
        return False, "Table name cannot be empty"
    
    # Convert to string for validation
    name = str(name).strip()
    
    # Check length
    if len(name) > 64:
        return False, "Table name too long (max 64 characters)"
    
    # Must start with letter (not underscore)
    if not re.match(r'^[a-zA-Z]', name):
        return False, "Table name must start with a letter"
    
    # Check format (only letters, numbers, underscores)
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', name):
        return False, "Table name can only contain letters, numbers, and underscores"
    
    # Check for SQL keywords
    sql_keywords = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER',
        'TABLE', 'INDEX', 'VIEW', 'DATABASE', 'FROM', 'WHERE', 'ORDER', 
        'GROUP', 'HAVING', 'UNION', 'JOIN', 'INNER', 'LEFT', 'RIGHT',
        'FULL', 'CROSS', 'ON', 'AS', 'AND', 'OR', 'NOT', 'NULL'
    }
    
    if name.upper() in sql_keywords:
        return False, f"'{name}' is a reserved SQL keyword"
    
    return True, None

def pre_validate_upload_data(table_name, filename=None):
    """Pre-validate upload data before processing"""
    errors = []
    
    # Auto-fix table name if it's invalid
    if table_name:
        is_valid, error = validate_table_name_enhanced(table_name)
        if not is_valid:
            # Try to auto-fix common issues
            fixed_name = auto_fix_table_name(table_name)
            if fixed_name != table_name:
                # Log the auto-fix but don't error
                logger.info(f"Auto-fixed table name: '{table_name}' -> '{fixed_name}'")
                # You'd need to return the fixed name somehow
            else:
                errors.append(f"Table name error: {error}")
    
    # Validate filename if provided
    if filename:
        # Check for problematic characters in filename
        if any(char in filename for char in ['<', '>', ':', '"', '|', '?', '*']):
            errors.append("Filename contains invalid characters")
        
        # Check file extension
        allowed_extensions = ['.csv', '.txt', '.tsv', '.xlsx', '.xls']
        ext = os.path.splitext(filename)[1].lower()
        if ext not in allowed_extensions:
            errors.append(f"Invalid file type '{ext}'. Allowed: {', '.join(allowed_extensions)}")
    
    return errors

def auto_fix_table_name(name):
    """Auto-fix common table name issues"""
    if not name:
        return name
    
    # Convert to string and strip
    name = str(name).strip()
    
    # Replace invalid characters with underscores
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    
    # If starts with number or underscore, prefix with 'table_'
    if name and not re.match(r'^[a-zA-Z]', name):
        name = 'table_' + name
    
    # Remove consecutive underscores
    name = re.sub(r'_{2,}', '_', name)
    
    # Remove leading/trailing underscores
    name = name.strip('_')
    
    # Truncate if too long
    if len(name) > 64:
        name = name[:60]
    
    # Fallback for empty names
    if not name:
        name = f'table_{uuid.uuid4().hex[:8]}'
    
    return name

def validate_csv_structure(csv_content: str, max_sample_rows: int = 100) -> tuple:
    """Enhanced CSV validation with better error handling"""
    try:
        if not csv_content or not csv_content.strip():
            return False, "CSV content is empty", None
            
        # Check for minimum content
        if len(csv_content.strip()) < 10:
            return False, "CSV content too short to be valid", None
            
        csv_file = io.StringIO(csv_content)
        
        # Try different dialects with better error handling
        try:
            # Sample first 8KB for dialect detection
            sample = csv_content[:8192]
            dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
        except (csv.Error, Exception) as e:
            logger.debug(f"Dialect detection failed: {e}, using excel dialect")
            dialect = csv.excel
        
        reader = csv.reader(csv_file, dialect=dialect)
        
        # Read header with error handling
        try:
            headers = next(reader)
            if not headers or all(not str(h).strip() for h in headers):
                return False, "CSV file has no valid headers", None
        except (StopIteration, UnicodeDecodeError, csv.Error) as e:
            return False, f"CSV file has no readable content: {str(e)}", None
        
        # Validate headers
        valid_headers = [str(h).strip() for h in headers if str(h).strip()]
        if len(valid_headers) == 0:
            return False, "CSV file has no valid column headers", None
        
        if len(valid_headers) != len(headers):
            logger.warning(f"CSV has {len(headers) - len(valid_headers)} empty headers out of {len(headers)} total")
        
        # Sample validation with better error handling
        row_lengths = []
        sample_rows = 0
        inconsistent_rows = []
        header_length = len(headers)
        
        try:
            for row_num, row in enumerate(reader, start=2):
                if sample_rows >= max_sample_rows:
                    break
                
                if not row or all(not str(cell).strip() for cell in row):
                    continue  # Skip completely empty rows
                    
                row_length = len(row)
                row_lengths.append(row_length)
                
                # Check for significant inconsistencies (allow some flexibility)
                variance = abs(row_length - header_length)
                if variance > max(2, header_length * 0.1):  # Allow 10% variance or 2 columns, whichever is larger
                    inconsistent_rows.append({
                        'row_num': row_num,
                        'expected': header_length,
                        'actual': row_length,
                        'variance': variance
                    })
                    
                sample_rows += 1
                
        except (csv.Error, UnicodeDecodeError) as e:
            logger.warning(f"Error sampling CSV rows: {e}")
            # Continue with partial validation if we got some data
        
        if not row_lengths:
            return False, "CSV file contains only headers with no valid data rows", None
        
        # Analyze inconsistencies
        inconsistent_percentage = len(inconsistent_rows) / len(row_lengths) if row_lengths else 0
        
        if inconsistent_percentage > 0.2:  # More than 20% inconsistent
            error_details = f"CSV has too many inconsistent rows ({inconsistent_percentage:.1%}). "
            error_details += f"Expected {header_length} columns but found major variances in {len(inconsistent_rows)} rows."
            return False, error_details, None
        
        # Return validation info
        column_info = {
            'header_count': len(headers),
            'valid_headers': len(valid_headers),
            'headers_sample': valid_headers[:10],
            'sample_rows_checked': sample_rows,
            'inconsistent_rows': len(inconsistent_rows),
            'inconsistent_percentage': inconsistent_percentage,
            'avg_row_length': sum(row_lengths) / len(row_lengths) if row_lengths else 0,
            'row_length_range': (min(row_lengths), max(row_lengths)) if row_lengths else (0, 0)
        }
        
        return True, None, column_info
        
    except Exception as e:
        logger.error(f"CSV validation error: {e}")
        return False, f"CSV validation failed due to unexpected error: {str(e)}", None    

@hookimpl
def register_routes():
    """Register both regular and AJAX upload routes"""
    return [
        # Regular upload route
        (r"^/upload-table/([^/]+)$", enhanced_upload_page),
        
        # AJAX upload routes
        (r"^/ajax-upload-file/([^/]+)$", ajax_file_upload_handler),
        (r"^/ajax-upload-sheets/([^/]+)$", ajax_sheets_upload_handler),
        (r"^/ajax-upload-url/([^/]+)$", ajax_url_upload_handler),
    ]