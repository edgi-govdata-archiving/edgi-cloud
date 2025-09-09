"""
Complete Ultra-High Performance Upload Module - ENHANCED WITH CANCELLATION
Supports: CSV files, Excel files (first sheet only), Google Sheets, and Web CSV
Memory-efficient streaming, connection pooling, robust CSV parsing
Enhanced cancellation support with upload session tracking
All validation improvements integrated
FIXED: Excel upload errors and missing functions
PART 1 of 3: Imports, Error Handling, and Core Classes
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
import queue
from urllib.parse import urlparse
import urllib.request
import tempfile
import subprocess
import signal
from pathlib import Path

# Optional imports with fallbacks
try:
    import certifi
    import os
    os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()
except ImportError:
    logging.warning("certifi not available - SSL verification may have issues")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not available - performance monitoring disabled")

from datasette import hookimpl
from datasette.utils.asgi import Response
from datasette.database import Database

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

# Excel processing imports - with proper error handling
try:
    PANDAS_AVAILABLE = True
    logger.info("Pandas available for Excel processing")
except ImportError:
    PANDAS_AVAILABLE = False
    logger.warning("Pandas not available - Excel uploads will be disabled")

# Optional encoding detection
try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False
    logger.warning("chardet not available - using basic encoding detection")

def check_excel_engine_availability(file_extension):
    """Check if appropriate Excel engine is available for file type"""
    if not PANDAS_AVAILABLE:
        return False, "Pandas not available. Please install: pip install pandas"
    
    if file_extension == '.xlsx':
        try:
            import openpyxl
            return True, None
        except ImportError:
            return False, "openpyxl not available for .xlsx files. Please install: pip install openpyxl"
    
    elif file_extension == '.xls':
        try:
            import xlrd
            return True, None
        except ImportError:
            return False, "xlrd not available for .xls files. Please install: pip install xlrd"
    
    return False, f"Unsupported Excel file extension: {file_extension}"

# ============= ERROR HANDLING FUNCTIONS =============

async def categorize_upload_error(error_msg, source_type, datasette):
    """Categorize upload errors and provide user-friendly messages"""
    error_msg_lower = str(error_msg).lower()
    
    if "cancelled" in error_msg_lower or "cancellation" in error_msg_lower:
        return {
            "user_message": "Upload was cancelled by user",
            "technical_details": str(error_msg),
            "category": "cancellation",
            "retry_suggested": False
        }
    
    if "too large" in error_msg_lower or "size" in error_msg_lower or "exceeded" in error_msg_lower:
        try:
            max_size = await get_max_file_size(datasette)
            max_mb = max_size / (1024 * 1024)
            return {
                "user_message": f"File is too large. Maximum allowed size is {max_mb:.0f}MB. Please use a smaller file or contact your administrator.",
                "technical_details": str(error_msg),
                "category": "file_size",
                "retry_suggested": False
            }
        except:
            return {
                "user_message": "File is too large. Please use a smaller file.",
                "technical_details": str(error_msg),
                "category": "file_size",
                "retry_suggested": False
            }
    
    if "excel" in error_msg_lower or "openpyxl" in error_msg_lower or "xlrd" in error_msg_lower:
        if "install" in error_msg_lower:
            return {
                "user_message": "Excel file support is not available on this server. Please convert your file to CSV format and try again.",
                "technical_details": str(error_msg),
                "category": "excel_support",
                "retry_suggested": False
            }
        else:
            return {
                "user_message": "Excel file processing failed. Please ensure your file is not corrupted and try again. Alternatively, save as CSV format.",
                "technical_details": str(error_msg),
                "category": "excel_processing",
                "retry_suggested": True
            }
    
    if "csv" in error_msg_lower or "delimiter" in error_msg_lower or "parsing" in error_msg_lower:
        return {
            "user_message": "CSV file format error. Please check that your file uses proper CSV formatting with consistent columns and delimiters.",
            "technical_details": str(error_msg),
            "category": "csv_format",
            "retry_suggested": True
        }
    
    if "network" in error_msg_lower or "connection" in error_msg_lower or "timeout" in error_msg_lower:
        return {
            "user_message": "Network connection failed. Please check your internet connection and try again.",
            "technical_details": str(error_msg),
            "category": "network",
            "retry_suggested": True
        }
    
    if "permission" in error_msg_lower or "access" in error_msg_lower or "denied" in error_msg_lower:
        return {
            "user_message": "Access denied. Please check that you have permission to access this database and file.",
            "technical_details": str(error_msg),
            "category": "permissions",
            "retry_suggested": False
        }
    
    if "google" in error_msg_lower or "sheets" in error_msg_lower:
        if "private" in error_msg_lower:
            return {
                "user_message": "Google Sheet is not publicly accessible. Please share the sheet with 'Anyone with the link can view' and try again.",
                "technical_details": str(error_msg),
                "category": "google_sheets_private",
                "retry_suggested": True
            }
        else:
            return {
                "user_message": "Google Sheets import failed. Please check the URL and ensure the sheet is publicly accessible.",
                "technical_details": str(error_msg),
                "category": "google_sheets",
                "retry_suggested": True
            }
    
    if "database" in error_msg_lower and "lock" in error_msg_lower:
        return {
            "user_message": "Database is temporarily busy. Please wait a moment and try again.",
            "technical_details": str(error_msg),
            "category": "database_lock",
            "retry_suggested": True
        }
    
    # Generic error
    return {
        "user_message": f"Upload failed: {str(error_msg)[:200]}{'...' if len(str(error_msg)) > 200 else ''}",
        "technical_details": str(error_msg),
        "category": "general",
        "retry_suggested": True
    }

def create_error_response(error_context, is_ajax=False):
    """Create appropriate error response based on context"""
    if is_ajax:
        return Response.json({
            "success": False,
            "error": error_context["user_message"],
            "category": error_context.get("category", "general"),
            "retry_suggested": error_context.get("retry_suggested", True)
        }, status=400 if error_context.get("retry_suggested", True) else 500)
    else:
        return Response.text(error_context["user_message"], status=400)

# ============= ENHANCED CANCELLATION SYSTEM =============

class CancellationError(Exception):
    """Custom exception for upload cancellation"""
    pass

class SubprocessDownloader:
    """Download files using subprocess that can be killed immediately"""
    
    def __init__(self, url, upload_session, max_file_size, encoding='utf-8'):
        self.url = url
        self.upload_session = upload_session
        self.max_file_size = max_file_size
        self.encoding = encoding
        self.process = None
        self.temp_file = None
        self.bytes_downloaded = 0
        
    def download_with_subprocess(self):
        """Download using curl subprocess - can be killed instantly"""
        try:
            # Create temporary file
            self.temp_file = tempfile.NamedTemporaryFile(mode='w+b', delete=False, suffix='.csv')
            temp_path = self.temp_file.name
            self.temp_file.close()
            
            logger.info(f"SUBPROCESS DOWNLOAD START: {self.url}")
            logger.info(f"Temp file: {temp_path}")
            
            # Use curl for reliable, cancellable download
            curl_cmd = [
                'curl',
                '--location',  # Follow redirects
                '--fail',      # Fail on HTTP errors
                '--silent',    # Quiet output
                '--show-error', # Show errors
                '--insecure',  # Skip SSL verification
                '--max-time', '300',  # 5 minute timeout
                '--connect-timeout', '30',  # 30 second connect timeout
                '--user-agent', 'Resette-Portal/1.0 (Environmental Data Portal)',
                '--output', temp_path,
                self.url
            ]
            
            # Check if curl is available
            try:
                subprocess.run(['curl', '--version'], capture_output=True, check=True, timeout=5)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                raise ValueError("curl command not available. Please install curl or use a different download method.")
            
            start_time = time.time()
            
            # Start the download process
            self.process = subprocess.Popen(
                curl_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
            
            # Monitor the download in a separate thread
            monitor_thread = threading.Thread(
                target=self._monitor_download,
                args=(temp_path, start_time),
                daemon=True
            )
            monitor_thread.start()
            
            # Wait for process to complete
            stdout, stderr = self.process.communicate()
            return_code = self.process.returncode
            
            # Check results
            if return_code == 0:
                # Success - read the file
                final_size = os.path.getsize(temp_path)
                logger.info(f"SUBPROCESS DOWNLOAD COMPLETE: {final_size / (1024*1024):.1f}MB")
                
                # Read and return content
                with open(temp_path, 'r', encoding=self.encoding, errors='replace') as f:
                    content = f.read()
                
                return content
                
            elif return_code == -9 or return_code == -15:  # SIGKILL or SIGTERM
                logger.info("SUBPROCESS DOWNLOAD CANCELLED by signal")
                raise CancellationError("Download cancelled by user")
                
            else:
                # Download failed
                error_msg = stderr.decode('utf-8', errors='replace') if stderr else f"curl failed with code {return_code}"
                logger.error(f"SUBPROCESS DOWNLOAD FAILED: {error_msg}")
                raise Exception(f"Download failed: {error_msg}")
                
        except CancellationError:
            raise
        except Exception as e:
            logger.error(f"Subprocess download error: {e}")
            raise
        finally:
            self._cleanup()
    
    def _monitor_download(self, temp_path, start_time):
        """Monitor download progress and cancellation"""
        last_size = 0
        last_check = time.time()
        
        while self.process and self.process.poll() is None:
            try:
                # Check cancellation every 0.5 seconds
                time.sleep(0.5)
                
                current_time = time.time()
                
                # Check for cancellation
                if self.upload_session and self.upload_session.is_cancelled:
                    logger.warning("CANCELLATION DETECTED - Killing subprocess")
                    self._kill_process()
                    break
                
                # Check file size and progress
                if os.path.exists(temp_path):
                    current_size = os.path.getsize(temp_path)
                    
                    # Check size limit
                    if current_size > self.max_file_size:
                        logger.error(f"File size exceeded limit: {current_size / (1024*1024):.1f}MB")
                        self._kill_process()
                        break
                    
                    # Update progress
                    if current_size != last_size:
                        self.bytes_downloaded = current_size
                        if self.upload_session:
                            self.upload_session.update_progress(bytes_downloaded=current_size)
                        
                        # Log progress occasionally
                        if current_time - last_check >= 2.0:  # Every 2 seconds
                            logger.info(f"Downloaded: {current_size / (1024*1024):.1f}MB")
                            last_check = current_time
                        
                        last_size = current_size
                
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                break
    
    def _kill_process(self):
        """Kill the download process immediately"""
        if self.process:
            try:
                if os.name == 'nt':  # Windows
                    # Use taskkill for Windows
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.process.pid)], 
                                 capture_output=True, timeout=5)
                else:  # Unix/Linux
                    # Send SIGTERM first, then SIGKILL if needed
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                    time.sleep(0.1)
                    if self.process.poll() is None:
                        os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                
                logger.info("Process killed successfully")
                
            except Exception as kill_error:
                logger.error(f"Failed to kill process: {kill_error}")
                # Fallback - try direct kill
                try:
                    self.process.kill()
                except:
                    pass
    
    def _cleanup(self):
        """Clean up temporary files and process"""
        if self.temp_file and os.path.exists(self.temp_file.name):
            try:
                os.unlink(self.temp_file.name)
                logger.debug("Cleaned up temporary file")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file: {e}")
        
        if self.process:
            try:
                self.process.terminate()
            except:
                pass

# Python-only fallback using requests with threading
class ThreadedDownloader:
    """Fallback using Python threading - less reliable but doesn't need external tools"""
    
    def __init__(self, url, upload_session, max_file_size, encoding='utf-8'):
        self.url = url
        self.upload_session = upload_session
        self.max_file_size = max_file_size
        self.encoding = encoding
        self.session = None
        self.stop_event = threading.Event()
        
    def download_with_threading(self):
        """Download using requests in thread - can be stopped"""
        import requests
        
        content_chunks = []
        bytes_downloaded = 0
        
        def download_worker():
            nonlocal content_chunks, bytes_downloaded
            
            try:
                self.session = requests.Session()
                headers = {'User-Agent': 'EDGI-Portal/1.0 (Environmental Data Portal)'}
                
                response = self.session.get(self.url, headers=headers, stream=True, timeout=30)
                response.raise_for_status()
                
                for chunk in response.iter_content(chunk_size=8192):
                    # Check cancellation AND stop event on EVERY chunk
                    if (self.stop_event.is_set() or 
                        (self.upload_session and self.upload_session.is_cancelled)):
                        logger.info("Download worker stopping due to cancellation")
                        break
                    
                    if chunk:
                        content_chunks.append(chunk)
                        bytes_downloaded += len(chunk)
                        
                        # Check size limit on every chunk
                        if bytes_downloaded > self.max_file_size:
                            logger.error(f"Size limit exceeded: {bytes_downloaded / (1024*1024):.1f}MB")
                            self.stop_event.set()  # Signal to stop
                            break  # Exit immediately
                        
                        if self.upload_session:
                            self.upload_session.update_progress(bytes_downloaded=bytes_downloaded)
                            
            except Exception as e:
                logger.error(f"Download worker error: {e}")
                content_chunks.append(('ERROR', str(e)))
        
        # Start download in thread
        download_thread = threading.Thread(target=download_worker, daemon=True)
        download_thread.start()
        
        # Monitor for cancellation
        start_time = time.time()
        while download_thread.is_alive():
            time.sleep(0.1)  # Check every 100ms
            
            if self.upload_session and self.upload_session.is_cancelled:
                logger.warning("CANCELLATION DETECTED - Stopping threaded download")
                self.stop_event.set()
                if self.session:
                    self.session.close()
                
                # Wait briefly for thread to stop
                download_thread.join(timeout=2.0)
                if download_thread.is_alive():
                    logger.warning("Download thread didn't stop gracefully")
                
                raise CancellationError("Download cancelled by user")
        
        # Check results
        if content_chunks and isinstance(content_chunks[-1], tuple) and content_chunks[-1][0] == 'ERROR':
            raise Exception(content_chunks[-1][1])
        
        if self.stop_event.is_set():
            raise CancellationError("Download cancelled by user")
        
        # Combine chunks
        full_content = b''.join(chunk for chunk in content_chunks if isinstance(chunk, bytes))
        return full_content.decode(self.encoding, errors='replace')

class UploadSession:
    """Enhanced upload session with HTTP connection control for proper cancellation"""
    
    def __init__(self, upload_id, user_id):
        self.upload_id = upload_id
        self.user_id = user_id
        self.is_cancelled = False
        self.created_at = time.time()
        self.phase = "initializing"
        self.bytes_downloaded = 0
        self.total_bytes = 0
        self.rows_processed = 0
        self.table_name = None
        self.abort_event = threading.Event()
        self.last_update = time.time()
        
        # HTTP connection management
        self.active_response = None
        self.http_session = None
        self.http_response = None
        
    def cancel(self):
        """Force immediate cancellation by shutting down the socket"""
        self.is_cancelled = True
        self.phase = "cancelled"
        self.abort_event.set()

        # Force socket shutdown - this is the key to immediate cancellation
        try:
            if hasattr(self, '_socket') and self._socket:
                logger.warning(f"FORCING SOCKET SHUTDOWN for upload {self.upload_id}")
                try:
                    # This is the most effective way to cancel a download
                    self._socket.shutdown(socket.SHUT_RDWR)
                except:
                    # If shutdown fails, just close it
                    self._socket.close()
        except Exception as e:
            logger.error(f"Error shutting down socket: {e}")
        
        # Close any HTTP connections
        try:
            if hasattr(self, 'http_response') and self.http_response:
                self.http_response.close()
        except:
            pass
            
        try:
            if hasattr(self, 'http_session') and self.http_session:
                self.http_session.close()
        except:
            pass
        
        logger.info(f"Upload session {self.upload_id} cancelled - socket shutdown forced")
        
    def update_progress(self, phase=None, bytes_downloaded=None, total_bytes=None, rows_processed=None):
        """Update session progress"""
        if phase:
            self.phase = phase
        if bytes_downloaded is not None:
            self.bytes_downloaded = bytes_downloaded
        if total_bytes is not None:
            self.total_bytes = total_bytes
        if rows_processed is not None:
            self.rows_processed = rows_processed
        self.last_update = time.time()

# Enhanced cancellation tracking with session management
upload_sessions = {}
session_lock = threading.Lock()

def create_upload_session(upload_id, user_id):
    """Create and track upload session"""
    with session_lock:
        session = UploadSession(upload_id, user_id)
        upload_sessions[upload_id] = session
        logger.info(f"Created upload session {upload_id} for user {user_id}")
        return session

def get_upload_session(upload_id):
    """Get upload session"""
    with session_lock:
        return upload_sessions.get(upload_id)

def cleanup_upload_session(upload_id, delay_seconds=5):
    """Clean up upload session with optional delay for late cancellation requests"""
    import threading
    
    def delayed_cleanup():
        import time
        time.sleep(delay_seconds)
        with session_lock:
            session = upload_sessions.pop(upload_id, None)
            if session:
                logger.info(f"Cleaned up upload session {upload_id} (delayed)")
    
    if delay_seconds > 0:
        # Start cleanup in background thread
        cleanup_thread = threading.Thread(target=delayed_cleanup, daemon=True)
        cleanup_thread.start()
    else:
        # Immediate cleanup
        with session_lock:
            session = upload_sessions.pop(upload_id, None)
            if session:
                logger.info(f"Cleaned up upload session {upload_id} (immediate)")

# ============= VALIDATION FUNCTIONS =============

def is_ajax_request(request):
    """ Robust AJAX request detection """
    # Primary AJAX indicators
    x_requested_with = request.headers.get('X-Requested-With', '').lower()
    if x_requested_with == 'xmlhttprequest':
        logger.info(f"AJAX detected via X-Requested-With header: {request.path}")
        return True
    
    # Secondary: Path-based detection for AJAX endpoints
    if '/ajax-' in request.path:
        logger.info(f"AJAX detected via path pattern: {request.path}")
        return True
    
    # Tertiary: Content-Type and Accept headers
    accept_header = request.headers.get('Accept', '').lower()
    content_type = request.headers.get('Content-Type', '').lower()
    
    if 'application/json' in accept_header or 'application/json' in content_type:
        logger.info(f"AJAX detected via JSON headers: {request.path}")
        return True
    
    logger.info(f"NOT AJAX request: {request.path}")
    return False

def validate_excel_headers(df, sheet_name):
    """Validate that Excel sheet has proper table structure with headers"""
    if df is None:
        return False, f"Could not read Excel sheet '{sheet_name}'. Please ensure the file is not corrupted."
    
    if df.empty:
        return False, f"Sheet '{sheet_name}' is empty. Please ensure your Excel file contains data."
    
    if len(df.columns) == 0:
        return False, f"Sheet '{sheet_name}' has no columns. Please ensure your data is in proper table format."
    
    columns = df.columns.tolist()
    all_numeric = all(isinstance(col, (int, float)) and not isinstance(col, bool) for col in columns)
    
    if all_numeric:
        return False, f"Sheet '{sheet_name}' appears to have numeric values instead of column names. Please ensure your data has text headers in the first row."
    
    unnamed_count = sum(1 for col in columns if str(col).startswith('Unnamed:'))
    if unnamed_count > len(columns) * 0.5:
        return False, f"Sheet '{sheet_name}' doesn't appear to have proper column headers. Found {unnamed_count} unnamed columns out of {len(columns)} total."
    
    if len(df) == 0:
        return False, f"Sheet '{sheet_name}' has headers but no data rows. Please add data to your spreadsheet."
    
    return True, None

def validate_google_sheets_url(url):
    """Enhanced Google Sheets URL validation with helpful error messages"""
    url = url.strip()
    
    if not url:
        return False, url, "Please enter a Google Sheets URL"
    
    if url.startswith('http://'):
        url = url.replace('http://', 'https://', 1)
        logger.info("Converted HTTP to HTTPS for Google Sheets URL")
    
    if not url.startswith('https://'):
        if 'docs.google.com' in url or 'drive.google.com' in url:
            url = 'https://' + url
            logger.info("Added HTTPS protocol to URL")
        else:
            return False, url, (
                "Invalid URL format. Please use the full URL starting with https://"
            )
    
    patterns = [
        (r'https://docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]{44})', 'standard'),
        (r'https://docs\.google\.com/spreadsheets/d/e/([a-zA-Z0-9-_]{56})', 'published'),
        (r'https://drive\.google\.com/file/d/([a-zA-Z0-9-_]+)/view', 'drive'),
        (r'https://docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]+)/edit', 'edit'),
    ]
    
    sheet_id = None
    url_type = None
    
    for pattern, ptype in patterns:
        match = re.search(pattern, url)
        if match:
            sheet_id = match.group(1)
            url_type = ptype
            
            if len(sheet_id) < 30:
                return False, url, (
                    f"Invalid sheet ID length ({len(sheet_id)} characters). "
                    f"Google Sheets IDs are typically 44+ characters long."
                )
            break
    
    if not sheet_id:
        if 'google.com' in url:
            if 'drive.google.com' in url and '/folders/' in url:
                return False, url, (
                    "This appears to be a Google Drive folder link, not a Sheets link. "
                    "Please open a specific spreadsheet and copy its URL."
                )
            elif 'docs.google.com' in url and '/document/' in url:
                return False, url, (
                    "This is a Google Docs link, not a Sheets link. "
                    "Please use a Google Sheets spreadsheet URL."
                )
            elif 'forms.google.com' in url:
                return False, url, (
                    "This is a Google Forms link. "
                    "To import form responses, open the linked spreadsheet from your form."
                )
            else:
                return False, url, (
                    "This Google link doesn't appear to be a Sheets URL. "
                    "Please open your spreadsheet and copy the URL from the address bar."
                )
        else:
            return False, url, (
                "Invalid Google Sheets URL format. Please:\n"
                "1. Open your Google Sheet\n"
                "2. Click Share > Copy link\n"
                "3. Make sure it's set to 'Anyone with the link can view'\n"
                "4. Paste the link here"
            )
    
    gid = 0
    if '#gid=' in url:
        try:
            gid = int(url.split('#gid=')[1].split('&')[0])
            logger.info(f"Extracted GID {gid} from URL")
        except (ValueError, IndexError):
            logger.warning("Could not extract valid GID from URL")
    
    return True, url, {
        'sheet_id': sheet_id,
        'url_type': url_type,
        'gid': gid,
        'message': f"Valid {url_type} Google Sheets URL detected"
    }

def validate_csv_structure_enhanced(csv_content, max_sample_rows=100):
    """Enhanced CSV validation with better error detection and user-friendly messages"""
    if not csv_content:
        return False, "CSV file is empty", None
    
    csv_content = csv_content.strip()
    if not csv_content:
        return False, "CSV file contains only whitespace", None
    
    if len(csv_content) < 10:
        return False, "CSV content too short to be valid", None
    
    lines = csv_content.split('\n')
    non_empty_lines = [line for line in lines if line.strip()]
    
    if len(non_empty_lines) == 0:
        return False, "CSV file contains no data lines", None
    
    first_line = non_empty_lines[0]
    
    delimiters = [',', '\t', ';', '|']
    delimiter_counts = {}
    
    for delim in delimiters:
        count = first_line.count(delim)
        if count > 0:
            delimiter_counts[delim] = count
    
    if not delimiter_counts:
        return False, (
            "No standard delimiters (comma, tab, semicolon, pipe) found in the file. "
            "This might be a single-column file or not a properly formatted CSV. "
            "Please ensure your file uses standard CSV formatting."
        ), None
    
    delimiter = max(delimiter_counts.keys(), key=delimiter_counts.get)
    expected_columns = delimiter_counts[delimiter] + 1
    
    logger.info(f"Detected delimiter: '{delimiter}' with {expected_columns} expected columns")
    
    try:
        csv_reader = csv.reader(io.StringIO(csv_content), delimiter=delimiter)
        rows = list(csv_reader)
    except csv.Error as e:
        return False, f"CSV parsing error: {str(e)}", None
    
    if len(rows) == 0:
        return False, "No rows could be parsed from CSV", None
    
    headers = rows[0] if rows else []
    if not headers:
        return False, "CSV file has no headers", None
    
    empty_headers = sum(1 for h in headers if not str(h).strip())
    if empty_headers > len(headers) * 0.5:
        return False, (
            f"Too many empty column headers ({empty_headers} out of {len(headers)}). "
            f"Please ensure all columns have names."
        ), None
    
    header_counts = {}
    for h in headers:
        clean_h = str(h).strip().lower()
        if clean_h:
            header_counts[clean_h] = header_counts.get(clean_h, 0) + 1
    
    duplicates = [h for h, count in header_counts.items() if count > 1]
    if duplicates:
        return False, (
            f"Duplicate column names found: {', '.join(duplicates[:5])}. "
            f"Please ensure all column names are unique."
        ), None
    
    if len(rows) < 2:
        return False, (
            "CSV file has headers but no data rows. "
            "Please ensure your file contains actual data."
        ), None
    
    inconsistent_rows = []
    empty_rows = 0
    sampled_rows = min(max_sample_rows, len(rows) - 1)
    
    for i in range(1, sampled_rows + 1):
        if i >= len(rows):
            break
            
        row = rows[i]
        
        if not any(str(cell).strip() for cell in row):
            empty_rows += 1
            continue
        
        if len(row) != len(headers):
            inconsistent_rows.append({
                'row_num': i + 1,
                'expected': len(headers),
                'actual': len(row)
            })
    
    if len(inconsistent_rows) > sampled_rows * 0.2:
        sample_errors = inconsistent_rows[:3]
        error_details = []
        for err in sample_errors:
            error_details.append(
                f"Row {err['row_num']}: {err['actual']} columns (expected {err['expected']})"
            )
        
        return False, (
            f"CSV structure is inconsistent. Found {len(inconsistent_rows)} "
            f"problematic rows in first {sampled_rows} rows:\n" +
            "\n".join(error_details) +
            "\n\nPlease ensure all rows have the same number of columns."
        ), None
    
    if empty_rows > sampled_rows * 0.5:
        return False, (
            f"Too many empty rows ({empty_rows} out of {sampled_rows} sampled). "
            f"Please clean your data by removing empty rows."
        ), None
    
    metadata = {
        'delimiter': delimiter,
        'header_count': len(headers),
        'headers': headers[:10],
        'total_rows': len(rows),
        'data_rows': len(rows) - 1,
        'empty_rows': empty_rows,
        'inconsistent_rows': len(inconsistent_rows),
        'sample_size': sampled_rows
    }
    
    return True, None, metadata

# ============= CONNECTION POOL =============

class SQLiteConnectionPool:
    """Thread-safe SQLite connection pool for concurrent operations"""
    
    def __init__(self, db_path, max_connections=3, ultra_pragmas=None):
        self.db_path = db_path
        self.max_connections = max_connections
        self.ultra_pragmas = ultra_pragmas or []
        self.pool = Queue(maxsize=max_connections)
        self.created_connections = 0
        self.lock = threading.Lock()
        
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
                    # Test if connection is still good
                    conn.execute("SELECT 1").fetchone()
                    # If successful, try to clean up any remaining transaction
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        # Ignore "no transaction is active"
                        pass
                except sqlite3.Error:
                    # Connection is broken, don't return to pool
                    pass
            raise e
            
        finally:
            # Return connection to pool or close if temporary
            if conn:
                try:
                    # Test if connection is still good
                    try:
                        conn.execute("SELECT 1").fetchone()
                        # Clean up any remaining transaction
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.OperationalError:
                            pass
                    except sqlite3.Error:
                        # Connection is broken, don't return to pool
                        conn.close()
                        logger.warning("Discarded broken connection")
                        return
                    
                    # Try to return to pool
                    try:
                        self.pool.put_nowait(conn)
                    except:
                        # Pool is full, close this connection
                        conn.close()
                        logger.debug("Closed temporary connection (pool full)")
                        
                except sqlite3.Error:
                    # Connection cleanup failed
                    try:
                        conn.close()
                    except:
                        pass
                    logger.warning("Discarded broken connection during cleanup")
    
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

# ============= OPTIMIZED UPLOADER =============

class PooledUltraOptimizedUploader:
    """Ultra-optimized uploader with connection pooling and enhanced cancellation"""
    
    ULTRA_PRAGMAS = [
        "PRAGMA synchronous = NORMAL",
        "PRAGMA journal_mode = WAL",
        "PRAGMA cache_size = -1000000",  # 1GB cache
        "PRAGMA temp_store = MEMORY",
        "PRAGMA mmap_size = 268435456",  # 256MB memory-mapped I/O
        "PRAGMA threads = 4",  # Enable multi-threading
    ]
    
    def __init__(self, db_path, ultra_mode=False, max_connections=3, upload_session=None):
        self.db_path = db_path
        self.ultra_mode = ultra_mode
        self.upload_session = upload_session
        self.connection_pool = SQLiteConnectionPool(
            db_path, 
            max_connections=max_connections,
            ultra_pragmas=self.ULTRA_PRAGMAS
        )
    
    def process_excel_ultra_fast(self, file_content, table_name, sheet_name=None, replace_existing=False):
        """Process Excel files with proper error handling and cancellation support"""
        if not PANDAS_AVAILABLE:
            raise ValueError("Excel processing not available. Install with: pip install pandas openpyxl")
        
        start_time = time.time()
        
        try:
            import pandas as pd
            
            if self.upload_session and self.upload_session.is_cancelled:
                raise CancellationError("Excel processing cancelled")
            
            logger.info(f"Processing Excel file for table '{table_name}'")
            
            # Determine file extension and check engine availability
            file_ext = '.xlsx'  # Default assumption
            engine_available, engine_error = check_excel_engine_availability(file_ext)
            if not engine_available:
                # Try .xls engine
                file_ext = '.xls'
                engine_available, engine_error = check_excel_engine_availability(file_ext)
                if not engine_available:
                    raise ValueError("Excel processing requires openpyxl (for .xlsx) or xlrd (for .xls). Please install the appropriate package.")
            
            # Read Excel file
            try:
                # Use openpyxl for .xlsx files for better compatibility
                engine = 'openpyxl' if file_ext == '.xlsx' else 'xlrd'
                
                df = pd.read_excel(
                    io.BytesIO(file_content),
                    engine=engine,
                    dtype=str,
                    na_filter=False,
                    keep_default_na=False
                )
                
                if df is None or df.empty:
                    raise ValueError("Excel file is empty or unreadable")
                    
            except ImportError as ie:
                if 'openpyxl' in str(ie):
                    raise ValueError("Excel support missing. Install with: pip install openpyxl")
                elif 'xlrd' in str(ie):
                    raise ValueError("Excel support missing. Install with: pip install xlrd")
                else:
                    raise ValueError(f"Excel processing error: {str(ie)}")
            except Exception as e:
                raise ValueError(f"Cannot read Excel file: {str(e)}")
            
            # Validate structure
            is_valid, error_msg = validate_excel_headers(df, "Sheet1")
            if not is_valid:
                raise ValueError(error_msg)
            
            # Clean column names
            df.columns = [self._clean_column_name(str(col)) for col in df.columns]
            df.columns = self._ensure_unique_column_names(df.columns.tolist())
            
            # Remove empty rows
            df = df.dropna(how='all')
            if df.empty:
                raise ValueError("No data found after removing empty rows")
            
            # Convert everything to strings and handle pandas-specific NaN values
            for col in df.columns:
                df[col] = df[col].astype(str).replace(['nan', 'NaN', 'None', '<NA>'], '')
            
            logger.info(f"Excel data prepared: {len(df)} rows, {len(df.columns)} columns")
            
            # Insert to database
            total_rows = len(df)
            inserted_rows = 0
            
            with self.connection_pool.get_connection() as conn:
                if self.upload_session and self.upload_session.is_cancelled:
                    raise CancellationError("Cancelled before database operations")
                
                if replace_existing:
                    conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
                
                # Create table
                columns_sql = ', '.join([f'[{col}] TEXT' for col in df.columns])
                conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns_sql})")
                
                # Insert data in batches
                batch_size = 5000
                conn.execute("BEGIN IMMEDIATE")
                
                try:
                    placeholders = ','.join(['?' for _ in df.columns])
                    insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
                    
                    for start_idx in range(0, total_rows, batch_size):
                        if self.upload_session and self.upload_session.is_cancelled:
                            raise CancellationError("Cancelled during processing")
                        
                        end_idx = min(start_idx + batch_size, total_rows)
                        batch_df = df.iloc[start_idx:end_idx]
                        
                        # Convert to tuples
                        batch_data = [tuple(row) for row in batch_df.values]
                        conn.executemany(insert_sql, batch_data)
                        inserted_rows += len(batch_data)
                        
                        if self.upload_session:
                            self.upload_session.update_progress(rows_processed=inserted_rows)
                        
                        logger.info(f"Processed: {inserted_rows:,} / {total_rows:,} rows")
                    
                    conn.execute("COMMIT")
                    
                except Exception as insert_error:
                    conn.execute("ROLLBACK")
                    raise Exception(f"Database insert failed: {str(insert_error)}")
            
            elapsed_time = time.time() - start_time
            rows_per_second = int(inserted_rows / elapsed_time) if elapsed_time > 0 else 0
            
            if self.upload_session:
                self.upload_session.update_progress("completed", rows_processed=inserted_rows)
            
            logger.info(f"EXCEL COMPLETE: {inserted_rows:,} rows in {elapsed_time:.2f}s")
            
            return {
                'table_name': table_name,
                'rows_inserted': inserted_rows,
                'columns': len(df.columns),
                'time_elapsed': elapsed_time,
                'rows_per_second': rows_per_second,
                'strategy': 'excel_ultra_fast',
                'file_type': 'excel'
            }
            
        except CancellationError:
            raise
        except Exception as e:
            logger.error(f"Excel processing failed: {e}")
            raise Exception(f"Excel processing failed: {str(e)}")

    def stream_csv_ultra_fast_pooled(self, response_or_content, table_name, replace_existing=False, max_file_size=None, upload_id=None):
        """Ultra-fast CSV processing - simplified for subprocess approach"""
        
        if isinstance(response_or_content, str):
            # Content string - use pooled batch processing (most common case now)
            return self._process_content_with_pool(
                response_or_content, table_name, replace_existing
            )
        elif hasattr(response_or_content, 'iter_content'):
            # Legacy streaming response - convert to string first
            logger.warning("Converting streaming response to string - consider using subprocess download")
            content_chunks = []
            for chunk in response_or_content.iter_content(decode_unicode=True):
                if self.upload_session and self.upload_session.is_cancelled:
                    raise CancellationError("Processing cancelled during stream conversion")
                content_chunks.append(chunk)
            
            csv_content = ''.join(content_chunks)
            return self._process_content_with_pool(
                csv_content, table_name, replace_existing
            )
        else:
            raise ValueError(f"Unsupported input type: {type(response_or_content)}")
    
    def _process_content_with_pool(self, csv_content, table_name, replace_existing):
        """Process CSV content using connection pool with cancellation checks"""
        start_time = time.time()
        
        # Handle different line ending formats
        csv_content = csv_content.replace('\r\n', '\n').replace('\r', '\n')
        csv_content = csv_content.replace('\x00', '')
        
        if csv_content.startswith('\ufeff'):
            csv_content = csv_content[1:]
        
        content_size_bytes = len(csv_content.encode('utf-8'))
        content_size_mb = content_size_bytes / (1024 * 1024)
        
        # Parse headers efficiently
        first_line_end = csv_content.find('\n')
        if first_line_end == -1:
            if ',' in csv_content or '\t' in csv_content:
                potential_headers = self._parse_csv_line(csv_content)
                if len(potential_headers) > 0:
                    logger.warning("CSV appears to have only headers, no data rows")
                    header_line = csv_content
                    csv_data = ""
                else:
                    raise ValueError("Invalid CSV format - unable to parse")
            else:
                raise ValueError("Invalid CSV - no line breaks or delimiters found")
        else:
            header_line = csv_content[:first_line_end]
            csv_data = csv_content[first_line_end + 1:]
        
        headers = [self._clean_column_name(h.strip()) for h in self._parse_csv_line(header_line)]
        
        if not headers:
            raise ValueError("No headers found in CSV file")
        
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
                if replace_existing:
                    conn.execute(f"DROP TABLE IF EXISTS [{table_name}]")
                
                columns = ', '.join([f'[{header}] TEXT' for header in headers])
                conn.execute(f"CREATE TABLE IF NOT EXISTS [{table_name}] ({columns})")
                
                if csv_data and csv_data.strip():
                    placeholders = ','.join(['?' for _ in headers])
                    insert_sql = f"INSERT INTO [{table_name}] VALUES ({placeholders})"
                    
                    conn.execute("BEGIN IMMEDIATE")
                    
                    try:
                        total_rows = self._process_csv_data_robust(
                            conn, csv_data, insert_sql, 
                            headers, batch_size
                        )
                        
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
        
        if self.upload_session:
            self.upload_session.update_progress("completed", rows_processed=total_rows)
        
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
        """Robust CSV data processing with cancellation checks"""
        total_rows = 0
        batch_data = []
        num_columns = len(headers)
        
        csv_reader = csv.reader(io.StringIO(csv_data))
        
        for row_data in csv_reader:
            # Check cancellation frequently even for in-memory processing
            if self.upload_session and self.upload_session.is_cancelled:
                raise CancellationError("Upload cancelled during CSV processing")
            
            if not any(cell.strip() for cell in row_data):
                continue
            
            # Normalize row length
            if len(row_data) < num_columns:
                row_data.extend([''] * (num_columns - len(row_data)))
            elif len(row_data) > num_columns:
                row_data = row_data[:num_columns]
            
            batch_data.append(tuple(row_data))
            
            if len(batch_data) >= batch_size:
                # Check cancellation before batch insert
                if self.upload_session and self.upload_session.is_cancelled:
                    raise CancellationError("Upload cancelled before batch insert")
                
                conn.executemany(insert_sql, batch_data)
                total_rows += len(batch_data)
                batch_data.clear()
                
                if self.upload_session:
                    self.upload_session.update_progress(rows_processed=total_rows)
                
                if total_rows % (batch_size * 2) == 0:
                    logger.info(f"POOLED: Processed {total_rows:,} rows")
        
        if batch_data:
            if self.upload_session and self.upload_session.is_cancelled:
                raise CancellationError("Upload cancelled before final batch")
            
            conn.executemany(insert_sql, batch_data)
            total_rows += len(batch_data)
        
        return total_rows
    
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

# ============= HELPER FUNCTIONS =============

def get_optimal_uploader(file_size, db_path, use_ultra_mode=False, upload_session=None):
    """Choose optimal uploader with connection pooling and cancellation support"""
    max_connections = 3 if file_size > 100 * 1024 * 1024 else 2
    return PooledUltraOptimizedUploader(
        db_path, 
        ultra_mode=use_ultra_mode, 
        max_connections=max_connections,
        upload_session=upload_session
    )

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

def parse_multipart_form_data_from_ajax(body, content_type):
    """Parse multipart form data from AJAX requests with error handling"""
    try:
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[-1].split(';')[0].strip()
        
        if not boundary:
            logger.error(f"No boundary found in content-type: {content_type}")
            return {}, {}
        
        logger.debug(f"Using boundary: {boundary}")
        
        forms, files = parse_multipart_form_data(body, boundary)
        
        processed_forms = {}
        for key, value in forms.items():
            if isinstance(value, list) and len(value) > 0:
                processed_forms[key] = value[0]
            else:
                processed_forms[key] = value if isinstance(value, str) else str(value)
        
        logger.debug(f"Parsed forms: {list(processed_forms.keys())}")
        logger.debug(f"Parsed files: {list(files.keys())}")
        
        return processed_forms, files
        
    except Exception as e:
        logger.error(f"Error parsing multipart data from AJAX: {e}")
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

def get_google_sheet_name_from_url(url, sheet_index=0):
    """Try to extract a meaningful name from Google Sheets URL - FIRST SHEET ONLY"""
    from datetime import datetime
    import re
    
    # REMOVED: Complex sheet detection logic since we only use first sheet
    timestamp = datetime.now().strftime('%m%d_%H%M')
    return f"google_sheet_first_{timestamp}"

def get_csv_name_from_url(url):
    """Extract a meaningful table name from CSV URL"""
    from datetime import datetime
    import re
    
    parsed = urlparse(url)
    path = parsed.path
    domain = parsed.netloc.lower()
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    filename = os.path.basename(path)
    
    if filename and filename != '':
        name = os.path.splitext(filename)[0]
        
        generic_names = {
            'download', 'export', 'data', 'csv', 'file', 'output', 
            'report', 'dataset', 'results', 'table', 'list',
            'rows', 'content', 'info', 'details'
        }
        
        if name and name.lower() not in generic_names and len(name) >= 3:
            clean_name = sanitize_filename_for_table(name)
            if clean_name and len(clean_name) >= 3:
                return clean_name
    
    path_parts = [part for part in path.split('/') if part and part.lower() not in {
        'api', 'v1', 'v2', 'data', 'export', 'download', 'csv', 'files'
    }]
    
    if path_parts:
        meaningful_part = path_parts[-1]
        if meaningful_part and len(meaningful_part) >= 3:
            meaningful_part = os.path.splitext(meaningful_part)[0]
            clean_name = sanitize_filename_for_table(meaningful_part)
            if clean_name and len(clean_name) >= 3 and clean_name.lower() not in generic_names:
                return clean_name
    
    if domain:
        domain_parts = domain.split('.')
        
        if len(domain_parts) >= 2:
            main_domain = domain_parts[-2]
        else:
            main_domain = domain_parts[0]
        
        domain_clean = re.sub(r'[^a-zA-Z0-9]', '_', main_domain)
        
        if len(domain_clean) > 15:
            domain_clean = domain_clean[:15]
        
        if domain_clean and len(domain_clean) >= 3:
            timestamp = datetime.now().strftime('%m%d_%H%M')
            return f"{domain_clean}_{timestamp}"
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')
    return f"web_csv_{timestamp}"

# ============= FETCH FUNCTIONS =============

async def fetch_sheet_data(sheet_url, datasette=None, upload_session=None):
    """Google Sheets fetching with proper cancellation - FIRST SHEET ONLY"""
    try:
        sheet_url = sheet_url.rstrip('/')
        
        patterns = [
            r'docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]{44})',
            r'docs\.google\.com/spreadsheets/d/e/([a-zA-Z0-9-_]{56})',
            r'drive\.google\.com/file/d/([a-zA-Z0-9-_]+)',
            r'/spreadsheets/d/([a-zA-Z0-9-_]{30,60})'
        ]
        
        sheet_id = None
        for pattern in patterns:
            match = re.search(pattern, sheet_url)
            if match:
                sheet_id = match.group(1)
                if len(sheet_id) >= 30:
                    break
                else:
                    sheet_id = None
        
        if not sheet_id:
            raise ValueError("Invalid Google Sheets URL format. Please use the sharing URL from Google Sheets.")
        
        logger.info(f"Extracted sheet ID: {sheet_id}")
        
        # ALWAYS use first sheet (gid=0) - ignore any gid in URL
        gid = 0
        logger.info("Using first sheet only (gid=0)")
        
        # REMOVED: Multiple export URL attempts - use only first sheet
        export_urls = [
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid=0",
            f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv",
            f"https://docs.google.com/spreadsheets/d/e/{sheet_id}/pub?output=csv&gid=0",
            f"https://docs.google.com/spreadsheets/d/e/{sheet_id}/pub?output=csv"
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/csv, text/plain, application/csv, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
        
        if datasette:
            max_file_size = await get_max_file_size(datasette)
        else:
            max_file_size = 500 * 1024 * 1024
        
        last_error = None
        
        for i, csv_url in enumerate(export_urls):
            try:
                # Check cancellation before each attempt
                if upload_session and upload_session.is_cancelled:
                    raise CancellationError("Import cancelled before starting Google Sheets fetch")
                
                logger.info(f"Attempting export method {i+1}: {csv_url}")

                try:
                    response = requests.get(csv_url, timeout=30, headers=headers, allow_redirects=True)
                    
                    if response.status_code == 401:
                        last_error = "Google Sheet access denied - make sure the sheet is publicly accessible"
                        continue
                    elif response.status_code == 400:
                        last_error = "Google Sheet access denied - sheet may be private"
                        continue
                    elif response.status_code == 404:
                        last_error = f"Google Sheet not found with this URL format (method {i+1})"
                        continue
                    elif response.status_code not in [200]:
                        last_error = f"Failed to access Google Sheet (HTTP {response.status_code})"
                        continue
                    
                    if response.url and 'accounts.google.com' in response.url:
                        last_error = "Google Sheet is private - redirected to login page"
                        continue
                    
                    # Check cancellation before processing content
                    if upload_session and upload_session.is_cancelled:
                        raise CancellationError("Google Sheets download cancelled")
                    
                    csv_content = response.text
                    
                    if not csv_content.strip():
                        last_error = f"Google Sheet appears to be empty (method {i+1})"
                        continue
                    
                    if csv_content.strip().startswith('<!DOCTYPE html') or '<html' in csv_content:
                        last_error = f"Received HTML instead of CSV - sheet may be private (method {i+1})"
                        continue
                    
                    if not (',' in csv_content or '\t' in csv_content):
                        last_error = f"Google Sheet doesn't contain valid CSV data (method {i+1})"
                        continue
                    
                    # CHECK FILE SIZE LIMIT
                    content_size = len(csv_content.encode('utf-8'))
                    if content_size > max_file_size:
                        size_mb = content_size / (1024 * 1024)
                        max_mb = max_file_size / (1024 * 1024)
                        raise ValueError(f"Google Sheets data ({size_mb:.1f}MB) exceeds maximum file size limit ({max_mb:.0f}MB)")
                    
                    final_size_mb = content_size / (1024 * 1024)
                    logger.info(f"Successfully retrieved first sheet CSV data using export method {i+1} ({final_size_mb:.1f}MB)")
                    
                    if upload_session:
                        upload_session.update_progress(phase="processing")
                    
                    return csv_content
                    
                except CancellationError:
                    raise
                except requests.exceptions.ChunkedEncodingError:
                    if upload_session and upload_session.is_cancelled:
                        raise CancellationError("Import cancelled during download")
                    raise
                except requests.RequestException as req_error:
                    last_error = f"Network error accessing Google Sheets (method {i+1}): {str(req_error)}"
                    continue
                
            except CancellationError:
                raise
            except ValueError as val_error:
                if "exceeds maximum file size" in str(val_error):
                    raise  # Re-raise size limit errors
                last_error = f"Export method {i+1} failed: {str(val_error)}"
                continue
            except Exception as method_error:
                last_error = f"Export method {i+1} failed: {str(method_error)}"
                continue
                        
        if last_error:
            if "private" in last_error.lower() or "access denied" in last_error.lower():
                raise ValueError(
                    "Google Sheet is not publicly accessible. "
                    "Please make it public by clicking Share > Anyone with the link can view."
                )
            elif "exceeds maximum file size" in last_error.lower():
                raise ValueError(last_error)
            else:
                raise ValueError(f"Unable to import from Google Sheet (first sheet): {last_error}")
        else:
            raise ValueError("Unable to export data from Google Sheet using any method")
            
    except CancellationError:
        logger.info("Google Sheets fetch cancelled by user")
        raise
    except Exception as e:
        logger.error(f"Google Sheets fetch error: {str(e)}")
        raise ValueError(f"Google Sheets import failed: {str(e)}")
                
async def fetch_csv_from_url_subprocess(datasette, csv_url, encoding='auto', upload_session=None):
    """Download CSV using subprocess - truly cancellable"""
    try:
        await validate_csv_url(datasette, csv_url)
        max_file_size = await get_max_file_size(datasette)
        
        logger.info(f"Starting SUBPROCESS cancellable download: {csv_url}")
        
        downloader = SubprocessDownloader(
            url=csv_url,
            upload_session=upload_session,
            max_file_size=max_file_size,
            encoding=encoding if encoding != 'auto' else 'utf-8'
        )
        
        # Download and return content
        content = downloader.download_with_subprocess()
        return content
        
    except Exception as e:
        logger.error(f"Subprocess downloader setup error: {e}")
        raise ValueError(f"Download failed: {str(e)}")

async def fetch_csv_from_url_threaded(datasette, csv_url, encoding='auto', upload_session=None):
    """Fallback threaded download when external tools unavailable"""
    try:
        await validate_csv_url(datasette, csv_url)
        max_file_size = await get_max_file_size(datasette)
        
        logger.info(f"Starting THREADED cancellable download: {csv_url}")
        
        downloader = ThreadedDownloader(
            url=csv_url,
            upload_session=upload_session,
            max_file_size=max_file_size,
            encoding=encoding if encoding != 'auto' else 'utf-8'
        )
        
        content = downloader.download_with_threading()
        return content
        
    except Exception as e:
        logger.error(f"Threaded downloader error: {e}")
        raise ValueError(f"Download failed: {str(e)}")

# Fix for missing function referenced in URL upload
async def fetch_csv_from_url_chunked(datasette, csv_url, encoding='auto', upload_session=None):
    """Wrapper function to choose best download method"""
    try:
        # First try subprocess method
        return await fetch_csv_from_url_subprocess(datasette, csv_url, encoding, upload_session)
    except ValueError as e:
        if "curl" in str(e) or "wget" in str(e):
            # External tools not available, use threaded fallback
            logger.warning("External download tools not available, using threaded fallback")
            return await fetch_csv_from_url_threaded(datasette, csv_url, encoding, upload_session)
        else:
            # Re-raise other errors
            raise
    
# ============= MAIN HANDLERS =============

async def enhanced_upload_page(datasette, request):
    """Upload page handler that properly routes AJAX vs regular requests"""
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
        if is_ajax_request(request):
            logger.warning(f"AJAX request received at main form handler: {request.path}")
            return Response.json({
                "success": False,
                "error": "AJAX request received at wrong endpoint. Check your JavaScript."
            }, status=400)
        
        logger.info(f"Regular form submission to main handler: {request.path}")
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
        error_context = await categorize_upload_error(str(e), "enhanced_upload", datasette)
        return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)

async def handle_file_upload_optimized(datasette, request, db_name, actor, max_file_size):
    """COMPLETE file upload handler with FULL Excel support restored"""
    try:
        is_ajax = is_ajax_request(request)
        
        body = await request.post_body()
        
        if len(body) > max_file_size:
            size_mb = max_file_size / (1024*1024)
            error_context = await categorize_upload_error(
                f"File size exceeds {size_mb:.0f}MB limit", "file", datasette
            )
            if is_ajax:
                return create_error_response(error_context, is_ajax=True)
            else:
                return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)
        
        content_type = request.headers.get('content-type', '')
        boundary = content_type.split('boundary=')[-1].split(';')[0].strip() if 'boundary=' in content_type else None
        
        if not boundary:
            error_msg = "Invalid form data - no boundary found"
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
        
        custom_table_name = forms.get('table_name', '').strip()
        replace_existing = forms.get('replace_existing') == 'on' or 'replace_existing' in forms
        upload_id = forms.get('upload_id')
        
        file_size = len(file_content)
        file_size_mb = file_size / (1024 * 1024)
        logger.info(f"Processing file: {filename} ({file_size_mb:.1f}MB), replace_existing={replace_existing}")
        
        # Create upload session for cancellation support
        upload_session = None
        if upload_id:
            upload_session = create_upload_session(upload_id, actor["id"])
        
        try:
            # Determine table name
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
            
            if replace_existing:
                table_name = base_table_name
                logger.info(f"Using table name for replacement: {table_name}")
            else:
                table_name = await suggest_unique_name(base_table_name, datasette, db_name)
                logger.info(f"Generated unique table name: {table_name}")
            
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
            
            # Determine file type and processing method
            file_ext = os.path.splitext(filename)[1].lower()
            use_ultra_mode = file_size > 50 * 1024 * 1024
            uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode, upload_session)
            
            try:
                # COMPLETE Excel processing
                if file_ext in ['.xlsx', '.xls']:
                    logger.info(f"Processing Excel file: {filename}")
                    
                    # Enhanced Excel validation
                    try:
                        # Quick validation read to check file integrity
                        test_df = pd.read_excel(io.BytesIO(file_content), nrows=5)
                        is_valid, error_msg = validate_excel_headers(test_df, "Sheet1")
                        
                        if not is_valid:
                            error_context = await categorize_upload_error(error_msg, "excel", datasette)
                            if is_ajax:
                                return create_error_response(error_context, is_ajax=True)
                            else:
                                return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)
                                
                    except Exception as validation_error:
                        error_msg = f"Cannot read Excel file: {str(validation_error)}"
                        logger.error(f"Excel validation error: {validation_error}")
                        error_context = await categorize_upload_error(error_msg, "excel", datasette)
                        if is_ajax:
                            return create_error_response(error_context, is_ajax=True)
                        else:
                            return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)
                    
                    # Process Excel file using the restored method
                    try:
                        result = uploader.process_excel_ultra_fast(file_content, table_name, None, replace_existing)
                    except Exception as excel_error:
                        logger.error(f"Excel processing failed: {excel_error}")
                        error_context = await categorize_upload_error(str(excel_error), "excel", datasette)
                        if is_ajax:
                            return create_error_response(error_context, is_ajax=True)
                        else:
                            return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)
                    
                # CSV processing
                elif file_ext in ['.csv', '.txt', '.tsv']:
                    logger.info(f"Processing CSV file: {filename}")
                    
                    # Decode CSV content
                    csv_content = None
                    for encoding in ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']:
                        try:
                            csv_content = file_content.decode(encoding)
                            logger.info(f"Successfully decoded CSV with {encoding} encoding")
                            break
                        except UnicodeDecodeError:
                            continue
                    
                    if not csv_content:
                        error_msg = "Cannot decode CSV file. Please ensure it's saved in UTF-8 encoding."
                        error_context = await categorize_upload_error(error_msg, "csv", datasette)
                        if is_ajax:
                            return create_error_response(error_context, is_ajax=True)
                        else:
                            return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)
                    
                    # Validate CSV structure
                    is_valid, error_msg, csv_metadata = validate_csv_structure_enhanced(csv_content)
                    
                    if not is_valid:
                        error_context = await categorize_upload_error(error_msg, "csv", datasette)
                        if is_ajax:
                            return create_error_response(error_context, is_ajax=True)
                        else:
                            return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)
                    
                    logger.info(f"CSV validated: {csv_metadata['data_rows']} rows, "
                              f"{csv_metadata['header_count']} columns, "
                              f"delimiter: '{csv_metadata['delimiter']}'")
                    
                    # Process CSV file
                    result = uploader.stream_csv_ultra_fast_pooled(csv_content, table_name, replace_existing)
                
                else:
                    raise ValueError(f"Unsupported file type: {file_ext}. Use CSV, TSV, TXT, or Excel files")
            
            finally:
                uploader.close_pool()
                if upload_session:
                    cleanup_upload_session(upload_id)
            
            # Update database timestamp
            await update_database_timestamp(datasette, db_name)
            
            # Sync table visibility
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
                datasette, actor.get("id"), "optimized_upload", 
                f"Uploaded {result['rows_inserted']:,} rows to '{table_name}' from '{filename}'",
                {
                    "source_type": "file",
                    "table_name": table_name,
                    "filename": filename,
                    "file_type": file_ext,
                    "record_count": result['rows_inserted'],
                    "replace_existing": replace_existing,
                    "file_size_mb": file_size_mb
                }
            )
            
            # Create success message
            success_msg = f"SUCCESS: Uploaded {result['rows_inserted']:,} rows to table '{table_name}' in {result['time_elapsed']:.1f}s"
            
            if is_ajax:
                return Response.json({
                    "success": True,
                    "message": success_msg,
                    "redirect_url": "/manage-databases",
                    "stats": f"{result['rows_inserted']:,} rows processed at {result.get('rows_per_second', 0):,} rows/sec"
                })
            else:
                return create_redirect_response(request, db_name, success_msg)
        
        except CancellationError as ce:
            logger.info(f"File upload cancelled: {ce}")
            if upload_session:
                cleanup_upload_session(upload_id)
            
            if is_ajax:
                return Response.json({"success": False, "error": "Upload cancelled by user"}, status=499)
            else:
                return create_redirect_response(request, db_name, "Upload cancelled by user", is_error=True)
            
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        error_context = await categorize_upload_error(str(e), "file", datasette)
        
        if is_ajax_request(request):
            return create_error_response(error_context, is_ajax=True)
        else:
            return create_redirect_response(request, db_name, error_context["user_message"], is_error=True)

# ============= AJAX HANDLERS =============

async def ajax_file_upload_handler(datasette, request):
    """Enhanced AJAX file upload handler with cancellation support"""
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
        error_context = await categorize_upload_error(str(e), "ajax_file_upload", datasette)
        return Response.json({"success": False, "error": error_context["user_message"]}, status=500)

async def ajax_sheets_upload_handler(datasette, request):
    """Enhanced AJAX Google Sheets upload handler - FIRST SHEET ONLY"""
    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({"success": False, "error": "Authentication required. Please log in again."}, status=401)

        path_parts = request.path.strip('/').split('/')
        if len(path_parts) < 2:
            return Response.json({"success": False, "error": "Invalid URL format"}, status=400)
        
        db_name = path_parts[1]
        
        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({"success": False, "error": "You don't have permission to modify this database"}, status=403)

        content_type = request.headers.get('content-type', '')
        body = await request.post_body()
        
        forms, files = parse_multipart_form_data_from_ajax(body, content_type)
        
        sheets_url = forms.get('sheets_url', '').strip()
        # REMOVED: sheet_index = int(forms.get('sheet_index', '0') or '0')  # Always use first sheet
        custom_table_name = forms.get('table_name', '').strip()
        replace_existing = forms.get('replace_existing') == 'on'
        upload_id = forms.get('upload_id')
        
        logger.debug(f"Google Sheets params: url='{sheets_url}', "
                    f"table_name='{custom_table_name}', replace={replace_existing}, upload_id={upload_id}")
        
        is_valid, cleaned_url, validation_result = validate_google_sheets_url(sheets_url)

        if not is_valid:
            return Response.json({
                "success": False,
                "error": validation_result
            }, status=400)

        if isinstance(validation_result, dict):
            logger.info(f"Google Sheets validated: {validation_result['message']}, "
                    f"Sheet ID: {validation_result['sheet_id']}")
        
        # Create upload session for cancellation support
        upload_session = None
        if upload_id:
            upload_session = create_upload_session(upload_id, actor["id"])
            logger.info(f"Created upload session for Google Sheets: {upload_id}")
        
        try:
            # Check cancellation before starting
            if upload_session and upload_session.is_cancelled:
                raise CancellationError("Import cancelled before fetching sheet data")
            
            # UPDATED: Always use first sheet, no sheet_index parameter
            csv_content = await fetch_sheet_data(cleaned_url, datasette, upload_session)
            
            # Check cancellation after fetch
            if upload_session and upload_session.is_cancelled:
                raise CancellationError("Import cancelled after fetching sheet data")
                
        except CancellationError as ce:
            logger.info(f"Google Sheets upload cancelled: {ce}")
            if upload_session:
                cleanup_upload_session(upload_id)
            return Response.json({
                "success": False,
                "error": "Import cancelled by user"
            }, status=499)
        except ValueError as fetch_error:
            if upload_session:
                cleanup_upload_session(upload_id)
            
            error_context = await categorize_upload_error(str(fetch_error), "google_sheets", datasette)
            return Response.json({"success": False, "error": error_context["user_message"]}, status=400)
        
        # Validate CSV structure
        is_valid, error_msg, csv_metadata = validate_csv_structure_enhanced(csv_content)
        if not is_valid:
            if upload_session:
                cleanup_upload_session(upload_id)
            return Response.json({
                "success": False,
                "error": f"Google Sheets data validation failed: {error_msg}"
            }, status=400)
        
        # Generate table name
        if custom_table_name:
            is_valid, validation_error = validate_table_name_enhanced(custom_table_name)
            if not is_valid:
                auto_fixed_name = auto_fix_table_name(custom_table_name)
                base_table_name = auto_fixed_name
                logger.info(f"Auto-fixed table name from '{custom_table_name}' to '{auto_fixed_name}'")
            else:
                base_table_name = custom_table_name
        else:
            # UPDATED: Use "first_sheet" instead of sheet index
            base_table_name = get_google_sheet_name_from_url(cleaned_url, 0)  # Always first sheet
        
        if replace_existing and custom_table_name:
            table_name = base_table_name
            logger.info(f"Will replace existing table: {table_name}")
        else:
            table_name = await suggest_unique_name(base_table_name, datasette, db_name)
            logger.info(f"Generated unique table name: {table_name}")
        
        # Update session with table name
        if upload_session:
            upload_session.table_name = table_name
        
        # Get database and process
        portal_db = datasette.get_database('portal')
        result = await portal_db.execute(
            "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
            [db_name, actor["id"]]
        )
        db_info = result.first()
        
        if not db_info:
            if upload_session:
                cleanup_upload_session(upload_id)
            return Response.json({"success": False, "error": "Database not found"}, status=404)
        
        file_path = db_info['file_path'] or os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
        
        file_size = len(csv_content.encode('utf-8'))
        file_size_mb = file_size / (1024 * 1024)
        use_ultra_mode = file_size > 50 * 1024 * 1024
        
        uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode, upload_session)
        
        try:
            # Check cancellation before processing
            if upload_session and upload_session.is_cancelled:
                raise CancellationError("Import cancelled before processing data")
            
            upload_result = uploader.stream_csv_ultra_fast_pooled(
                csv_content, 
                table_name, 
                replace_existing=(replace_existing and custom_table_name),
                upload_id=upload_id
            )
        except CancellationError as ce:
            logger.info(f"Google Sheets processing cancelled: {ce}")
            if upload_session:
                cleanup_upload_session(upload_id)
            return Response.json({
                "success": False,
                "error": "Import cancelled by user"
            }, status=499)
        except Exception as process_error:
            if upload_session:
                cleanup_upload_session(upload_id)
            error_context = await categorize_upload_error(str(process_error), "google_sheets", datasette)
            return Response.json({
                "success": False,
                "error": error_context["user_message"]
            }, status=500)
        finally:
            uploader.close_pool()
            if upload_session:
                cleanup_upload_session(upload_id)
        
        await update_database_timestamp(datasette, db_name)

        try:
            db_result = await portal_db.execute(
                "SELECT db_id FROM databases WHERE db_name = ? AND status != 'Deleted'", [db_name]
            )
            db_record = db_result.first()
            if db_record:
                await sync_database_tables_on_upload(datasette, db_record['db_id'], table_name)
        except Exception as sync_error:
            logger.error(f"Error syncing table visibility: {sync_error}")
        
        await log_upload_activity_enhanced(
            datasette, 
            actor.get("id"), 
            "ajax_sheets_upload_first_sheet", 
            f"AJAX: Imported {upload_result['rows_inserted']:,} rows from Google Sheets (first sheet only)",
            {
                "source_type": "google_sheets_first_sheet_only",
                "table_name": table_name,
                "sheets_url": cleaned_url,
                "sheet_index": 0,  # Always first sheet
                "record_count": upload_result['rows_inserted'],
                "replace_existing": replace_existing and custom_table_name
            }
        )
        
        success_msg = f"Successfully imported {upload_result['rows_inserted']:,} rows from Google Sheets (first sheet) to table '{table_name}'"
        
        return Response.json({
            "success": True,
            "message": success_msg,
            "redirect_url": "/manage-databases"
        })
        
    except Exception as e:
        logger.error(f"AJAX sheets upload handler error: {str(e)}")
        
        error_context = await categorize_upload_error(str(e), "ajax_sheets_upload", datasette)
        return Response.json({
            "success": False, 
            "error": error_context["user_message"]
        }, status=500)


async def ajax_url_upload_handler(datasette, request):
    """AJAX URL upload handler with comprehensive error handling and user-friendly messages"""
    if not is_ajax_request(request):
        return Response.json({
            "success": False, 
            "error": "This endpoint is for AJAX requests only"
        }, status=400)

    upload_id = None
    upload_session = None

    try:
        actor = get_actor_from_request(request)
        if not actor:
            return Response.json({
                "success": False, 
                "error": "Your session has expired. Please refresh the page and log in again."
            }, status=401)

        path_parts = request.path.strip('/').split('/')
        if len(path_parts) < 2:
            return Response.json({
                "success": False, 
                "error": "Invalid request format. Please try again."
            }, status=400)
        
        db_name = path_parts[1]

        if not await user_owns_database(datasette, actor["id"], db_name):
            return Response.json({
                "success": False, 
                "error": "You don't have permission to upload to this database."
            }, status=403)

        # Parse form data
        content_type = request.headers.get('content-type', '')
        body = await request.post_body()

        if 'multipart/form-data' in content_type:
            forms, files = parse_multipart_form_data_from_ajax(body, content_type)
        else:
            post_vars = await request.post_vars()
            forms = dict(post_vars)

        csv_url = forms.get('csv_url', '').strip()
        custom_table_name = forms.get('table_name', '').strip()
        encoding = forms.get('encoding', 'auto')
        replace_existing = forms.get('replace_existing') == 'on'
        upload_id = forms.get('upload_id')
        
        if not csv_url:
            return Response.json({
                "success": False, 
                "error": "Please enter a valid CSV file URL."
            }, status=400)

        # Validate URL
        try:
            await validate_csv_url(datasette, csv_url)
        except ValueError as val_error:
            error_context = await categorize_upload_error(str(val_error), "url_validation", datasette)
            return Response.json({
                "success": False,
                "error": error_context["user_message"]
            }, status=400)

        # Create upload session
        if upload_id:
            upload_session = create_upload_session(upload_id, actor["id"])
            logger.info(f"Created upload session for URL upload: {upload_id}")

        try:
            # Check cancellation before starting
            if upload_session and upload_session.is_cancelled:
                raise CancellationError("Import cancelled before starting")
            
            # Download with enhanced error handling
            try:
                csv_content = await fetch_csv_from_url_subprocess(datasette, csv_url, encoding, upload_session)
            except ValueError as download_error:
                error_msg = str(download_error)
                if "curl" in error_msg or "wget" in error_msg:
                    # External tool not available, try threaded fallback
                    logger.warning("External download tools not available, using threaded fallback")
                    csv_content = await fetch_csv_from_url_threaded(datasette, csv_url, encoding, upload_session)
                else:
                    # Re-raise other download errors
                    raise download_error
            
            # Check for cancellation after download but before processing
            if upload_session and upload_session.is_cancelled:
                logger.info(f"Upload {upload_id} cancelled after download completed but before database processing")
                cleanup_upload_session(upload_id, delay_seconds=0)
                return Response.json({
                    "success": False,
                    "error": "Upload cancelled by user. The file was downloaded but not saved to the database."
                }, status=499)
            
            # Validate CSV content
            is_valid, error_msg, csv_metadata = validate_csv_structure_enhanced(csv_content)
            if not is_valid:
                if upload_session:
                    cleanup_upload_session(upload_id, delay_seconds=0)
                error_context = await categorize_upload_error(error_msg, "csv_validation", datasette)
                return Response.json({
                    "success": False,
                    "error": error_context["user_message"]
                }, status=400)
            
            # Determine table name
            if custom_table_name:
                is_valid, error_msg = validate_table_name_enhanced(custom_table_name)
                if not is_valid:
                    auto_fixed_name = auto_fix_table_name(custom_table_name)
                    base_table_name = auto_fixed_name
                    logger.info(f"Auto-corrected table name: '{custom_table_name}' -> '{auto_fixed_name}'")
                else:
                    base_table_name = custom_table_name
            else:
                base_table_name = get_csv_name_from_url(csv_url)
            
            if replace_existing and custom_table_name:
                table_name = base_table_name
            else:
                table_name = await suggest_unique_name(base_table_name, datasette, db_name)
            
            # Update session with table name
            if upload_session:
                upload_session.table_name = table_name
                upload_session.update_progress(phase="processing")
            
            # Get database info
            portal_db = datasette.get_database('portal')
            result = await portal_db.execute(
                "SELECT file_path FROM databases WHERE db_name = ? AND user_id = ?",
                [db_name, actor["id"]]
            )
            db_info = result.first()
            
            if not db_info:
                if upload_session:
                    cleanup_upload_session(upload_id, delay_seconds=0)
                return Response.json({
                    "success": False,
                    "error": "Database not found. Please refresh the page and try again."
                }, status=404)
            
            file_path = db_info['file_path'] or os.path.join(DATA_DIR, actor["id"], f"{db_name}.db")
            
            # Process CSV with enhanced cancellation checking
            file_size = len(csv_content.encode('utf-8'))
            use_ultra_mode = file_size > 50 * 1024 * 1024
            uploader = get_optimal_uploader(file_size, file_path, use_ultra_mode, upload_session)
            
            try:
                # Final cancellation check before database operations
                if upload_session and upload_session.is_cancelled:
                    logger.info(f"Upload {upload_id} cancelled before database processing")
                    raise CancellationError("Import cancelled before saving to database")
                
                # Process the CSV content
                upload_result = uploader.stream_csv_ultra_fast_pooled(
                    csv_content,
                    table_name, 
                    replace_existing=(replace_existing and custom_table_name)
                )
                
                # Check cancellation one more time before commit
                if upload_session and upload_session.is_cancelled:
                    logger.info(f"Upload {upload_id} cancelled after processing but cleanup will continue")
                    # Note: At this point, data is already committed, so we inform user
                    cleanup_upload_session(upload_id, delay_seconds=0)
                    return Response.json({
                        "success": False,
                        "error": "Upload was cancelled but the data may have already been saved to the database. Please check your database tables."
                    }, status=499)
                
            except CancellationError as ce:
                logger.info(f"URL upload cancelled during processing: {ce}")
                if upload_session:
                    cleanup_upload_session(upload_id, delay_seconds=0)
                return Response.json({
                    "success": False,
                    "error": "Upload cancelled by user. No data was saved to the database."
                }, status=499)
            finally:
                uploader.close_pool()
                if upload_session and not upload_session.is_cancelled:
                    cleanup_upload_session(upload_id, delay_seconds=10)
            
            # Success - update metadata
            await update_database_timestamp(datasette, db_name)
            
            try:
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
                f"AJAX: Imported {upload_result['rows_inserted']:,} rows from web CSV",
                {
                    "source_type": "web_csv_enhanced",
                    "table_name": table_name,
                    "csv_url": csv_url,
                    "record_count": upload_result['rows_inserted'],
                    "replace_existing": replace_existing and custom_table_name
                }
            )
            
            file_size_mb = file_size / (1024 * 1024)
            success_msg = f"Successfully imported {upload_result['rows_inserted']:,} rows ({file_size_mb:.1f}MB) from web CSV to table '{table_name}'"
            
            return Response.json({
                "success": True,
                "message": success_msg,
                "redirect_url": "/manage-databases"
            })
            
        except CancellationError as ce:
            logger.info(f"URL upload cancelled: {ce}")
            if upload_session:
                cleanup_upload_session(upload_id, delay_seconds=0)
            return Response.json({
                "success": False,
                "error": "Upload cancelled by user."
            }, status=499)
            
    except Exception as e:
        logger.error(f"AJAX URL upload error: {str(e)}")
        
        # Clean up on any error
        if upload_session:
            cleanup_upload_session(upload_id, delay_seconds=0)
        
        # Provide user-friendly error messages
        error_context = await categorize_upload_error(str(e), "ajax_url_upload", datasette)
        return Response.json({
            "success": False, 
            "error": error_context["user_message"]
        }, status=500)


# ============= STATUS AND CANCELLATION API =============

async def upload_status_api(datasette, request):
    """API endpoint to get upload status for real-time updates"""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)
    
    try:
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))
        upload_id = data.get('upload_id')
        
        if not upload_id:
            return Response.json({"error": "upload_id required"}, status=400)
        
        upload_session = get_upload_session(upload_id)
        if upload_session:
            return Response.json({
                "success": True,
                "phase": upload_session.phase,
                "bytes_downloaded": upload_session.bytes_downloaded,
                "total_bytes": upload_session.total_bytes,
                "rows_processed": upload_session.rows_processed,
                "table_name": upload_session.table_name,
                "is_cancelled": upload_session.is_cancelled,
                "elapsed_time": time.time() - upload_session.created_at
            })
        else:
            return Response.json({
                "success": False,
                "message": "Upload session not found"
            })
        
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return Response.json({"error": str(e)}, status=500)

async def cancel_upload_api(datasette, request):
    """Enhanced cancellation API with extended cleanup tracking"""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)
    
    actor = get_actor_from_request(request)
    if not actor:
        return Response.json({"error": "Authentication required"}, status=401)
    
    try:
        body = await request.post_body()
        data = json.loads(body.decode('utf-8'))
        upload_id = data.get('upload_id')
        
        if not upload_id:
            return Response.json({"error": "upload_id required"}, status=400)
        
        upload_session = get_upload_session(upload_id)
        if upload_session:
            upload_session.cancel()
            return Response.json({
                "success": True,
                "message": "Upload cancellation requested"
            })
        else:
            return Response.json({
                "success": True,
                "message": "Upload session not found (may have already completed)"
            })
        
    except Exception as e:
        logger.error(f"Error cancelling upload: {e}")
        return Response.json({"error": str(e)}, status=500)

# ============= ROUTE REGISTRATION =============

@hookimpl
def register_routes():
    """Register routes with enhanced cancellation support"""
    return [
        # AJAX routes FIRST - these are more specific and should match first
        (r"^/ajax-upload-file/([^/]+)$", ajax_file_upload_handler),
        (r"^/ajax-upload-sheets/([^/]+)$", ajax_sheets_upload_handler),
        (r"^/ajax-upload-url/([^/]+)$", ajax_url_upload_handler),
        
        # Status and cancellation APIs
        (r"^/api/upload-status$", upload_status_api),
        (r"^/api/cancel-upload$", cancel_upload_api),
        
        # General upload route LAST - this is less specific
        (r"^/upload-table/([^/]+)$", enhanced_upload_page),
    ]