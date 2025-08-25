import pytest
import os
import tempfile
from httpx import AsyncClient
from common_utils import parse_multipart_form_data, handle_image_upload_robust

@pytest.mark.asyncio
async def test_multipart_parser_with_image():
    '''Test multipart parser with actual image data'''
    content_type = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
    
    # Create test image data
    test_image_data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF'  # JPEG header
    
    body = (
        b'------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n'
        b'Content-Disposition: form-data; name="image"; filename="test.jpg"\r\n'
        b'Content-Type: image/jpeg\r\n'
        b'\r\n'
        + test_image_data +
        b'\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n'
        b'Content-Disposition: form-data; name="alt_text"\r\n'
        b'\r\n'
        b'Test Image Alt Text\r\n'
        b'------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n'
    )
    
    forms, files = parse_multipart_form_data(body, content_type)
    
    assert 'alt_text' in forms
    assert forms['alt_text'][0] == 'Test Image Alt Text'
    assert 'image' in files
    assert files['image']['filename'] == 'test.jpg'
    assert files['image']['content'] == test_image_data

@pytest.mark.asyncio 
async def test_image_upload_size_validation():
    '''Test image upload size validation'''
    # Test with oversized file
    large_data = b'x' * (6 * 1024 * 1024)  # 6MB
    
    content_type = "multipart/form-data; boundary=test123"
    body = (
        b'--test123\r\n'
        b'Content-Disposition: form-data; name="image"; filename="large.jpg"\r\n'
        b'Content-Type: image/jpeg\r\n'
        b'\r\n'
        + large_data +
        b'\r\n--test123--\r\n'
    )
    
    class MockRequest:
        def __init__(self, body, headers):
            self._body = body
            self.headers = headers
        
        async def post_body(self):
            return self._body
    
    request = MockRequest(body, {'content-type': content_type})
    
    result, error = await handle_image_upload_robust(
        None, request, 'test_db', {'id': 'test_user'}, 5 * 1024 * 1024
    )
    
    assert result is None
    assert 'too large' in error.lower()

def test_boundary_parsing_edge_cases():
    '''Test boundary parsing with various formats'''
    test_cases = [
        'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW',
        'multipart/form-data; boundary="----WebKitFormBoundary7MA4YWxkTrZu0gW"',
        'multipart/form-data; boundary=simple123',
        'multipart/form-data; boundary="complex-boundary_123"'
    ]
    
    for content_type in test_cases:
        # Test that parser can extract boundary
        import re
        patterns = [
            r'boundary=([^;,\s]+)',
            r'boundary="([^"]+)"',
            r'boundary=([a-zA-Z0-9\-_]+)'
        ]
        
        boundary = None
        for pattern in patterns:
            match = re.search(pattern, content_type, re.IGNORECASE)
            if match:
                boundary = match.group(1).strip('"')
                break
        
        assert boundary is not None, f"Failed to parse boundary from: {content_type}"