import json
import bcrypt
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from email.parser import BytesParser
from email.policy import default
import bleach
import re
import os
import sqlite_utils
import uuid
import pandas as pd

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png', '.csv', '.db'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

def sanitize_text(text):
    """Sanitize text by stripping HTML tags while preserving safe characters."""
    return bleach.clean(text, tags=[], strip=True)

def parse_markdown_links(text):
    """Parse markdown-like links [text](url) into HTML <a> tags and split into paragraphs."""
    paragraphs = [p.strip() for p in text.split('\n') if p.strip()]
    parsed_paragraphs = []
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
    for paragraph in paragraphs:
        parsed = link_pattern.sub(lambda m: f'<a href="{sanitize_text(m.group(2))}" class="text-accent hover:text-primary">{sanitize_text(m.group(1))}</a>', paragraph)
        parsed_paragraphs.append(parsed)
    return parsed_paragraphs

async def login_page(datasette, request):
    logger.debug(f"Login request: method={request.method}, scope={request.scope}")
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Login Cookies: {cookies}")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}}

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"POST vars: {post_vars}")
        username = post_vars.get("username")
        password = post_vars.get("password")
        try:
            db = datasette.get_database("portal")
            result = await db.execute("SELECT password_hash, role FROM users WHERE username = ?", [username])
            user = result.first()
            if user and bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                logger.debug("Login successful for user: %s", username)
                response = Response.redirect("/admin")
                actor_data = {"id": username, "name": f"User {username}", "role": user["role"]}
                response.set_cookie("ds_actor", json.dumps(actor_data, ensure_ascii=False), httponly=True)
                request.scope["actor"] = actor_data
                return response
            else:
                logger.warning("Login failed for user: %s", username)
                return Response.html(
                    await datasette.render_template(
                        "login.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Invalid username or password"
                        },
                        request=request
                    )
                )
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "login.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": f"Login error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "login.html",
            {
                "metadata": datasette.metadata(),
                "content": content
            },
            request=request
        )
    )

async def register_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Register Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = json.loads(ds_actor_cookie)
                logger.debug(f"Parsed actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor or actor.get("role") != "admin":
        logger.warning("Unauthorized register attempt")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}}

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"Register POST vars: {post_vars}")
        username = post_vars.get("username")
        password = post_vars.get("password")
        role = post_vars.get("role")
        email = post_vars.get("email")
        if not username or not password or not email or role not in ["admin", "moderator", "viewer"]:
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "Username, password, email, and valid role are required"
                    },
                    request=request
                )
            )
        try:
            db = datasette.get_database("portal")
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user_id = str(uuid.uuid4())
            await db.execute_write(
                "INSERT INTO users (user_id, username, password_hash, role, email, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [user_id, username, hashed_password, role, email, datetime.utcnow()]
            )
            logger.debug("User registered: %s with role: %s", username, role)
            return Response.redirect("/admin?success=1")
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": f"Registration error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "register.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor
            },
            request=request
        )
    )

async def change_password_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Change Password Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = json.loads(ds_actor_cookie)
                logger.debug(f"Parsed actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning("Unauthorized change password attempt")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}}

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"Change password POST vars: {post_vars}")
        current_password = post_vars.get("current_password")
        new_password = post_vars.get("new_password")
        confirm_password = post_vars.get("confirm_password")
        username = actor.get("id")

        if not current_password or not new_password or new_password != confirm_password:
            return Response.html(
                await datasette.render_template(
                    "change_password.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": "All fields are required and new passwords must match"
                    },
                    request=request
                )
            )

        try:
            db = datasette.get_database("portal")
            result = await db.execute("SELECT password_hash FROM users WHERE username = ?", [username])
            user = result.first()
            if user and bcrypt.checkpw(current_password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                await db.execute_write(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    [hashed_password, username]
                )
                logger.debug("Password changed for user: %s", username)
                return Response.redirect("/admin?success=1")
            else:
                logger.warning("Invalid current password for user: %s", username)
                return Response.html(
                    await datasette.render_template(
                        "change_password.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "error": "Invalid current password"
                        },
                        request=request
                    )
                )
        except Exception as e:
            logger.error(f"Password change error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "change_password.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "error": f"Password change error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "change_password.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor
            },
            request=request
        )
    )

async def logout_page(datasette, request):
    response = Response.redirect("/")
    response.set_cookie("ds_actor", "", expires=0)
    return response

async def create_database(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Create Database Cookies: {cookies}")

    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = json.loads(ds_actor_cookie)
                logger.debug(f"Parsed actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    if not actor:
        logger.warning("Unauthorized create database attempt")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    title = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["title"])
    title_row = title.first()
    content = {'title': json.loads(title_row["content"]) if title_row else {'content': 'EDGI Datasette Cloud Portal'}}

    if request.method == "POST":
        try:
            body = await request.post_body()
            content_type = request.headers.get('content-type', '')
            boundary = None
            if 'boundary=' in content_type.lower():
                boundary = content_type.split('boundary=')[-1].split(';')[0].strip().encode('utf-8')
            if not boundary:
                logger.error("No boundary found in Content-Type header")
                return Response.json({'error': 'Invalid multipart form data: missing boundary'}, status=400)

            headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
            headers['content-type'] = content_type
            msg = BytesParser(policy=default).parsebytes(b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n' + body)
            
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
                            if filename:
                                files[field_name] = {
                                    'filename': filename,
                                    'content': part.get_payload(decode=True)
                                }
                            else:
                                forms[field_name] = [part.get_payload(decode=True).decode('utf-8')]
            
            db_name = forms.get('db_name', [''])[0].strip()
            logger.debug(f"Create database: db_name={db_name}, files={files}")

            if not db_name or not files.get('dataset'):
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "Database name and dataset file are required"
                        },
                        request=request
                    )
                )

            file = files['dataset']
            if len(file['content']) > MAX_FILE_SIZE:
                logger.error("File exceeds 50MB limit")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "File exceeds 50MB limit"
                        },
                        request=request
                    )
                )

            ext = Path(file['filename']).suffix.lower()
            if ext not in {'.csv', '.db'}:
                logger.error(f"Invalid file extension: {ext}")
                return Response.html(
                    await datasette.render_template(
                        "create_database.html",
                        {
                            "metadata": datasette.metadata(),
                            "content": content,
                            "actor": actor,
                            "error": "Only .csv and .db files allowed"
                        },
                        request=request
                    )
                )

            username = actor.get("id")
            db_id = str(uuid.uuid4())
            db_path = f"/data/{username}/{db_name}.db"
            website_url = f"{username}-{db_name}.datasette-portal.fly.dev"

            os.makedirs(f"/data/{username}", exist_ok=True)
            if ext == '.csv':
                db_file = sqlite_utils.Database(db_path)
                db_file.insert_all(pd.read_csv(file['content']).to_dict('records'), table="measurements")
                db_file.create_table("admin_content", {
                    "section": str,
                    "content": str,
                    "updated_at": str,
                    "updated_by": str
                }, pk="section")
                db_file["admin_content"].insert({
                    "section": "title",
                    "content": json.dumps({"content": db_name}),
                    "updated_at": datetime.utcnow().isoformat(),
                    "updated_by": username
                })
            else:  # .db
                with open(db_path, 'wb') as f:
                    f.write(file['content'])
                db_file = sqlite_utils.Database(db_path)
                if "admin_content" not in db_file.table_names():
                    db_file.create_table("admin_content", {
                        "section": str,
                        "content": str,
                        "updated_at": str,
                        "updated_by": str
                    }, pk="section")
                    db_file["admin_content"].insert({
                        "section": "title",
                        "content": json.dumps({"content": db_name}),
                        "updated_at": datetime.utcnow().isoformat(),
                        "updated_by": username
                    })

            portal_db = datasette.get_database("portal")
            await portal_db.execute_write(
                "INSERT INTO databases (db_id, user_id, db_name, db_path, website_url, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [db_id, username, db_name, db_path, website_url, datetime.utcnow()]
            )
            await portal_db.execute_write(
                "INSERT INTO user_database_roles (user_id, db_id, role, assigned_at) VALUES (?, ?, ?, ?)",
                [username, db_id, "admin", datetime.utcnow()]
            )

            logger.debug(f"Database created: {db_path}, website_url={website_url}")
            return Response.redirect("/?success=1")
        except Exception as e:
            logger.error(f"Create database error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "create_database.html",
                    {
                        "metadata": datasette.metadata(),
                        "content": content,
                        "actor": actor,
                        "error": f"Create database error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "create_database.html",
            {
                "metadata": datasette.metadata(),
                "content": content,
                "actor": actor
            },
            request=request
        )
    )

async def admin_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Admin Cookies: {cookies}")
    
    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = json.loads(ds_actor_cookie)
                logger.debug(f"Parsed actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    logger.debug(f"Admin page access: actor={actor}")
    if not actor or actor.get("role") not in ["admin", "moderator"]:
        logger.warning("Unauthorized admin access attempt")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    sections = await db.execute('SELECT section, content FROM admin_content')
    content = {row['section']: json.loads(row['content']) for row in sections}

    if 'title' not in content:
        content['title'] = {'content': 'EDGI Datasette Cloud Portal'}
    if 'header_image' not in content:
        content['header_image'] = {'image_url': '/static/header.jpg', 'alt_text': '', 'credit_url': '', 'credit_text': ''}
    if 'info' not in content:
        content['info'] = {'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.', 'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')}
    if 'feature_cards' not in content:
        content['feature_cards'] = []
    if 'statistics' not in content:
        content['statistics'] = []
    if 'footer' not in content:
        content['footer'] = {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': parse_markdown_links('Made with EDGI')}

    if 'info' in content and 'content' in content['info'] and 'paragraphs' not in content['info']:
        content['info']['paragraphs'] = parse_markdown_links(content['info']['content'])
    if 'footer' in content and 'content' in content['footer'] and 'paragraphs' not in content['footer']:
        content['footer']['paragraphs'] = parse_markdown_links(content['footer']['content'])

    return Response.html(
        await datasette.render_template(
            'admin.html',
            {
                'content': content,
                'metadata': datasette.metadata(),
                'actor': actor,
                'success': request.args.get('success')
            },
            request=request
        )
    )

async def update_content(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Update content cookies: {cookies}")
    
    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = json.loads(ds_actor_cookie)
                logger.debug(f"Parsed actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    logger.debug(f"Update content: actor={actor}")
    if not actor or actor.get("role") not in ["admin", "moderator"]:
        logger.warning("Unauthorized update attempt")
        return Response.redirect("/login")

    db = datasette.get_database('portal')
    section = None
    post_vars = {}
    files = {}

    if 'multipart/form-data' in request.headers.get('content-type', '').lower():
        try:
            body = await request.post_body()
            content_type = request.headers.get('content-type', '')
            boundary = None
            if 'boundary=' in content_type.lower():
                boundary = content_type.split('boundary=')[-1].split(';')[0].strip().encode('utf-8')
            if not boundary:
                logger.error("No boundary found in Content-Type header")
                return Response.json({'error': 'Invalid multipart form data: missing boundary'}, status=400)

            headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
            headers['content-type'] = content_type
            msg = BytesParser(policy=default).parsebytes(b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n' + body)
            
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
                            if filename:
                                files[field_name] = {
                                    'filename': filename,
                                    'content': part.get_payload(decode=True)
                                }
                            else:
                                forms[field_name] = [part.get_payload(decode=True).decode('utf-8')]
            
            section = forms.get('section', [''])[0]
            logger.debug(f"Parsed forms: {forms}")
            logger.debug(f"Parsed files: {files}")
            logger.debug(f"Updating section: {section}")

        except Exception as e:
            logger.error(f"Multipart form parsing error: {str(e)}")
            return Response.json({'error': f"Form parsing error: {str(e)}"}, status=400)
    else:
        post_vars = await request.post_vars()
        section = post_vars.get('section', '')
        logger.debug(f"Regular POST vars: {post_vars}")
        logger.debug(f"Updating section: {section}")

    if section == 'header_image':
        if 'multipart/form-data' not in request.headers.get('content-type', '').lower():
            logger.error("Header image update requires multipart/form-data")
            return Response.json({'error': 'Header image update requires multipart/form-data'}, status=400)

        current_content = {}
        result = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["header_image"])
        row = result.first()
        if row:
            try:
                current_content = json.loads(row["content"])
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for header_image: {str(e)}")
                current_content = {}

        content = {
            'image_url': current_content.get('image_url', '/static/header.jpg'),
            'alt_text': sanitize_text(forms.get('alt_text', [''])[0]),
            'credit_url': sanitize_text(forms.get('credit_url', [''])[0]),
            'credit_text': sanitize_text(forms.get('credit_text', [''])[0])
        }

        if 'image' in files and files['image']['content']:
            file = files['image']
            if len(file['content']) > MAX_FILE_SIZE:
                logger.error("File exceeds 50MB limit")
                return Response.json({'error': 'File exceeds 50MB limit'}, status=400)
            ext = Path(file['filename']).suffix.lower()
            if ext not in {'.jpg', '.png'}:
                logger.error(f"Invalid file extension: {ext}")
                return Response.json({'error': 'Only .jpg and .png files allowed'}, status=400)
            filename = f"header{ext}"
            file_path = f"/data/static/{filename}"
            try:
                os.makedirs("/data/static", exist_ok=True)
                with open(file_path, 'wb') as f:
                    f.write(file['content'])
                content['image_url'] = f'/static/{filename}'
            except Exception as e:
                logger.error(f"Failed to save header image: {str(e)}")
                return Response.json({'error': f"Failed to save header image: {str(e)}"}, status=400)

    elif section == 'title':
        content = {'content': sanitize_text(post_vars.get('content', ''))}

    elif section == 'info':
        content = {'content': sanitize_text(post_vars.get('content', ''))}

    elif section == 'feature_cards':
        cards = []
        i = 0
        while f'card_title_{i}' in post_vars:
            cards.append({
                'title': sanitize_text(post_vars[f'card_title_{i}']),
                'description': sanitize_text(post_vars[f'card_description_{i}']),
                'url': sanitize_text(post_vars[f'card_url_{i}']),
                'icon': 'ri-bar-chart-line'
            })
            i += 1
        content = cards

    elif section == 'statistics':
        stats = []
        i = 0
        while f'stat_label_{i}' in post_vars:
            query = post_vars[f'stat_query_{i}']
            if not query.startswith('SELECT COUNT(*) FROM'):
                logger.error(f"Invalid SQL query: {query}")
                return Response.json({'error': 'Invalid SQL query'}, status=400)
            stats.append({
                'label': sanitize_text(post_vars[f'stat_label_{i}']),
                'query': query,
                'url': sanitize_text(post_vars[f'stat_url_{i}'])
            })
            i += 1
        content = stats

    elif section == 'footer':
        content = {
            'content': sanitize_text(post_vars.get('content', '')),
            'odbl_text': sanitize_text(post_vars.get('odbl_text', 'Data licensed under ODbL')),
            'odbl_url': sanitize_text(post_vars.get('odbl_url', 'https://opendatacommons.org/licenses/odbl/'))
        }

    else:
        logger.error(f"Invalid section: {section}")
        return Response.json({'error': 'Invalid section'}, status=400)

    await db.execute_write(
        'INSERT OR REPLACE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, CURRENT_TIMESTAMP, ?)',
        (section, json.dumps(content, ensure_ascii=False), actor.get("id"))
    )
    logger.debug(f"Content updated successfully for section: {section} by user: {actor.get('id')}")
    return Response.redirect('/admin?success=1')

async def index_page(datasette, request):
    db = datasette.get_database("portal")

    async def get_section(section_name):
        result = await db.execute("SELECT content FROM admin_content WHERE section = ?", [section_name])
        row = result.first()
        if row:
            try:
                content = json.loads(row["content"])
                if section_name == "info" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                if section_name == "footer" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                return content
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for section {section_name}: {str(e)}")
                return {}
        else:
            return {}

    content = {}
    content['header_image'] = await get_section("header_image") or {'image_url': '/static/header.jpg', 'alt_text': '', 'credit_url': '', 'credit_text': ''}
    content['info'] = await get_section("info") or {'content': 'The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.', 'paragraphs': parse_markdown_links('The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.')}
    content['feature_cards'] = await get_section("feature_cards") or []
    content['statistics'] = await get_section("statistics") or []
    content['footer'] = await get_section("footer") or {'content': 'Made with EDGI', 'odbl_text': 'Data licensed under ODbL', 'odbl_url': 'https://opendatacommons.org/licenses/odbl/', 'paragraphs': parse_markdown_links('Made with EDGI')}
    content['title'] = await get_section("title") or {'content': 'EDGI Datasette Cloud Portal'}

    if isinstance(content['statistics'], str):
        try:
            content['statistics'] = json.loads(content['statistics'])
        except json.JSONDecodeError:
            logger.error("Failed to parse statistics JSON")
            content['statistics'] = []
    if not isinstance(content['statistics'], list):
        content['statistics'] = []

    statistics_data = []
    for stat in content['statistics']:
        query = stat.get("query", "")
        label = stat.get("label", "Unnamed Stat")
        url = stat.get("url", "")
        if query:
            try:
                result = await db.execute(query)
                value = result.first()[0] if result.first() else "N/A"
            except Exception as e:
                logger.error(f"Query error for stat {label}: {str(e)}")
                value = "Error"
        else:
            value = "N/A"
        statistics_data.append({"label": label, "value": value, "url": url})

    actor = request.scope.get("actor")
    user_databases = []
    if actor:
        portal_db = datasette.get_database("portal")
        result = await portal_db.execute("SELECT db_name, website_url FROM databases WHERE user_id = ?", [actor.get("id")])
        user_databases = [{"db_name": row["db_name"], "website_url": row["website_url"]} for row in result]

    logger.debug(f"Rendering index with data: content={content}, statistics_data={statistics_data}, user_databases={user_databases}")

    return Response.html(
        await datasette.render_template(
            "index.html",
            {
                "page_title": content['title'].get('content', "EDGI Datasette Cloud Portal") + " | EDGI",
                "header_image": content['header_image'],
                "info": content['info'],
                "feature_cards": content['feature_cards'],
                "statistics": statistics_data,
                "footer": content['footer'],
                "content": content,
                "actor": actor,
                "user_databases": user_databases,
                "debug": {
                    "header_image": content['header_image'],
                    "info": content['info'],
                    "feature_cards": content['feature_cards'],
                    "statistics": statistics_data,
                    "footer": content['footer'],
                    "title": content['title'],
                    "user_databases": user_databases
                }
            },
            request=request
        )
    )

@hookimpl
def register_routes():
    return [
        (r"^/$", index_page),
        (r"^/login$", login_page),
        (r"^/register$", register_page),
        (r"^/change-password$", change_password_page),
        (r"^/logout$", logout_page),
        (r"^/admin$", admin_page),
        (r"^/admin/update$", update_content),
        (r"^/create-database$", create_database),
    ]

@hookimpl
def startup(datasette):
    async def init():
        db = datasette.get_database("portal")
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT,
                email TEXT,
                created_at TIMESTAMP
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS databases (
                db_id TEXT PRIMARY KEY,
                user_id TEXT,
                db_name TEXT,
                db_path TEXT,
                website_url TEXT,
                created_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS user_database_roles (
                user_id TEXT,
                db_id TEXT,
                role TEXT,
                assigned_at TIMESTAMP,
                PRIMARY KEY (user_id, db_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (db_id) REFERENCES databases(db_id)
            )
        """)
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS admin_content (
                section TEXT PRIMARY KEY,
                content JSON,
                updated_at TIMESTAMP,
                updated_by TEXT
            )
        """)
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["title", json.dumps({"content": "EDGI Datasette Cloud Portal"}), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["header_image", json.dumps({"image_url": "/static/header.jpg", "alt_text": "", "credit_url": "", "credit_text": ""}), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["info", json.dumps({"content": "The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.", "paragraphs": parse_markdown_links("The EDGI Datasette Cloud Portal enables users to share environmental datasets as interactive websites.")}), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["feature_cards", json.dumps([]), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["statistics", json.dumps([]), datetime.utcnow().isoformat(), "system"]
        )
        await db.execute_write(
            "INSERT OR IGNORE INTO admin_content (section, content, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ["footer", json.dumps({"content": "Made with EDGI", "odbl_text": "Data licensed under ODbL", "odbl_url": "https://opendatacommons.org/licenses/odbl/", "paragraphs": parse_markdown_links("Made with EDGI")}), datetime.utcnow().isoformat(), "system"]
        )
    return init