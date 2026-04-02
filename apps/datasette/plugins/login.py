from datasette import hookimpl
from datasette.utils.asgi import Response
from apps.datasette.plugins.common_utils import set_actor_cookie
from apps.datasette.plugins.router import DatasetteRouter
import bcrypt
import json

INVALID_USERNAME_OR_PASSWORD_RESPONSE = Response.json({
    "error": "Incorrect username or password"
}, status=401)

router = DatasetteRouter()

@router.post("/resette/login")
async def login(datasette, request):
    body = await request.post_body()
    data = json.loads(body)
    username, password = data.get("username"), data.get("password")
    
    db = datasette.get_database("portal")
    result = await db.execute(
        "SELECT user_id, username, password_hash, role, COALESCE(must_change_password, 0) as must_change_password FROM users WHERE username = ?", 
        (username,)
    )
    user_row = result.first()
    if not user_row:
        return INVALID_USERNAME_OR_PASSWORD_RESPONSE
    
    # Access by column name (sqlite3.Row supports this)
    user_id = user_row["user_id"]
    password_hash = user_row["password_hash"]
    role = user_row["role"]
    must_change_password = bool(user_row["must_change_password"])
    if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
        return INVALID_USERNAME_OR_PASSWORD_RESPONSE
    
    actor_data = {
        "id": user_id, 
        "name": f"User {username}", 
        "role": role, 
        "username": username,
        "must_change_password": must_change_password
    }
    response_data = {
        "user": actor_data,
        "redirectTo": get_redirect_url(must_change_password),
    }
    response = Response.json(response_data)
    set_actor_cookie(response, datasette, actor_data)    
    return response

def get_redirect_url(must_change_password):
    if must_change_password:
        return "/force-change-password?reason=first_login"  
    # Normal login flow
    return "/datasets"

@hookimpl
def register_routes():
    return router.get_routes()
