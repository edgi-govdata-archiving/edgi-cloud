from datasette import hookimpl
from datasette.utils.asgi import Response
from apps.datasette.plugins.common_utils import set_actor_cookie
from apps.datasette.plugins.router import DatasetteRouter
import bcrypt
import json

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
    if user_row:
        # Access by column name (sqlite3.Row supports this)
        user_id = user_row["user_id"]
        username_db = user_row["username"]
        password_hash = user_row["password_hash"]
        role = user_row["role"]
        must_change_password = bool(user_row["must_change_password"])
    else:
        user_row = None
    if user_row and bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
        actor_data = {
            "id": user_id, 
            "name": f"User {username}", 
            "role": role, 
            "username": username,
            "must_change_password": must_change_password
        }
        if must_change_password:
            redirect_url = "/force-change-password?reason=first_login"
            response = Response.json({
                "redirectTo": redirect_url,   
            })
            set_actor_cookie(response, datasette, actor_data)
            return response
        else:
            # Normal login flow
            redirect_url = "/system-admin" if role == "system_admin" else "/manage-databases"
            response = Response.json({
                "redirectTo": redirect_url,
            })
            set_actor_cookie(response, datasette, actor_data)
            return response
    return Response.json({
        "error": "Incorrect username or password"
    }, status=401)

@hookimpl
def register_routes():
    return router.get_routes()
