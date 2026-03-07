from datasette import hookimpl
from datasette.utils.asgi import Response


@hookimpl
def register_routes():
    return [
        (r"^/csrf$", csrf),
    ]
        
def csrf(request):
    token = request.scope["csrftoken"]()
    response = Response.json(
        {"status": "ok"},
    )
    response.set_cookie(
        "ds_csrftoken",
        token,
        path="/",
        samesite="lax"
    )
    return response