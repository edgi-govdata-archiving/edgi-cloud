from datasette import hookimpl
from datasette.utils.asgi import Response
from apps.datasette.lib.router import DatasetteRouter

router = DatasetteRouter()

@router.get("/resette/csrf")
async def csrf(request):
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

@hookimpl
def register_routes():
    return router.get_routes()