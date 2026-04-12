import re
import traceback

from datasette.utils.asgi import Response
from datasette.utils import async_call_with_supported_arguments

from apps.datasette.lib.http import INTERNAL_SERVER_ERROR, METHOD_NOT_ALLOWED


class DatasetteRouter:
    """
    Decorator-based router for Datasette plugins that supports
    Next.js-style route parameters.

    Route parameters are written with `:name` and compiled into
    regex named capture groups.

    Example routes and their compiled regex:

        "/hello"
            -> ^/hello$

        "/items/:id"
            -> ^/items/(?P<id>[^/]+)$

        "/datasets/:db/tables/:table"
            -> ^/datasets/(?P<db>[^/]+)/tables/(?P<table>[^/]+)$

    Parameters become available in handlers via:

    - request.url_vars["id"]
    - request.url_vars["db"]
    - request.url_vars["table"]
    """

    PARAM_PATTERN = re.compile(r":(\w+)")

    def __init__(self):
        self._routes = []

    def route(self, paths, methods=None):
        if isinstance(paths, str):
            paths = [paths]

        methods = {m.upper() for m in (methods or ["GET"])}

        def decorator(func):
            for path in paths:
                regex = self._compile_path(path)
                handler = self._wrap_handler(func, methods)
                self._routes.append((regex, handler))
            return func

        return decorator

    def _compile_path(self, path):
        # convert /items/:id → /items/(?P<id>[^/]+)
        pattern = self.PARAM_PATTERN.sub(
            lambda m: f"(?P<{m.group(1)}>[^/]+)", path
        )

        return f"^{pattern}$"

    def _wrap_handler(self, func, methods):
        # The handler's parameters come from the parameters defined for
        # datasette view functions:
        # https://docs.datasette.io/en/stable/plugin_hooks.html#register-routes-datasette
        async def handler(datasette, request, scope, send, receive):
            request_method = request.method.upper()
            if request_method not in methods:
                return Response.json(
                    {
                        "error": f"405 Method Not Allowed: {request_method}",
                        "allowed_methods": sorted(methods),
                    }, 
                    status=METHOD_NOT_ALLOWED,
                )

            try:
                return await async_call_with_supported_arguments(
                    func,
                    datasette=datasette,
                    request=request,
                    scope=scope,
                    send=send,
                    receive=receive,
                )
            except:
                return Response.json(
                    {
                        "error": "500 Internal Server Error",
                        "traceback": traceback.format_exc(),
                    },
                    status=INTERNAL_SERVER_ERROR,
                )

        return handler

    def get(self, paths):
        return self.route(paths, ["GET"])

    def post(self, paths):
        return self.route(paths, ["POST"])
    
    def put(self, paths):
        return self.route(paths, ["PUT"])
    
    def delete(self, paths):
        return self.route(paths, ["DELETE"])

    def get_routes(self):
        return self._routes
