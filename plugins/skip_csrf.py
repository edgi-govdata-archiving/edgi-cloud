from pluggy import HookimplMarker
hookimpl = HookimplMarker("datasette")
@hookimpl
def skip_csrf(datasette, scope):
    if scope["path"] == "/create-database":
        return True
    return False