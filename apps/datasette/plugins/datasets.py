from datasette import hookimpl
from datasette.hookspecs import database_actions
from datasette.utils.asgi import Response
from apps.datasette.plugins.router import DatasetteRouter
from apps.datasette.lib.datasets import get_all_datasets

router = DatasetteRouter()

@router.get("/datasets")
async def datasets(datasette):
    datasets = await get_all_datasets(datasette)
    data = {
        "datasets": datasets
    }
    return Response.json(data)

@hookimpl
def register_routes():
    return router.get_routes()