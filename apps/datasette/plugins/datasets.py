from datasette import hookimpl
from datasette.hookspecs import database_actions
from datasette.utils.asgi import Response
from apps.datasette.plugins.router import DatasetteRouter
from apps.datasette.lib.datasets import get_all_datasets, get_dataset_by_id

router = DatasetteRouter()

@router.get("/datasets")
async def datasets(datasette):
    datasets = await get_all_datasets(datasette)
    data = {
        "datasets": datasets
    }
    return Response.json(data)

@router.get("/datasets/:id")
async def dataset(datasette, request):
    dataset_id = request.url_vars["id"]
    dataset = await get_dataset_by_id(datasette, dataset_id)
    data = {
        "dataset": dataset
    }
    return Response.json(data)

@hookimpl
def register_routes():
    return router.get_routes()