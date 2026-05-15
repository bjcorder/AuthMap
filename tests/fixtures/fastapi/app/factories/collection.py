from fastapi import APIRouter


def make_collection_router() -> APIRouter:
    router = APIRouter(prefix="/collection")

    @router.delete("/items/{item_id}")
    async def delete_collection_item(item_id: str):
        return {"deleted": item_id}

    return router
