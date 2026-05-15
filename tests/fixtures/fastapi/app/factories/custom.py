from fastapi import APIRouter

from app.factories.nested import make_nested_router


class ProjectRouter(APIRouter):
    pass


def make_factory_router() -> APIRouter:
    router = ProjectRouter(prefix="/factory")

    @router.post("/items")
    async def create_factory_item():
        return {"ok": True}

    router.include_router(make_nested_router())

    return router
