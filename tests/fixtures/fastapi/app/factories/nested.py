from fastapi import APIRouter


def make_nested_router() -> APIRouter:
    router = APIRouter(prefix="/nested")

    @router.get("/status")
    async def nested_status():
        return {"ok": True}

    return router
