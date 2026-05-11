from fastapi import FastAPI, APIRouter
from app.routes.users import router as users_router

app = FastAPI()
local_router = APIRouter(prefix="/local", tags=["local-default"])
dynamic_prefix = "/dynamic"
dynamic_path = "/generated"
dynamic_router = APIRouter(prefix=dynamic_prefix)


@app.get("/health", name="healthcheck", tags=["system"])
def health():
    return {"ok": True}


@app.post(path="/items", tags=["items"])
def create_item():
    return {"created": True}


@local_router.delete("/{item_id}", name="delete_local")
def delete_local(item_id: str):
    return {"deleted": item_id}


@dynamic_router.get("/reports")
def dynamic_reports():
    return []


@app.api_route("/search", methods=["GET", "POST"], tags=["search"])
def search():
    return []


@app.api_route("/fallback")
def fallback():
    return {}


@app.get(dynamic_path)
def generated_path():
    return {}


app.include_router(local_router, prefix="/api")
app.include_router(users_router, prefix="/v1")
app.include_router(dynamic_router, prefix=dynamic_prefix)
