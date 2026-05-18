from fastapi import FastAPI, APIRouter, Depends
from app.factories.collection import make_collection_router
from app.factories.custom import make_factory_router
from app.services.account import AccountService
from app.routes.users import router as users_router

app = FastAPI()
local_router = APIRouter(prefix="/local", tags=["local-default"])
dynamic_prefix = "/dynamic"
dynamic_path = "/generated"
ALIAS_SOURCE_PATH = "/constant"
ALIASED_PATH = ALIAS_SOURCE_PATH
runtime_path = get_runtime_path()
dynamic_router = APIRouter(prefix=dynamic_prefix)


def require_user():
    return {"id": "user_1"}


def require_admin(user=Depends(require_user)):
    if user.get("role") != "admin":
        raise PermissionError("admin required")
    return user


def can_edit_account(user=Depends(require_user)):
    return True


def dynamic_policy_check(policy_name: str):
    return policy_name == "account.update"


def provide_database_interface():
    return object()


@app.get("/health", name="healthcheck", tags=["system"])
def health():
    return {"ok": True}


@app.post(path="/items", tags=["items"])
def create_item():
    return {"created": True}


@app.get("/profile")
def profile(user=Depends(require_user)):
    return user


@app.delete("/admin/accounts/{account_id}", dependencies=[Depends(require_admin)])
def delete_account(account_id: str):
    return {"deleted": account_id}


@app.patch("/accounts/{account_id}/permissions", dependencies=[Depends(can_edit_account)])
def grant_permission(account_id: str):
    if not dynamic_policy_check("account.update"):
        raise PermissionError("policy denied")
    return {"account_id": account_id}


@app.post("/service/accounts")
def service_account(service: AccountService = Depends()):
    service.execute()
    return {"ok": True}


@local_router.delete("/{item_id}", name="delete_local")
def delete_local(item_id: str):
    return {"deleted": item_id}


variable_router = APIRouter(prefix="/variable")


@variable_router.get("/settings")
def variable_settings():
    return {}


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


@app.get(ALIASED_PATH)
def constant_alias_path():
    return {}


@app.get(runtime_path)
def unresolved_runtime_path():
    return {}


def register_default_paths(
    status_path: str = "/factory/status",
    ready_path: str = "/factory/ready",
):
    @app.get(status_path)
    def default_status_path():
        return {}

    @app.get(path=ready_path)
    def default_ready_path():
        return {}


app.include_router(local_router, prefix="/api", dependencies=[Depends(require_user)])
app.include_router(users_router, prefix="/v1")
app.include_router(make_factory_router())
ROUTERS = (make_collection_router(),)
for router in ROUTERS:
    app.include_router(router)
shared_dependencies = [Depends(require_user)]
shared_dependencies.append(Depends(can_edit_account))
shared_dependencies.append(Depends(provide_database_interface))
SHARED_ROUTERS = (variable_router, users_router)
for router in SHARED_ROUTERS:
    app.include_router(router, prefix="/shared", dependencies=shared_dependencies)
app.include_router(dynamic_router, prefix=dynamic_prefix)
