from fastapi import FastAPI, APIRouter, Depends
from app.routes.users import router as users_router

app = FastAPI()
local_router = APIRouter(prefix="/local", tags=["local-default"])
dynamic_prefix = "/dynamic"
dynamic_path = "/generated"
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
