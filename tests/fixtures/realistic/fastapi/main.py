from fastapi import APIRouter, Depends, FastAPI

from app.routers.accounts import router as accounts_router

app = FastAPI()
dynamic_prefix = "/dynamic"
dynamic_router = APIRouter(prefix=dynamic_prefix)


def require_user():
    return {"id": "user_1", "role": "member", "permissions": ["accounts.write"]}


def require_admin(user=Depends(require_user)):
    if user.get("role") != "admin":
        raise PermissionError("admin required")
    return user


def can_edit_account(user=Depends(require_user)):
    return "accounts.write" in user.get("permissions", [])


def dynamic_policy_check(policy_name: str):
    return policy_name == "accounts.update"


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/admin/audit")
def audit_log(user=Depends(require_admin)):
    return {"admin": user["id"]}


@dynamic_router.get("/reports")
def dynamic_reports(user=Depends(require_user)):
    return []


app.include_router(accounts_router, prefix="/api")
app.include_router(dynamic_router, prefix=dynamic_prefix)
