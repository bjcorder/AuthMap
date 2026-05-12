from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.models import Account
from app.services.accounts import create_account, delete_account, update_account
from main import can_edit_account, dynamic_policy_check, require_admin, require_user

router = APIRouter(prefix="/accounts")


@router.get("/{account_id}")
def read_account(account_id: str, user=Depends(require_user)):
    return {"id": account_id, "user": user["id"]}


@router.post("")
def create_account_route(session: Session, user=Depends(require_user)):
    account = Account(name="direct", owner_id=user["id"])
    session.add(account)
    session.commit()
    return {"created": True}


@router.patch("/{account_id}")
def update_account_route(account_id: str, user=Depends(can_edit_account)):
    if not dynamic_policy_check("accounts.update"):
        raise PermissionError("policy denied")
    return update_account(account_id, {"name": "renamed"})


@router.delete("/{account_id}")
def delete_account_route(account_id: str, user=Depends(require_admin)):
    return delete_account(account_id)


@router.post("/service")
def service_create_account(user=Depends(require_user)):
    return create_account(user["id"])


@router.post("/dynamic-service")
def dynamic_service_create(user=Depends(require_user)):
    return account_services["create"](user["id"])
