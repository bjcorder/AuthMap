from fastapi import APIRouter, Depends

router = APIRouter(prefix="/accounts")


def require_user():
    return {"id": "user_1"}


def require_admin(user=Depends(require_user)):
    if user.get("role") != "admin":
        raise PermissionError("admin required")
    return user


@router.get("/me")
def get_profile(user=Depends(require_user)):
    return user


@router.delete("/{account_id}", dependencies=[Depends(require_admin)])
def delete_account(account_id: str):
    return {"deleted": account_id}
