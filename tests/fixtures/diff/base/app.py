from fastapi import Depends, FastAPI

app = FastAPI()


def require_user():
    return {"id": "user_1"}


def require_tenant():
    return {"tenant_id": "tenant_1"}


def can_edit_account():
    return True


class Account:
    id = "account_id"


@app.get("/accounts/{account_id}")
def read_account(account_id: str, user=Depends(require_user), tenant=Depends(require_tenant)):
    return {"id": account_id, "tenant": tenant}


@app.patch("/accounts/{account_id}")
def update_account(account_id: str, allowed=Depends(can_edit_account)):
    session.query(Account).filter(Account.id == account_id).update({"name": "base"})
    return {"ok": allowed}
