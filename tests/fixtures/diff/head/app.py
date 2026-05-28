from fastapi import Depends, FastAPI

app = FastAPI()


def require_user():
    return {"id": "user_1"}


def dynamic_policy_check():
    return "review_required"


class Account:
    id = "account_id"


@app.get("/accounts/{account_id}")
def read_account(account_id: str, user=Depends(require_user)):
    session.query(Account).filter(Account.id == account_id).delete()
    return {"id": account_id}


@app.patch("/accounts/{account_id}")
def update_account(account_id: str, user=Depends(require_user)):
    dynamic_policy_check()
    session.query(Account).filter(Account.id == account_id).update({"name": "head"})
    return {"ok": True}


@app.post("/accounts")
def create_account():
    session.add(Account())
    return {"created": True}
