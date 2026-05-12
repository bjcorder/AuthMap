from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.models import Account


session = Session()


def create_account(owner_id: str):
    account = Account(name="service", owner_id=owner_id)
    session.add(account)
    session.commit()
    return account


def update_account(account_id: str, data):
    session.execute(update(Account))
    return {"id": account_id, **data}


def delete_account(account_id: str):
    session.execute(delete(Account))
    return {"deleted": account_id}
