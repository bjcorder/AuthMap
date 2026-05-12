from sqlalchemy.orm import Session

from fastapi_models import User


def create_user(email: str):
    session = Session()
    record = User(email=email)
    session.add(record)
    session.commit()
    return record
