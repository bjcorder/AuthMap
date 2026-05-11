from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models import User


def create_user(session: Session, email: str):
    user = User(email=email)
    session.add(user)
    session.commit()
    return user


def disable_user(session: Session, user_id: str):
    user = session.get(User, user_id)
    user.disabled = True
    session.commit()
    return user


def raw_delete(session: Session, user_id: str):
    session.execute(text("delete from sessions where user_id = :user_id"), {"user_id": user_id})
    session.commit()
