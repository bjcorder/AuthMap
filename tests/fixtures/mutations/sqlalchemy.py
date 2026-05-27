from sqlalchemy import delete, insert, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models import SessionToken, User


def create_user(session: Session, email: str):
    user = User(email=email)
    session.add(user)
    session.commit()
    return user


def create_many(session: Session, emails: list[str]):
    users = [User(email=email) for email in emails]
    session.add_all(users)
    session.commit()


def disable_user(session: Session, user_id: str):
    user = session.get(User, user_id)
    user.disabled = True
    session.commit()
    return user


def disable_with_execute(session: Session, user_id: str):
    session.execute(update(User).where(User.id == user_id).values(disabled=True))
    session.commit()


def delete_user(session: Session, user_id: str):
    user = session.get(User, user_id)
    session.delete(user)
    session.commit()


def delete_tokens(session: Session, user_id: str):
    session.execute(delete(SessionToken).where(SessionToken.user_id == user_id))
    session.commit()


def raw_delete(session: Session, user_id: str):
    session.execute(text("delete from sessions where user_id = :user_id"), {"user_id": user_id})
    session.commit()


def read_only(session: Session, user_id: str):
    return session.execute(text("select * from users where id = :user_id"), {"user_id": user_id})


def create_with_execute(session: Session, email: str):
    session.execute(insert(User).values(email=email))
    session.commit()


async def upsert_token(db_conn: AsyncSession, token: SessionToken):
    db_conn.merge(token)
    await db_conn.commit()
