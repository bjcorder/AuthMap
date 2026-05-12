from sqlalchemy import text


def read_only(session):
    # session.delete(user)
    sql = "update users set disabled = true"
    return session.execute(text("select * from users"))

