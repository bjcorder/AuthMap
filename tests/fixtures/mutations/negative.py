from sqlalchemy import text


def read_only(session):
    # session.delete(user)
    sql = "update users set disabled = true"
    return session.execute(text("select * from users"))


def ordinary_helpers(cart, cache, entry, worker):
    cart.add(CacheEntry())
    cache.delete("session")
    entry.save()
    worker.execute("delete-local-cache")
