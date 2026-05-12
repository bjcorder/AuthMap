from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from fastapi_models import User
from fastapi_services import create_user

app = FastAPI()


def require_user():
    return {"id": "user_1"}


@app.post("/fastapi/direct")
def fastapi_direct(session: Session, user=Depends(require_user)):
    record = User(email="direct@example.test")
    session.add(record)
    session.commit()
    return {"ok": True}


@app.post("/fastapi/service")
def fastapi_service(user=Depends(require_user)):
    return create_user("service@example.test")


@app.post("/fastapi/dynamic")
def fastapi_dynamic(user=Depends(require_user)):
    return service_registry["create_user"]("dynamic@example.test")


@app.get("/fastapi/read")
def fastapi_read():
    return {"ok": True}
