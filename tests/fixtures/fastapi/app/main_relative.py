from fastapi import FastAPI

from .routes.users import router as relative_users_router

app = FastAPI()

app.include_router(relative_users_router, prefix="/relative")
