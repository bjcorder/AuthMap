from fastapi import APIRouter

router = APIRouter(prefix="/users")


@router.get("/{user_id}", name="get_user", tags=["users"])
def get_user(user_id: str):
    return {"id": user_id}


@router.put("/{user_id}", tags=["users"])
def update_user(user_id: str):
    return {"id": user_id}
