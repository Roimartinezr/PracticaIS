from fastapi import APIRouter, Depends
from ...api.deps import get_current_username
from ...db.repository import get_stats_db_for_user

router = APIRouter()

@router.get("/stats")
async def get_stats(username: str = Depends(get_current_username)):
    return get_stats_db_for_user(username)
