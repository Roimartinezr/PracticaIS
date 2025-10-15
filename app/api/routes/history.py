import datetime
from fastapi import APIRouter, Depends, HTTPException
from ...api.deps import get_current_username
from ...models.schemas import HistoryEntry
from ...db.repository import add_history_db, get_history_db, clear_history_db

router = APIRouter()

@router.get("/history")
async def history_get(username: str = Depends(get_current_username)):
    return get_history_db(username)

@router.post("/history")
async def history_add(entry: HistoryEntry, username: str = Depends(get_current_username)):
    entry_dict = entry.dict() if hasattr(entry, "dict") else entry.model_dump()
    entry_dict["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry_dict["username"] = username
    add_history_db(entry_dict)
    return {"message": "Entry added to history"}

@router.delete("/history")
async def history_clear(username: str = Depends(get_current_username)):
    clear_history_db(username)
    return {"message": "History cleared"}
