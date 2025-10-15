from fastapi import Header, HTTPException
from ..core.security import verify_token

async def get_current_username(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = authorization.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return username
