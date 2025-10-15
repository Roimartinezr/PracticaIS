from fastapi import APIRouter, HTTPException, Depends, Request
from ...models.schemas import Credentials
from ...core.security import create_user, create_session, verify_password, delete_session
from ...db.database import get_db_conn

router = APIRouter()

@router.post("/signup")
async def signup(creds: Credentials):
    if not creds.username or not creds.password:
        raise HTTPException(status_code=400, detail="username and password required")
    ok = create_user(creds.username, creds.password)
    if not ok:
        raise HTTPException(status_code=400, detail="username already exists")
    return {"message": "user created"}

@router.post("/login")
async def login(creds: Credentials):
    if not creds.username or not creds.password:
        raise HTTPException(status_code=400, detail="username and password required")
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute("SELECT password_hash,salt FROM users WHERE username=?", (creds.username,))
    r = cur.fetchone(); conn.close()
    if not r or not verify_password(creds.password, r["password_hash"], r["salt"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = create_session(creds.username)
    return {"token": token, "username": creds.username}

@router.post("/logout")
async def logout(request: Request):
    auth = request.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = auth.split(None, 1)[1]
    delete_session(token)
    return {"message": "logged out"}

@router.post("/reset_stats")
async def reset_stats(request: Request):
    auth = request.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = auth.split(None, 1)[1]
    # Reutiliza logout->verify_token vía endpoint history/stats, pero aquí basta con eliminar historial por token
    # Para respetar el comportamiento original, hay que conocer el username:
    from ...core.security import verify_token
    from ...db.repository import clear_history_db
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    clear_history_db(username)
    return {"message": "stats reset (history cleared for user)"}
