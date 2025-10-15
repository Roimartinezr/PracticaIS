import secrets
import hashlib
import datetime
from ..db.database import get_db_conn

# Igual que en tu monolito: PBKDF2-HMAC-SHA256 con 150k iteraciones. :contentReference[oaicite:4]{index=4}
def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150000)
    return pw_hash.hex(), salt.hex()

def verify_password(password: str, pw_hash_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150000).hex()
    return secrets.compare_digest(calc, pw_hash_hex)

def create_user(username: str, password: str) -> bool:
    conn = get_db_conn(); cur = conn.cursor()
    pw_hash, salt = hash_password(password)
    try:
        cur.execute(
            "INSERT INTO users (username,password_hash,salt,created_at) VALUES (?,?,?,?)",
            (username, pw_hash, salt, datetime.datetime.now().isoformat()),
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat()
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO sessions (token,username,expires_at) VALUES (?,?,?)",
                (token, username, expires))
    conn.commit(); conn.close()
    return token

def verify_token(token: str) -> str | None:
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute("SELECT username,expires_at FROM sessions WHERE token=?", (token,))
    r = cur.fetchone(); conn.close()
    if not r:
        return None
    if datetime.datetime.fromisoformat(r["expires_at"]) < datetime.datetime.utcnow():
        return None
    return r["username"]

def delete_session(token: str) -> None:
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit(); conn.close()
