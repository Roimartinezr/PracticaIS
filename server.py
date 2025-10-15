from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any
import datetime
import re
import os
import json
import asyncio
import httpx
import sqlite3
import secrets
import hashlib
from dotenv import load_dotenv
import logging

# Load .env if exists (convenience)
load_dotenv()

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="PhishGuard AI - Dev Server")

# Allow all origins for local development (reduce for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (index.html, script.js, style.css)
HERE = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=HERE), name="static")

# Database file
DATA_DIR = os.path.join(HERE, 'data')
DB_FILE = os.path.join(DATA_DIR, 'app.db')


def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)


def get_db_conn():
    ensure_data_dir()
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    # history table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        type TEXT,
        input TEXT,
        verdict TEXT,
        percentage INTEGER,
        timestamp TEXT
    )
    ''')
    # users table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        salt TEXT,
        created_at TEXT
    )
    ''')
    # sessions table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        username TEXT,
        expires_at TEXT
    )
    ''')
    conn.commit()
    conn.close()


def migrate_json_history():
    # If legacy history.json exists, migrate into DB once
    legacy = os.path.join(DATA_DIR, 'history.json')
    if os.path.exists(legacy):
        try:
            with open(legacy, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                conn = get_db_conn(); cur = conn.cursor()
                for e in data:
                    # legacy JSON has no username; migrate as NULL
                    cur.execute('INSERT INTO history (username,type,input,verdict,percentage,timestamp) VALUES (?,?,?,?,?,?)',
                                (None, e.get('type'), e.get('input'), e.get('verdict'), e.get('percentage'), e.get('timestamp')))
                conn.commit(); conn.close()
            # optionally keep or remove legacy file; we keep it but empty
            with open(legacy, 'w', encoding='utf-8') as f:
                json.dump([], f)
        except Exception:
            pass


# Initialize DB and migrate
init_db()
migrate_json_history()


def ensure_db_schema():
    """Run small migrations to ensure required columns exist (idempotent).
    Adds `username` column to `history` if missing.
    """
    conn = get_db_conn(); cur = conn.cursor()
    try:
        cur.execute("PRAGMA table_info(history)")
        cols = [r[1] for r in cur.fetchall()]
        if 'username' not in cols:
            # Add the username column (nullable) for older DBs
            cur.execute('ALTER TABLE history ADD COLUMN username TEXT')
            conn.commit()
    except Exception:
        # If anything fails, don't crash on startup; log and continue
        logging.exception('Failed to ensure DB schema')
    finally:
        conn.close()


ensure_db_schema()


class AnalyzeRequest(BaseModel):
    text: str


class AnalyzeUrlRequest(BaseModel):
    url: str


class HistoryEntry(BaseModel):
    type: str
    input: str
    verdict: str
    percentage: int = None


def extract_urls(text: str) -> List[str]:
    # simple regex to extract http/https URLs
    pattern = r"https?://[\w\-\.\/~:?&=#%+\[\]]+"
    return re.findall(pattern, text)


def add_history_db(entry: Dict[str, Any]):
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute('INSERT INTO history (username,type,input,verdict,percentage,timestamp) VALUES (?,?,?,?,?,?)',
                (entry.get('username'), entry.get('type'), entry.get('input'), entry.get('verdict'), entry.get('percentage'), entry.get('timestamp')))
    conn.commit(); conn.close()


def get_history_db(username: str | None = None):
    conn = get_db_conn(); cur = conn.cursor()
    if username:
        cur.execute('SELECT type,input,verdict,percentage,timestamp FROM history WHERE username=? ORDER BY id ASC', (username,))
    else:
        cur.execute('SELECT type,input,verdict,percentage,timestamp FROM history ORDER BY id ASC')
    rows = cur.fetchall(); conn.close()
    return [dict(r) for r in rows]


def clear_history_db(username: str | None = None):
    conn = get_db_conn(); cur = conn.cursor()
    if username:
        cur.execute('DELETE FROM history WHERE username=?', (username,))
    else:
        cur.execute('DELETE FROM history')
    conn.commit(); conn.close()


def get_stats_db():
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute('SELECT COUNT(*) as total FROM history')
    total = cur.fetchone()['total']

    cur.execute('SELECT percentage FROM history WHERE type = "texto" AND percentage IS NOT NULL')
    text_rows = [r[0] for r in cur.fetchall()]
    conn.close()
    if total == 0:
        return {"total": 0, "avg_risk": 0, "safe": 0, "suspicious": 0, "phishing": 0}
    text_entries = text_rows
    avg_risk = sum(text_entries) / len(text_entries) if text_entries else 0
    safe = len([p for p in text_entries if p <= 33]) / len(text_entries) * 100 if text_entries else 0
    suspicious = len([p for p in text_entries if 33 < p <= 66]) / len(text_entries) * 100 if text_entries else 0
    phishing = len([p for p in text_entries if p > 66]) / len(text_entries) * 100 if text_entries else 0
    return {"total": total, "avg_risk": int(avg_risk), "safe": int(safe), "suspicious": int(suspicious), "phishing": int(phishing)}


def get_stats_db_for_user(username: str):
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute('SELECT COUNT(*) as total FROM history WHERE username=?', (username,))
    total = cur.fetchone()['total']

    cur.execute('SELECT percentage FROM history WHERE type = "texto" AND percentage IS NOT NULL AND username=?', (username,))
    text_rows = [r[0] for r in cur.fetchall()]
    conn.close()
    if total == 0:
        return {"total": 0, "avg_risk": 0, "safe": 0, "suspicious": 0, "phishing": 0}
    text_entries = text_rows
    avg_risk = sum(text_entries) / len(text_entries) if text_entries else 0
    safe = len([p for p in text_entries if p <= 33]) / len(text_entries) * 100 if text_entries else 0
    suspicious = len([p for p in text_entries if 33 < p <= 66]) / len(text_entries) * 100 if text_entries else 0
    phishing = len([p for p in text_entries if p > 66]) / len(text_entries) * 100 if text_entries else 0
    return {"total": total, "avg_risk": int(avg_risk), "safe": int(safe), "suspicious": int(suspicious), "phishing": int(phishing)}


def score_url(url: str) -> Dict[str, Any]:
    # Heurística simple y reproducible para valoración de URL
    score = 0
    reasons = []

    # IP address instead of domain
    if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", url):
        score += 30
        reasons.append("Uso de dirección IP en URL")

    # Long URL
    if len(url) > 75:
        score += 15
        reasons.append("URL muy larga")

    # Muchos guiones o caracteres sospechosos
    if url.count("-") > 2 or re.search(r"[<>]", url):
        score += 10
        reasons.append("Sintaxis sospechosa")

    # TLDs raros o palabras comunes asociadas a phishing
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    if any(url.lower().endswith(t) for t in suspicious_tlds):
        score += 20
        reasons.append("TLD con reputación débil")

    suspicious_words = ["login", "verify", "secure", "update", "confirm", "account", "bank"]
    if any(w in url.lower() for w in suspicious_words):
        score += 18
        reasons.append("Palabras asociadas a phishing en la URL")

    # Clamp
    score = max(0, min(100, score))

    verdict = "Maliciosa" if score > 60 else "Sospechosa" if score > 30 else "Segura"
    reason = ", ".join(reasons) if reasons else "Sin señales fuertes"
    return {"url": url, "score": score, "verdict": verdict, "reason": reason}


def score_text(text: str) -> Dict[str, Any]:
    # Heurística simple basada en palabras clave y presencia de URLs
    score = 0
    reasons = []

    keywords_high = ["transferir", "verifique", "verificar", "bloqueada", "urgente", "inmediatamente", "confirmar", "credenciales", "contraseña", "pago"]
    keywords_medium = ["problema", "alerta", "suscrito", "ganó", "felicitaciones"]

    low_count = sum(1 for w in keywords_medium if w in text.lower())
    mid_count = sum(1 for w in keywords_high if w in text.lower())

    score += mid_count * 18
    score += low_count * 8

    urls = extract_urls(text)
    if urls:
        # cada URL añade riesgo según su propia puntuación
        for u in urls:
            url_info = score_url(u)
            score += url_info["score"] * 0.6
            reasons.append(f"URL detectada: {u} ({url_info['verdict']})")

    # Mensajes en mayúsculas, muchos signos de exclamación, etc.
    if re.search(r"[A-Z]{5,}", text):
        score += 8
        reasons.append("Texto en mayúsculas — tono alarmista")
    if text.count("!") >= 2:
        score += 6
        reasons.append("Uso excesivo de signos de exclamación")

    score = int(max(0, min(100, score)))
    verdict = "Phishing" if score > 66 else "Sospechoso" if score > 33 else "Seguro"
    return {"percentage": score, "verdict": verdict, "reasons": reasons, "url_results": [score_url(u) for u in urls]}


async def check_url_google_safe_browsing(url: str) -> Dict[str, Any]:
    """Query Google Safe Browsing API v4 to check whether a URL is flagged.
    Requires environment variable GOOGLE_SAFE_BROWSING_API_KEY to be set.
    Returns a dict with keys: verdict (Segura/Sospechosa/Maliciosa), reason, raw.
    """
    key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if not key:
        raise RuntimeError('GOOGLE_SAFE_BROWSING_API_KEY not configured')
    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}'
    payload = {
        "client": {"clientId": "phishguard-local", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.post(endpoint, json=payload)
            if r.status_code != 200:
                return {"verdict": "Desconocido", "reason": f"Google API returned {r.status_code}", "raw": r.text}
            data = r.json()
            if not data or 'matches' not in data:
                return {"verdict": "Segura", "reason": "No encontrada en listas negras públicas", "raw": data}
            # There are matches: aggregate reasons
            reasons = []
            for m in data.get('matches', []):
                t = m.get('threatType') or ''
                p = m.get('platformType') or ''
                et = m.get('threatEntryType') or ''
                reasons.append(f"{t} on {p} ({et})")
            return {"verdict": "Maliciosa", "reason": ", ".join(reasons), "raw": data}
    except Exception as e:
        return {"verdict": "Desconocido", "reason": f"error contacting Google SafeBrowsing: {e}", "raw": None}


@app.post("/analyze")
async def analyze_text(request: AnalyzeRequest, http_request: Request):
    # Require authentication
    auth = http_request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail='invalid or expired token')

    # Minimal local analysis to avoid external dependencies
    text = (request.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Texto vacío")

    # GEMINI: prefer external model for text analysis, but fallback to local heuristics if not configured or on error
    gemini_key = os.getenv('GEMINI_API_KEY')
    gemini_url = os.getenv('GEMINI_API_URL')
    if gemini_key and gemini_url:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                payload = {"prompt": f"Analiza este texto y responde JSON con fields verdict (Seguro/Sospechoso/Phishing) and percentage (0-100) and reasons list:\n\n{ text }", "max_tokens": 400}
                headers = {"Authorization": f"Bearer {gemini_key}", "Content-Type": "application/json"}
                r = await client.post(gemini_url, json=payload, headers=headers)
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except Exception:
                        data = None
                    if isinstance(data, dict) and ("verdict" in data or "percentage" in data):
                        combined = data.get('verdict', 'Sospechoso')
                        percentage = int(data.get('percentage', 0))
                        url_results = data.get('url_results', []) if isinstance(data.get('url_results', []), list) else []
                        entry = {"username": username, "type": "texto", "input": text, "verdict": combined, "percentage": percentage, "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                        add_history_db(entry)
                        return {"combined_verdict": combined, "percentage": percentage, "url_results": url_results, "reasons": data.get('reasons', [])}
                    # Try parse textual response
                    text_resp = r.text
                    m_pct = re.search(r"(\d{1,3})\s*%", text_resp)
                    pct = int(m_pct.group(1)) if m_pct else 0
                    if "phish" in text_resp.lower() or "malicious" in text_resp.lower():
                        combined = "Phishing"
                    elif "sospech" in text_resp.lower() or "suspicious" in text_resp.lower():
                        combined = "Sospechoso"
                    else:
                        combined = "Seguro"
                    entry = {"username": username, "type": "texto", "input": text, "verdict": combined, "percentage": pct, "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    add_history_db(entry)
                    return {"combined_verdict": combined, "percentage": pct, "url_results": [], "reasons": [text_resp[:400]]}
                else:
                    logging.warning(f'External text API returned status {r.status_code}, falling back to local heuristics')
        except Exception as e:
            logging.warning(f'Error calling external text API, falling back to local heuristics: {e}')

    # Fallback local analysis
    analysis = score_text(text)
    entry = {"username": username, "type": "texto", "input": text, "verdict": analysis['verdict'], "percentage": analysis['percentage'], "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    add_history_db(entry)
    return {"combined_verdict": analysis["verdict"], "percentage": analysis["percentage"], "url_results": [{"url": u["url"], "verdict": u["verdict"], "reason": u["reason"]} for u in analysis["url_results"]], "reasons": analysis["reasons"]}


@app.post("/analyze_url")
async def analyze_url(request: AnalyzeUrlRequest, http_request: Request):
    # auth
    auth = http_request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail='invalid or expired token')

    url = (request.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL vacía")

    gemini_key = os.getenv('GEMINI_API_KEY')
    gemini_url = os.getenv('GEMINI_API_URL')
    # For URL analysis, use Google Safe Browsing. Do not use local heuristics as fallback.
    # Prefer Google Safe Browsing when available; otherwise fallback to local heuristics
    try:
        res = await check_url_google_safe_browsing(url)
        verdict = res.get('verdict', 'Desconocido')
        reason = res.get('reason', '')
    except RuntimeError as e:
        # missing API key -> fallback
        logging.info('Google Safe Browsing API key not configured, using local heuristics')
        info = score_url(url)
        verdict = info['verdict']; reason = info['reason']
    except Exception as e:
        logging.warning(f'Error calling Google Safe Browsing, falling back to local heuristics: {e}')
        info = score_url(url)
        verdict = info['verdict']; reason = info['reason']

    entry = {"username": username, "type": "url", "input": url, "verdict": verdict, "percentage": None, "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    add_history_db(entry)
    return {"verdict": verdict, "reason": reason}


@app.get("/history")
async def get_history(http_request: Request):
    auth = http_request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail='invalid or expired token')
    return get_history_db(username)


@app.post("/history")
async def add_to_history(entry: HistoryEntry, http_request: Request):
    auth = http_request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail='invalid or expired token')
    entry_dict = entry.dict()
    entry_dict["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry_dict["username"] = username
    add_history_db(entry_dict)
    return {"message": "Entry added to history"}


@app.delete("/history")
async def clear_history(http_request: Request):
    auth = http_request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail='invalid or expired token')
    clear_history_db(username)
    return {"message": "History cleared"}


@app.get("/stats")
async def get_stats(http_request: Request):
    auth = http_request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail='invalid or expired token')
    # return stats filtered for the user
    return get_stats_db_for_user(username)


######### AUTH ################################################################
def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 150000)
    return pw_hash.hex(), salt.hex()


def verify_password(password: str, pw_hash_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    calc = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 150000).hex()
    return secrets.compare_digest(calc, pw_hash_hex)


def create_user(username: str, password: str) -> bool:
    conn = get_db_conn(); cur = conn.cursor()
    pw_hash, salt = hash_password(password)
    try:
        cur.execute('INSERT INTO users (username,password_hash,salt,created_at) VALUES (?,?,?,?)',
                    (username, pw_hash, salt, datetime.datetime.now().isoformat()))
        conn.commit(); return True
    except Exception:
        return False
    finally:
        conn.close()


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat()
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute('INSERT INTO sessions (token,username,expires_at) VALUES (?,?,?)', (token, username, expires))
    conn.commit(); conn.close()
    return token


def verify_token(token: str) -> str | None:
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute('SELECT username,expires_at FROM sessions WHERE token=?', (token,))
    r = cur.fetchone(); conn.close()
    if not r:
        return None
    if datetime.datetime.fromisoformat(r['expires_at']) < datetime.datetime.utcnow():
        return None
    return r['username']


def delete_session(token: str):
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute('DELETE FROM sessions WHERE token=?', (token,))
    conn.commit(); conn.close()


@app.post('/signup')
async def signup(data: Dict[str, str]):
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        raise HTTPException(status_code=400, detail='username and password required')
    ok = create_user(username, password)
    if not ok:
        raise HTTPException(status_code=400, detail='username already exists')
    return {'message': 'user created'}


@app.post('/login')
async def login(data: Dict[str, str]):
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        raise HTTPException(status_code=400, detail='username and password required')
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute('SELECT password_hash,salt FROM users WHERE username=?', (username,))
    r = cur.fetchone(); conn.close()
    if not r:
        raise HTTPException(status_code=401, detail='invalid credentials')
    if not verify_password(password, r['password_hash'], r['salt']):
        raise HTTPException(status_code=401, detail='invalid credentials')
    token = create_session(username)
    return {'token': token, 'username': username}


@app.post('/logout')
async def logout(request: Request):
    auth = request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    delete_session(token)
    return {'message': 'logged out'}


@app.post('/reset_stats')
async def reset_stats(request: Request):
    auth = request.headers.get('authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='missing token')
    token = auth.split(None, 1)[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail='invalid or expired token')
    # For now reset equals clear history for this user
    clear_history_db(username)
    return {'message': 'stats reset (history cleared for user)'}


@app.get("/")
async def root():
    # Dev convenience: serve the index.html so you can open http://127.0.0.1:8000/
    index_path = os.path.join(HERE, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return JSONResponse({"message": "Index file not found"}, status_code=404)


@app.get("/style.css")
async def css():
    p = os.path.join(HERE, "style.css")
    if os.path.exists(p):
        return FileResponse(p, media_type="text/css")
    raise HTTPException(status_code=404, detail="style.css not found")


@app.get("/script.js")
async def js():
    p = os.path.join(HERE, "script.js")
    if os.path.exists(p):
        return FileResponse(p, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="script.js not found")


@app.get("/favicon.ico")
async def favicon():
    p = os.path.join(HERE, "favicon.ico")
    if os.path.exists(p):
        return FileResponse(p, media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="favicon not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
