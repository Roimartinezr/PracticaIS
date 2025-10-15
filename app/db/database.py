import os, json, sqlite3, logging
from . import repository
from ..core.config import settings

logging.basicConfig(level=logging.INFO)

def ensure_data_dir():
    if not os.path.exists(settings.DATA_DIR):
        os.makedirs(settings.DATA_DIR, exist_ok=True)

def get_db_conn():
    ensure_data_dir()
    conn = sqlite3.connect(settings.DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        type TEXT,
        input TEXT,
        verdict TEXT,
        percentage INTEGER,
        timestamp TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        salt TEXT,
        created_at TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        username TEXT,
        expires_at TEXT
    )""")
    conn.commit(); conn.close()

def migrate_json_history():
    # Igual que tu monolito: leer legacy history.json si existe y volcar a SQLite. :contentReference[oaicite:5]{index=5}
    legacy = settings.LEGACY_HISTORY_JSON
    if os.path.exists(legacy):
        try:
            with open(legacy, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                conn = get_db_conn(); cur = conn.cursor()
                for e in data:
                    cur.execute(
                        "INSERT INTO history (username,type,input,verdict,percentage,timestamp) VALUES (?,?,?,?,?,?)",
                        (None, e.get("type"), e.get("input"), e.get("verdict"),
                         e.get("percentage"), e.get("timestamp")),
                    )
                conn.commit(); conn.close()
            with open(legacy, "w", encoding="utf-8") as f:
                json.dump([], f)
        except Exception:
            pass

def ensure_db_schema():
    # Añade columna username en history si faltase (migración idempotente). :contentReference[oaicite:6]{index=6}
    conn = get_db_conn(); cur = conn.cursor()
    try:
        cur.execute("PRAGMA table_info(history)")
        cols = [r[1] for r in cur.fetchall()]
        if "username" not in cols:
            cur.execute("ALTER TABLE history ADD COLUMN username TEXT")
            conn.commit()
    except Exception:
        logging.exception("Failed to ensure DB schema")
    finally:
        conn.close()
