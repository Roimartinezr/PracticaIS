from .database import get_db_conn

def add_history_db(entry: dict):
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO history (username,type,input,verdict,percentage,timestamp) VALUES (?,?,?,?,?,?)",
        (entry.get("username"), entry.get("type"), entry.get("input"),
         entry.get("verdict"), entry.get("percentage"), entry.get("timestamp"))
    )
    conn.commit(); conn.close()

def get_history_db(username: str | None = None):
    conn = get_db_conn(); cur = conn.cursor()
    if username:
        cur.execute("SELECT type,input,verdict,percentage,timestamp FROM history WHERE username=? ORDER BY id ASC", (username,))
    else:
        cur.execute("SELECT type,input,verdict,percentage,timestamp FROM history ORDER BY id ASC")
    rows = cur.fetchall(); conn.close()
    return [dict(r) for r in rows]

def clear_history_db(username: str | None = None):
    conn = get_db_conn(); cur = conn.cursor()
    if username:
        cur.execute("DELETE FROM history WHERE username=?", (username,))
    else:
        cur.execute("DELETE FROM history")
    conn.commit(); conn.close()

def get_stats_db():
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM history")
    total = cur.fetchone()["total"]
    cur.execute('SELECT percentage FROM history WHERE type="texto" AND percentage IS NOT NULL')
    text_rows = [r[0] for r in cur.fetchall()]
    conn.close()

    if total == 0:
        return {"total": 0, "avg_risk": 0, "safe": 0, "suspicious": 0, "phishing": 0}
    avg_risk = sum(text_rows) / len(text_rows) if text_rows else 0
    safe = len([p for p in text_rows if p <= 33]) / len(text_rows) * 100 if text_rows else 0
    suspicious = len([p for p in text_rows if 33 < p <= 66]) / len(text_rows) * 100 if text_rows else 0
    phishing = len([p for p in text_rows if p > 66]) / len(text_rows) * 100 if text_rows else 0
    return {"total": total, "avg_risk": int(avg_risk), "safe": int(safe), "suspicious": int(suspicious), "phishing": int(phishing)}

def get_stats_db_for_user(username: str):
    conn = get_db_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM history WHERE username=?", (username,))
    total = cur.fetchone()["total"]
    cur.execute('SELECT percentage FROM history WHERE type="texto" AND percentage IS NOT NULL AND username=?', (username,))
    text_rows = [r[0] for r in cur.fetchall()]
    conn.close()

    if total == 0:
        return {"total": 0, "avg_risk": 0, "safe": 0, "suspicious": 0, "phishing": 0}
    avg_risk = sum(text_rows) / len(text_rows) if text_rows else 0
    safe = len([p for p in text_rows if p <= 33]) / len(text_rows) * 100 if text_rows else 0
    suspicious = len([p for p in text_rows if 33 < p <= 66]) / len(text_rows) * 100 if text_rows else 0
    phishing = len([p for p in text_rows if p > 66]) / len(text_rows) * 100 if text_rows else 0
    return {"total": total, "avg_risk": int(avg_risk), "safe": int(safe), "suspicious": int(suspicious), "phishing": int(phishing)}
