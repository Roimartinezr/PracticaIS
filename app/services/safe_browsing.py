import httpx
from ..core.config import settings

# Igual que tu lógica: Google Safe Browsing v4, con fallback gestionado desde el router. :contentReference[oaicite:8]{index=8}
async def check_url_google_safe_browsing(url: str) -> dict:
    key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not key:
        raise RuntimeError("GOOGLE_SAFE_BROWSING_API_KEY not configured")
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    payload = {
        "client": {"clientId": "phishguard-local", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    async with httpx.AsyncClient(timeout=8.0) as client:
        r = await client.post(endpoint, json=payload)
        if r.status_code != 200:
            return {"verdict": "Desconocido", "reason": f"Google API returned {r.status_code}", "raw": r.text}
        data = r.json()
        if not data or "matches" not in data:
            return {"verdict": "Segura", "reason": "No encontrada en listas negras públicas", "raw": data}
        reasons = []
        for m in data.get("matches", []):
            t = m.get("threatType") or ""
            p = m.get("platformType") or ""
            et = m.get("threatEntryType") or ""
            reasons.append(f"{t} on {p} ({et})")
        return {"verdict": "Maliciosa", "reason": ", ".join(reasons), "raw": data}
