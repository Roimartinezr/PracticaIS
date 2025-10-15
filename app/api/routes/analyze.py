import datetime, re, httpx, logging
from fastapi import APIRouter, HTTPException, Depends
from ...models.schemas import AnalyzeRequest, AnalyzeUrlRequest
from ...api.deps import get_current_username
from ...db.repository import add_history_db
from ...services.scoring import score_text, score_url
from ...services.safe_browsing import check_url_google_safe_browsing
from ...core.config import settings

router = APIRouter()

@router.post("/analyze")
async def analyze_text(request: AnalyzeRequest, username: str = Depends(get_current_username)):
    text = (request.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Texto vacío")

    # Preferir modelo externo (GEMINI) si está configurado, manteniendo el fallback local. :contentReference[oaicite:9]{index=9}
    if settings.GEMINI_API_KEY and settings.GEMINI_API_URL:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                payload = {"prompt": f"Analiza este texto y responde JSON con fields verdict (Seguro/Sospechoso/Phishing) and percentage (0-100) and reasons list:\n\n{ text }",
                           "max_tokens": 400}
                headers = {"Authorization": f"Bearer {settings.GEMINI_API_KEY}", "Content-Type": "application/json"}
                r = await client.post(settings.GEMINI_API_URL, json=payload, headers=headers)
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except Exception:
                        data = None
                    if isinstance(data, dict) and ("verdict" in data or "percentage" in data):
                        combined = data.get("verdict", "Sospechoso")
                        percentage = int(data.get("percentage", 0))
                        url_results = data.get("url_results", []) if isinstance(data.get("url_results", []), list) else []
                        entry = {"username": username, "type": "texto", "input": text,
                                 "verdict": combined, "percentage": percentage,
                                 "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                        add_history_db(entry)
                        return {"combined_verdict": combined, "percentage": percentage,
                                "url_results": url_results, "reasons": data.get("reasons", [])}
                    # Parseo textual como en tu monolito. :contentReference[oaicite:10]{index=10}
                    text_resp = r.text
                    m_pct = re.search(r"(\d{1,3})\s*%", text_resp)
                    pct = int(m_pct.group(1)) if m_pct else 0
                    if "phish" in text_resp.lower() or "malicious" in text_resp.lower():
                        combined = "Phishing"
                    elif "sospech" in text_resp.lower() or "suspicious" in text_resp.lower():
                        combined = "Sospechoso"
                    else:
                        combined = "Seguro"
                    entry = {"username": username, "type": "texto", "input": text,
                             "verdict": combined, "percentage": pct,
                             "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    add_history_db(entry)
                    return {"combined_verdict": combined, "percentage": pct, "url_results": [], "reasons": [text_resp[:400]]}
                else:
                    logging.warning(f"External text API returned status {r.status_code}, falling back to local heuristics")
        except Exception as e:
            logging.warning(f"Error calling external text API, falling back to local heuristics: {e}")

    # Fallback local (idéntico a tu lógica). :contentReference[oaicite:11]{index=11}
    analysis = score_text(text)
    entry = {"username": username, "type": "texto", "input": text,
             "verdict": analysis["verdict"], "percentage": analysis["percentage"],
             "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    add_history_db(entry)
    return {"combined_verdict": analysis["verdict"], "percentage": analysis["percentage"],
            "url_results": [{"url": u["url"], "verdict": u["verdict"], "reason": u["reason"]}
                            for u in analysis["url_results"]],
            "reasons": analysis["reasons"]}

@router.post("/analyze_url")
async def analyze_url(request: AnalyzeUrlRequest, username: str = Depends(get_current_username)):
    url = (request.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL vacía")

    try:
        res = await check_url_google_safe_browsing(url)
        verdict = res.get("verdict", "Desconocido")
        reason = res.get("reason", "")
    except RuntimeError:
        # Fallback a heurística local si falta API key (igual que tu monolito). :contentReference[oaicite:12]{index=12}
        info = score_url(url); verdict = info["verdict"]; reason = info["reason"]
    except Exception:
        info = score_url(url); verdict = info["verdict"]; reason = info["reason"]

    entry = {"username": username, "type": "url", "input": url,
             "verdict": verdict, "percentage": None,
             "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    add_history_db(entry)
    return {"verdict": verdict, "reason": reason}
