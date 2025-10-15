# app/api/routes/analyze.py
import datetime
import logging
from fastapi import APIRouter, HTTPException, Depends

from ...models.schemas import AnalyzeRequest, AnalyzeUrlRequest
from ...api.deps import get_current_username
from ...db.repository import add_history_db
from ...core.config import settings

from ...services.scoring import score_text, score_url
from ...services.safe_browsing import check_url_google_safe_browsing
from ...services.gemini_client import analyze_text as gemini_analyze_text, analyze_url as gemini_analyze_url

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze")
async def analyze_text_route(request: AnalyzeRequest, username: str = Depends(get_current_username)):
    """
    Analiza TEXTO:
      1) Intenta Gemini (si está configurado)
      2) Fallback a heurística local
    Registra el resultado en la tabla 'history'.
    """
    text = (request.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Texto vacío")

    verdict: str
    percentage: int
    reasons: list
    url_results: list

    # 1) Intento con Gemini (si hay configuración)
    try:
        result = await gemini_analyze_text(
            text,
            gemini_key=settings.GEMINI_API_KEY,
            gemini_url=settings.GEMINI_API_URL
        )
        verdict = result.get("verdict", "Sospechoso")
        # Normalizamos por si el proveedor devuelve algo no entero
        try:
            percentage = int(result.get("percentage", 0))
        except Exception:
            percentage = 0
        reasons = result.get("reasons", []) or []
        url_results = result.get("url_results", []) or []
    except RuntimeError:
        # Gemini no configurado → heurística local
        local = score_text(text)
        verdict = local["verdict"]
        percentage = int(local["percentage"])
        reasons = local["reasons"]
        url_results = local["url_results"]
    except Exception as e:
        # Error en la llamada a Gemini → heurística local, anotando el error como razón adicional
        logger.warning(f"Error llamando a Gemini analyze_text: {e}")
        local = score_text(text)
        verdict = local["verdict"]
        percentage = int(local["percentage"])
        reasons = [f"Fallback local por error de proveedor: {e}"] + local["reasons"]
        url_results = local["url_results"]

    # Guardar en historial
    entry = {
        "username": username,
        "type": "texto",
        "input": text,
        "verdict": verdict,
        "percentage": percentage,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    add_history_db(entry)

    return {
        "combined_verdict": verdict,
        "percentage": percentage,
        "url_results": [{"url": u.get("url"), "verdict": u.get("verdict"), "reason": u.get("reason")}
                        for u in (url_results or [])],
        "reasons": reasons,
    }


@router.post("/analyze_url")
async def analyze_url_route(request: AnalyzeUrlRequest, username: str = Depends(get_current_username)):
    """
    Analiza una URL:
      1) Intenta Gemini (si está configurado) para un veredicto rápido
      2) Si falla o no está, intenta Google Safe Browsing
      3) Fallback final: heurística local de URL
    Registra el resultado en la tabla 'history' (percentage=None para URLs).
    """
    url = (request.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL vacía")

    verdict: str | None = None
    reason: str = ""

    # 1) Intento con Gemini (si hay configuración)
    tried_gemini = False
    if settings.GEMINI_API_KEY and settings.GEMINI_API_URL:
        tried_gemini = True
        try:
            g = await gemini_analyze_url(
                url,
                gemini_key=settings.GEMINI_API_KEY,
                gemini_url=settings.GEMINI_API_URL
            )
            verdict = g.get("verdict") or None
            # 'reason' puede venir como str o list (normalizamos a str corto)
            r = g.get("reason", "")
            reason = r if isinstance(r, str) else ", ".join(map(str, r)) if isinstance(r, list) else ""
        except Exception as e:
            logger.warning(f"Error llamando a Gemini analyze_url: {e}")

    # 2) Si no tenemos veredicto todavía, intentar Google Safe Browsing
    if verdict is None:
        try:
            gsb = await check_url_google_safe_browsing(url)
            verdict = gsb.get("verdict", "Desconocido")
            reason = gsb.get("reason", "") or reason
        except RuntimeError:
            # API key no configurada: saltar a heurística
            pass
        except Exception as e:
            logger.warning(f"Error llamando a Google Safe Browsing: {e}")

    # 3) Fallback final: heurística local de URL
    if verdict is None:
        local = score_url(url)
        verdict = local["verdict"]
        if not reason:
            reason = local["reason"]

    # Guardar en historial (percentage=None para entradas de tipo URL)
    entry = {
        "username": username,
        "type": "url",
        "input": url,
        "verdict": verdict,
        "percentage": None,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    add_history_db(entry)

    # Respuesta homogénea
    return {
        "verdict": verdict,
        "reason": reason,
        # Metadatos útiles para depurar en dev (no sensibles)
        "provider_tried": {
            "gemini": tried_gemini,
            "google_safe_browsing": settings.GOOGLE_SAFE_BROWSING_API_KEY is not None
        }
    }
