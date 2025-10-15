"""
Cliente sencillo para llamar a una API tipo "Gemini" (u otro LLM que acepte POST JSON)
- Provee funciones asíncronas `analyze_text` y `analyze_url`.
- Lee las variables de entorno GEMINI_API_KEY y GEMINI_API_URL por defecto.
- Normaliza la respuesta a un diccionario con claves: verdict, percentage, reasons, url_results, raw

Este módulo es intencionalmente genérico: cada proveedor tiene su propio schema de request/response;
este cliente intenta parsear JSON si lo recibe, y si no, extrae un porcentaje/veredicto básico del texto devuelto.

Uso:
    from gemini_client import analyze_text
    info = await analyze_text("texto a analizar")

"""
from __future__ import annotations

import os
import re
import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)


async def _post_to_gemini(prompt: str, gemini_key: str, gemini_url: str, max_tokens: int = 400, timeout: float = 15.0) -> httpx.Response:
    headers = {"Authorization": f"Bearer {gemini_key}", "Content-Type": "application/json"}
    payload = {"prompt": prompt, "max_tokens": max_tokens}
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(gemini_url, json=payload, headers=headers)
        return r


def _parse_provider_text_response(text_resp: str) -> Dict[str, Any]:
    """Intenta extraer un porcentaje y un veredicto heurísticamente de una respuesta textual del proveedor."""
    # Buscar un porcentaje en la respuesta
    m_pct = re.search(r"(\d{1,3})\s*%", text_resp)
    pct = int(m_pct.group(1)) if m_pct else 0
    lower = text_resp.lower()
    if "phish" in lower or "malicious" in lower or "malicioso" in lower:
        verdict = "Phishing"
    elif "sospech" in lower or "suspicious" in lower:
        verdict = "Sospechoso"
    elif pct >= 66:
        verdict = "Phishing"
    elif pct > 33:
        verdict = "Sospechoso"
    else:
        verdict = "Seguro"
    # Devuelve también el texto recortado como reason
    reasons = [text_resp.strip()[:800]] if text_resp else []
    return {"verdict": verdict, "percentage": pct, "reasons": reasons, "url_results": [], "raw": text_resp}


async def analyze_text(text: str, gemini_key: Optional[str] = None, gemini_url: Optional[str] = None, max_tokens: int = 400, timeout: float = 15.0) -> Dict[str, Any]:
    """Analiza un texto usando la API de Gemini (o similar).

    Retorna un diccionario con al menos: verdict, percentage, reasons, url_results, raw
    Lanza RuntimeError si no está configurada la API (si no se pasan gemini_key/url). Si la llamada falla devuelve excepción httpx o RuntimeError.
    """
    gemini_key = gemini_key or os.getenv("GEMINI_API_KEY")
    gemini_url = gemini_url or os.getenv("GEMINI_API_URL")
    if not gemini_key or not gemini_url:
        raise RuntimeError("Gemini API not configured (set GEMINI_API_KEY and GEMINI_API_URL)")

    prompt = (
        "Analiza este texto y responde estrictamente en JSON con los campos: verdict (Seguro/Sospechoso/Phishing), "
        "percentage (0-100) y reasons (lista de razones cortas). Además, si detectas URLs dentro del texto, "
        "incluye url_results como lista de objetos {url, verdict, reason}.\n\nTexto:\n" + text
    )

    try:
        resp = await _post_to_gemini(prompt, gemini_key, gemini_url, max_tokens=max_tokens, timeout=timeout)
    except Exception as e:
        logger.exception("Error calling Gemini-like API")
        raise

    # Intentar parsear JSON primero
    content_type = resp.headers.get("content-type", "")
    body_text = resp.text
    if "application/json" in content_type:
        try:
            data = resp.json()
            # Normalizar respuesta
            verdict = data.get("verdict") or data.get("label") or data.get("resultado")
            percentage = None
            if "percentage" in data:
                try:
                    percentage = int(data.get("percentage") or 0)
                except Exception:
                    percentage = 0
            reasons = data.get("reasons") if isinstance(data.get("reasons"), list) else ([data.get("reason")] if data.get("reason") else [])
            url_results = data.get("url_results") if isinstance(data.get("url_results"), list) else []
            return {"verdict": verdict or "Sospechoso", "percentage": percentage if percentage is not None else 0, "reasons": reasons or [], "url_results": url_results or [], "raw": data}
        except Exception:
            # Caer back al parseo de texto
            logger.debug("Provider returned JSON content-type but parsing failed, falling back to textual parsing")

    # Si no es JSON, intentar extraer de la respuesta textual
    return _parse_provider_text_response(body_text)


async def analyze_url(url: str, gemini_key: Optional[str] = None, gemini_url: Optional[str] = None, max_tokens: int = 200, timeout: float = 10.0) -> Dict[str, Any]:
    """Usa Gemini para analizar una URL con un prompt orientado. Misma forma de retorno que analyze_text."""
    gemini_key = gemini_key or os.getenv("GEMINI_API_KEY")
    gemini_url = gemini_url or os.getenv("GEMINI_API_URL")
    if not gemini_key or not gemini_url:
        raise RuntimeError("Gemini API not configured (set GEMINI_API_KEY and GEMINI_API_URL)")

    prompt = (
        "Analiza esta URL y responde estrictamente en JSON con campos: verdict (Segura/Sospechosa/Maliciosa), reason, score (0-100).\n\nURL:\n"
        + url
    )
    try:
        resp = await _post_to_gemini(prompt, gemini_key, gemini_url, max_tokens=max_tokens, timeout=timeout)
    except Exception:
        logger.exception("Error calling Gemini-like API for URL")
        raise

    content_type = resp.headers.get("content-type", "")
    body_text = resp.text
    if "application/json" in content_type:
        try:
            data = resp.json()
            verdict = data.get("verdict") or data.get("label") or "Desconocido"
            reason = data.get("reason") or data.get("reasons") or ""
            score = data.get("score") or data.get("percentage") or 0
            try:
                score = int(score)
            except Exception:
                score = 0
            return {"verdict": verdict, "reason": reason, "score": score, "raw": data}
        except Exception:
            logger.debug("Provider returned JSON content-type but parsing failed for URL")

    # Si no es JSON, parsear heurísticamente el texto
    m_pct = re.search(r"(\d{1,3})\s*%", body_text)
    pct = int(m_pct.group(1)) if m_pct else 0
    lower = body_text.lower()
    if "malicious" in lower or "malicioso" in lower or "phish" in lower:
        verdict = "Maliciosa"
    elif "sospech" in lower or "suspicious" in lower:
        verdict = "Sospechosa"
    else:
        verdict = "Segura"
    return {"verdict": verdict, "reason": body_text.strip()[:800], "score": pct, "raw": body_text}


__all__ = ["analyze_text", "analyze_url"]
