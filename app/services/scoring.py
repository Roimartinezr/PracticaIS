import re
from typing import List, Dict, Any

# Misma heurística que tu server.py para ser 100% compatible. :contentReference[oaicite:7]{index=7}
def extract_urls(text: str) -> List[str]:
    pattern = r"https?://[\w\-\.\/~:?&=#%+\[\]]+"
    return re.findall(pattern, text)

def score_url(url: str) -> Dict[str, Any]:
    score = 0; reasons = []
    if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", url):
        score += 30; reasons.append("Uso de dirección IP en URL")
    if len(url) > 75:
        score += 15; reasons.append("URL muy larga")
    if url.count("-") > 2 or re.search(r"[<>]", url):
        score += 10; reasons.append("Sintaxis sospechosa")
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    if any(url.lower().endswith(t) for t in suspicious_tlds):
        score += 20; reasons.append("TLD con reputación débil")
    suspicious_words = ["login", "verify", "secure", "update", "confirm", "account", "bank"]
    if any(w in url.lower() for w in suspicious_words):
        score += 18; reasons.append("Palabras asociadas a phishing en la URL")
    score = max(0, min(100, score))
    verdict = "Maliciosa" if score > 60 else "Sospechosa" if score > 30 else "Segura"
    reason = ", ".join(reasons) if reasons else "Sin señales fuertes"
    return {"url": url, "score": score, "verdict": verdict, "reason": reason}

def score_text(text: str) -> Dict[str, Any]:
    score = 0; reasons = []
    keywords_high = ["transferir", "verifique", "verificar", "bloqueada", "urgente",
                     "inmediatamente", "confirmar", "credenciales", "contraseña", "pago"]
    keywords_medium = ["problema", "alerta", "suscrito", "ganó", "felicitaciones"]

    low_count = sum(1 for w in keywords_medium if w in text.lower())
    mid_count = sum(1 for w in keywords_high if w in text.lower())
    score += mid_count * 18
    score += low_count * 8

    urls = extract_urls(text)
    if urls:
        for u in urls:
            url_info = score_url(u)
            score += url_info["score"] * 0.6
            reasons.append(f"URL detectada: {u} ({url_info['verdict']})")

    if re.search(r"[A-Z]{5,}", text):
        score += 8; reasons.append("Texto en mayúsculas — tono alarmista")
    if text.count("!") >= 2:
        score += 6; reasons.append("Uso excesivo de signos de exclamación")

    score = int(max(0, min(100, score)))
    verdict = "Phishing" if score > 66 else "Sospechoso" if score > 33 else "Seguro"
    return {"percentage": score, "verdict": verdict, "reasons": reasons,
            "url_results": [score_url(u) for u in urls]}
