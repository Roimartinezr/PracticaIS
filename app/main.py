import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from .db.database import init_db, migrate_json_history, ensure_db_schema
from .api.routes.auth import router as auth_router
from .api.routes.analyze import router as analyze_router
from .api.routes.history import router as history_router
from .api.routes.stats import router as stats_router

app = FastAPI(title="PhishGuard AI - Dev Server")

# CORS abierto para dev (ajusta en prod)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# Inicialización DB y migraciones idempotentes
init_db()
migrate_json_history()
ensure_db_schema()

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Routers
app.include_router(auth_router)
app.include_router(analyze_router)
app.include_router(history_router)
app.include_router(stats_router)

# Rutas raíz y estáticos "compatibles" con tu monolito
@app.get("/")
async def root():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return JSONResponse({"message": "Index file not found"}, status_code=404)

@app.get("/style.css")
async def css():
    p = os.path.join(STATIC_DIR, "style.css")
    if os.path.exists(p):
        return FileResponse(p, media_type="text/css")
    return JSONResponse({"detail": "style.css not found"}, status_code=404)

@app.get("/script.js")
async def js():
    p = os.path.join(STATIC_DIR, "script.js")
    if os.path.exists(p):
        return FileResponse(p, media_type="application/javascript")
    return JSONResponse({"detail": "script.js not found"}, status_code=404)

@app.get("/favicon.ico")
async def favicon():
    p = os.path.join(STATIC_DIR, "favicon.ico")
    if os.path.exists(p):
        return FileResponse(p, media_type="image/x-icon")
    return JSONResponse({"detail": "favicon not found"}, status_code=404)
