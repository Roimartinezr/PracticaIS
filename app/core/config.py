import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    GEMINI_API_KEY: str | None = os.getenv("GEMINI_API_KEY")
    GEMINI_API_URL: str | None = os.getenv("GEMINI_API_URL")

    # rutas
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    PROJECT_ROOT = os.path.dirname(BASE_DIR)
    DATA_DIR = os.path.join(PROJECT_ROOT, "data")
    DB_FILE = os.path.join(DATA_DIR, "app.db")
    LEGACY_HISTORY_JSON = os.path.join(DATA_DIR, "history.json")

settings = Settings()
