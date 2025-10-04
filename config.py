# config.py
import os

# Flask config
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"

# Database (SQLite by default)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./research_data.db")

# Redis for rate limiting (optional but recommended)
REDIS_URL = os.getenv("REDIS_URL", None)  # e.g. "redis://localhost:6379/0"

# API auth config
API_KEY_HEADER = "X-Api-Key"  # or Authorization: Bearer <key>
DEFAULT_RATE_LIMIT_PER_MIN = int(os.getenv("DEFAULT_RATE_LIMIT_PER_MIN", "60"))

# Security note: set SECRET_KEY in env for session handling if needed
SECRET_KEY = os.getenv("SECRET_KEY", "replace-with-secure-secret")
