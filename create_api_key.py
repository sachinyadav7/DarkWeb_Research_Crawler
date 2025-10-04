# create_api_key.py
import sqlite3
import secrets
import hashlib
import argparse
from config import DATABASE_URL

def db_connect_sqlite(path='research_data.db'):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def hash_key(plain_key: str) -> str:
    return hashlib.sha256(plain_key.encode('utf-8')).hexdigest()

def create_api_key(name: str, rate_limit_per_min: int, db_path='research_data.db'):
    plain = secrets.token_urlsafe(32)  # secure random key
    hashed = hash_key(plain)
    conn = db_connect_sqlite(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO api_keys (name, hashed_key, rate_limit_per_min, active) VALUES (?, ?, ?, 1)",
        (name, hashed, rate_limit_per_min)
    )
    conn.commit()
    conn.close()
    return plain

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create an API key and save hashed version into DB.")
    parser.add_argument("--name", "-n", required=True, help="Name for the API key (e.g., 'dashboard-service')")
    parser.add_argument("--limit", "-l", type=int, default=60, help="Rate limit per minute")
    parser.add_argument("--db", default="research_data.db", help="Path to sqlite DB")
    args = parser.parse_args()

    key = create_api_key(args.name, args.limit, db_path=args.db)
    print("API key created. SAVE THIS KEY NOW (it will not be shown again):\n")
    print(key)
    print("\nStore it safely. Use it in X-Api-Key header or Authorization: Bearer <key>.")
