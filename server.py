"""RECK-0 local prototype server.

Accounts use PBKDF2-HMAC-SHA256 password hashes. Auth sessions are signed,
HTTP-only cookies. This is an MVP authentication implementation, not a substitute
for a production identity provider or a security review.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import uuid
import wave
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

BASE_DIR = Path(__file__).resolve().parent

# Load .env file if present (lightweight parser, no extra dependency required)
env_file = BASE_DIR / ".env"
if env_file.is_file():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b")

DB_PATH = Path(os.environ.get("RECK0_DB_PATH", str(BASE_DIR / "reck0.db"))).resolve()
SESSION_SECRET = os.environ.get("RECK0_SESSION_SECRET", "")
if not SESSION_SECRET:
    # A per-install secret is persisted locally for convenience on first run.
    secret_path = BASE_DIR / ".reck0_session_secret"
    try:
        if secret_path.exists():
            SESSION_SECRET = secret_path.read_text().strip()
        else:
            SESSION_SECRET = secrets.token_urlsafe(48)
            secret_path.write_text(SESSION_SECRET)
            try:
                secret_path.chmod(0o600)
            except OSError:
                pass
    except OSError:
        SESSION_SECRET = secrets.token_urlsafe(48)

COOKIE_SECURE = os.environ.get("RECK0_COOKIE_SECURE", "0").strip() == "1"
PBKDF2_ROUNDS = 600_000
MAX_FAILS = 5
LOCK_SECONDS = 15 * 60
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_AUDIO_SECONDS = 30 * 60
UPLOAD_DIR = Path(os.environ.get("RECK0_UPLOAD_DIR", str(BASE_DIR / "evidence_uploads"))).resolve()
failed_logins: dict[str, list[float]] = {}

app = FastAPI(title="RECK-0 Investigator Console", version="0.2.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="reck0_session",
    max_age=8 * 60 * 60,
    same_site="lax",
    https_only=COOKIE_SECURE,
)

class Credentials(BaseModel):
    email: str
    password: str

class Registration(Credentials):
    full_name: str


def connect_db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


@contextmanager
def db_connection():
    con = connect_db()
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_connection() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        con.execute("""CREATE TABLE IF NOT EXISTS audio_evidence (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            duration_seconds REAL NOT NULL,
            sample_rate INTEGER NOT NULL,
            channels INTEGER NOT NULL,
            frames INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_audio_evidence_owner ON audio_evidence(user_id, created_at DESC)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalise_email(email: str) -> str:
    return email.strip().lower()


def valid_email(email: str) -> bool:
    return len(email) <= 254 and bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=32)
    return "pbkdf2_sha256${}${}".format(base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(derived).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, salt_text, hash_text = stored.split("$", 2)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(hash_text.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# Precompute a dummy credential hash once so unknown-email failures still perform
# one PBKDF2 verification rather than a visibly cheaper database-only path.
DUMMY_PASSWORD_HASH = hash_password("constant-time-dummy-password-for-user-enumeration")


def public_user(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "full_name": row["full_name"], "email": row["email"], "created_at": row["created_at"], "role": "investigator"}


def require_session_user(request: Request) -> sqlite3.Row:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Sign in to access this resource.")
    with db_connection() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Session is no longer valid.")
    return row


def ensure_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    parsed = urlparse(origin)
    if parsed.netloc and parsed.netloc.lower() != request.url.netloc.lower():
        raise HTTPException(status_code=403, detail="Cross-origin request rejected.")


def get_client_key(request: Request, email: str) -> str:
    client_ip = request.client.host if request.client else "unknown"
    return f"{client_ip}:{email}"


def check_throttle(key: str) -> None:
    now = time.monotonic()
    attempts = [t for t in failed_logins.get(key, []) if now - t < LOCK_SECONDS]
    failed_logins[key] = attempts
    if len(attempts) >= MAX_FAILS:
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in about 15 minutes.")


def record_failure(key: str) -> None:
    now = time.monotonic()
    failed_logins[key] = [t for t in failed_logins.get(key, []) if now - t < LOCK_SECONDS] + [now]


def clear_failures(key: str) -> None:
    failed_logins.pop(key, None)


init_db()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/auth") else "no-cache"
    return response

@app.get("/")
def index():
    return FileResponse(
        BASE_DIR / "index.html",
        media_type="text/html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    )

@app.get("/health")
def health():
    return {"status": "ok", "service": "reck0", "auth": "enabled"}

@app.post("/api/auth/register")
def register(payload: Registration, request: Request):
    ensure_same_origin(request)
    name = payload.full_name.strip()
    email = normalise_email(payload.email)
    password = payload.password
    if len(name) < 2 or len(name) > 80:
        raise HTTPException(status_code=400, detail="Full name must be between 2 and 80 characters.")
    if not valid_email(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if len(password) < 12 or len(password) > 256:
        raise HTTPException(status_code=400, detail="Password must be between 12 and 256 characters.")
    try:
        with db_connection() as con:
            cur = con.execute(
                "INSERT INTO users(full_name,email,password_hash,created_at) VALUES(?,?,?,?)",
                (name, email, hash_password(password), utc_now()),
            )
            row = con.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        # Avoid disclosing whether an account exists beyond what a signup flow needs.
        raise HTTPException(status_code=409, detail="An account with this email may already exist. Try signing in.")
    request.session.clear()
    request.session["user_id"] = row["id"]
    request.session["issued_at"] = int(time.time())
    return JSONResponse({"user": public_user(row)}, status_code=201)

@app.post("/api/auth/login")
def login(payload: Credentials, request: Request):
    ensure_same_origin(request)
    email = normalise_email(payload.email)
    if not valid_email(email) or not payload.password or len(payload.password) > 256:
        raise HTTPException(status_code=400, detail="Enter a valid email and password (maximum 256 characters).")
    key = get_client_key(request, email)
    check_throttle(key)
    with db_connection() as con:
        row = con.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
    # Run a comparable password derivation for unknown users to reduce timing-based enumeration.
    if row is None:
        verify_password(payload.password, DUMMY_PASSWORD_HASH)
        record_failure(key)
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    if not verify_password(payload.password, row["password_hash"]):
        record_failure(key)
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    clear_failures(key)
    request.session.clear()
    request.session["user_id"] = row["id"]
    request.session["issued_at"] = int(time.time())
    return {"user": public_user(row)}

@app.get("/api/auth/me")
def me(request: Request):
    return {"user": public_user(require_session_user(request))}

@app.post("/api/calls/upload")
async def upload_call_audio(request: Request, file: UploadFile = File(...)):
    """Store an authenticated PCM WAV upload and record its integrity metadata.

    This endpoint does not run transcription or speech-emotion inference.
    """
    user = require_session_user(request)
    original_name = Path(file.filename or "recording.wav").name[:255]
    if Path(original_name).suffix.lower() != ".wav":
        await file.close()
        raise HTTPException(status_code=415, detail="This MVP accepts WAV recordings only.")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    record_id = uuid.uuid4().hex
    stored_filename = f"{record_id}.wav"
    target = UPLOAD_DIR / stored_filename
    digest = hashlib.sha256()
    total = 0

    try:
        with target.open("xb") as dest:
            while True:
                chunk = await file.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Audio file exceeds the 25 MB upload limit.")
                digest.update(chunk)
                dest.write(chunk)
        if total == 0:
            raise HTTPException(status_code=400, detail="The selected audio file is empty.")
        try:
            with wave.open(str(target), "rb") as audio:
                channels = audio.getnchannels()
                sample_rate = audio.getframerate()
                frames = audio.getnframes()
                compression = audio.getcomptype()
                duration = frames / sample_rate if sample_rate else 0.0
                if compression != "NONE":
                    raise HTTPException(status_code=415, detail="Use an uncompressed PCM WAV file for this MVP.")
                if channels < 1 or sample_rate < 1 or frames < 1 or duration <= 0:
                    raise HTTPException(status_code=400, detail="The WAV file has invalid or incomplete audio metadata.")
                if duration > MAX_AUDIO_SECONDS:
                    raise HTTPException(status_code=413, detail="Audio duration exceeds the 30-minute limit.")
        except (wave.Error, EOFError, OSError) as exc:
            raise HTTPException(status_code=400, detail="The file is not a valid readable WAV recording.") from exc

        sha256 = digest.hexdigest()
        with db_connection() as con:
            con.execute(
                """INSERT INTO audio_evidence
                (id,user_id,original_filename,stored_filename,sha256,size_bytes,duration_seconds,sample_rate,channels,frames,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (record_id, user["id"], original_name, stored_filename, sha256, total, round(duration, 3), sample_rate, channels, frames, utc_now()),
            )
        return {
            "call": {
                "id": record_id,
                "filename": original_name,
                "sha256": sha256,
                "size_bytes": total,
                "duration_seconds": round(duration, 3),
                "sample_rate": sample_rate,
                "channels": channels,
                "frames": frames,
                "status": "INGESTED_NOT_ANALYSED",
            }
        }
    except Exception:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        await file.close()

@app.get("/api/calls")
def list_uploaded_calls(request: Request):
    user = require_session_user(request)
    with db_connection() as con:
        rows = con.execute(
            """SELECT id, original_filename, sha256, size_bytes, duration_seconds,
                      sample_rate, channels, frames, created_at
               FROM audio_evidence WHERE user_id=? ORDER BY created_at DESC LIMIT 100""",
            (user["id"],),
        ).fetchall()
    return {"calls": [dict(row) for row in rows]}

@app.get("/api/calls/{call_id}/stream")
def stream_call_audio(call_id: str, request: Request):
    user = require_session_user(request)
    with db_connection() as con:
        row = con.execute(
            "SELECT * FROM audio_evidence WHERE id=? AND user_id=?",
            (call_id, user["id"]),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Recording not found.")
    file_path = UPLOAD_DIR / row["stored_filename"]
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Audio file is missing from local storage.")
    return FileResponse(file_path, media_type="audio/wav", filename=row["original_filename"])

@app.post("/api/auth/logout")
def logout(request: Request):
    ensure_same_origin(request)
    request.session.clear()
    return {"ok": True}
