"""Keep automated tests isolated from a developer's local RECK-0 data."""
import os
import tempfile
from pathlib import Path

_TEST_DIR = Path(tempfile.mkdtemp(prefix="reck0-test-"))
os.environ["RECK0_DB_PATH"] = str(_TEST_DIR / "test.db")
os.environ["RECK0_UPLOAD_DIR"] = str(_TEST_DIR / "uploads")
os.environ["RECK0_SESSION_SECRET"] = "test-only-secret-not-for-real-deployment-329847"
os.environ["RECK0_COOKIE_SECURE"] = "0"
