from __future__ import annotations

import hashlib
import io
import uuid
import wave

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture
def client():
    with TestClient(server.app) as test_client:
        yield test_client


def fresh_email() -> str:
    return f"investigator-{uuid.uuid4().hex[:12]}@example.test"


def create_account(client: TestClient) -> tuple[str, str]:
    email = fresh_email()
    password = "A-long-test-passphrase-2026!"
    response = client.post(
        "/api/auth/register",
        json={"full_name": "Test Investigator", "email": email, "password": password},
    )
    assert response.status_code == 201
    return email, password


def make_wav() -> bytes:
    data = io.BytesIO()
    with wave.open(data, "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(8000)
        audio.writeframes(b"\x00\x00" * 8000)  # one second of silent PCM audio
    return data.getvalue()


def test_home_health_and_horizontal_nav(client: TestClient) -> None:
    home = client.get("/")
    assert home.status_code == 200
    assert "RECK-0" in home.text
    assert "floating-nav" in home.text
    assert "Create account" in home.text
    assert "Local demo environment" not in home.text

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"


def test_registration_creates_authenticated_session(client: TestClient) -> None:
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test Investigator",
            "email": fresh_email(),
            "password": "A-long-test-passphrase-2026!",
        },
    )
    assert response.status_code == 201
    assert response.json()["user"]["role"] == "investigator"
    assert "reck0_session" in response.headers.get("set-cookie", "")

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["full_name"] == "Test Investigator"


def test_login_logout_and_wrong_password(client: TestClient) -> None:
    email, password = create_account(client)
    client.post("/api/auth/logout")

    bad = client.post("/api/auth/login", json={"email": email, "password": "wrong-passphrase-123"})
    assert bad.status_code == 401

    good = client.post("/api/auth/login", json={"email": email, "password": password})
    assert good.status_code == 200
    assert good.json()["user"]["email"] == email

    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_upload_requires_login(client: TestClient) -> None:
    response = client.post("/api/calls/upload", files={"file": ("sample.wav", make_wav(), "audio/wav")})
    assert response.status_code == 401


def test_wav_upload_is_stored_and_hashed(client: TestClient) -> None:
    create_account(client)
    wav_bytes = make_wav()
    response = client.post("/api/calls/upload", files={"file": ("call sample.wav", wav_bytes, "audio/wav")})
    assert response.status_code == 200
    call = response.json()["call"]
    assert call["filename"] == "call sample.wav"
    assert call["sha256"] == hashlib.sha256(wav_bytes).hexdigest()
    assert call["duration_seconds"] == 1.0
    assert call["sample_rate"] == 8000
    assert call["channels"] == 1
    assert call["status"] == "INGESTED_NOT_ANALYSED"

    listed = client.get("/api/calls")
    assert listed.status_code == 200
    assert len(listed.json()["calls"]) == 1
    assert listed.json()["calls"][0]["sha256"] == call["sha256"]


def test_non_wav_upload_is_rejected(client: TestClient) -> None:
    create_account(client)
    response = client.post("/api/calls/upload", files={"file": ("call.mp3", b"not really audio", "audio/mpeg")})
    assert response.status_code == 415
