import base64
import hashlib
import hmac
import os
import secrets
import time

from fastapi import HTTPException, Request

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
SESSION_COOKIE_NAME = "sentinelops_session"
SESSION_TTL_SECONDS = 3600
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").strip().lower() not in {
    "0",
    "false",
    "no",
}


def auth_is_configured() -> bool:
    return len(ADMIN_PASSWORD) >= 16 and len(SESSION_SECRET.encode("utf-8")) >= 32


def verify_admin_password(password: str) -> bool:
    return hmac.compare_digest(password, ADMIN_PASSWORD)


def create_session_token() -> str:
    payload = f"{int(time.time()) + SESSION_TTL_SECONDS}:{secrets.token_urlsafe(24)}"
    encoded_payload = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{encoded_payload}.{signature}"


def has_admin_session(request: Request) -> bool:
    if not auth_is_configured():
        return False

    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    try:
        encoded_payload, supplied_signature = token.rsplit(".", 1)
        expected_signature = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return False

        padded_payload = encoded_payload + "=" * (-len(encoded_payload) % 4)
        payload = base64.urlsafe_b64decode(padded_payload).decode("utf-8")
        expires_at, nonce = payload.split(":", 1)
        return bool(nonce) and int(expires_at) > int(time.time())
    except (ValueError, UnicodeError):
        return False


def require_admin(request: Request) -> None:
    if not auth_is_configured():
        raise HTTPException(status_code=503, detail="Admin authentication is not configured")
    if not has_admin_session(request):
        raise HTTPException(status_code=401, detail="Admin login required")
