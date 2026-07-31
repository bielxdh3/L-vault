from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from .config import paths
from .utils import atomic_write_text

AUTH_FILE = "auth.json"
SCRYPT_N = 2**14
SESSION_MAX_AGE = 8 * 60 * 60


def auth_path(root: Path) -> Path:
    return paths(root).config / AUTH_FILE


def load_auth(root: Path) -> dict[str, str] | None:
    try:
        data = json.loads(auth_path(root).read_text(encoding="utf-8"))
        if isinstance(data, dict) and {"salt", "password_hash", "session_secret", "session_version"} <= data.keys():
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return None


def set_password(root: Path, password: str) -> None:
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = secrets.token_bytes(16)
    record = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(_derive(password, salt)).decode("ascii"),
        "session_secret": secrets.token_urlsafe(48),
        "session_version": secrets.token_urlsafe(24),
    }
    target = auth_path(root)
    atomic_write_text(target, json.dumps(record, indent=2), encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def verify_password(record: dict[str, str] | None, password: str) -> bool:
    if not record:
        return False
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["password_hash"], validate=True)
    except (KeyError, ValueError):
        return False
    return hmac.compare_digest(_derive(password, salt), expected)


def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=8, p=1, dklen=32)
