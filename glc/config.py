"""Loads channels.yaml and policy.yaml. Resolves user-config directory.

The default config lives in `~/.glc/`. Override with GLC_CONFIG_DIR for
tests and CI. The directory is created on import if missing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import yaml

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CONFIG_DIR = Path(os.getenv("GLC_CONFIG_DIR", str(DEFAULT_DIR)))
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Packaged defaults shipped with glc (under the policy/ subpackage).
PACKAGED_POLICY = Path(__file__).parent / "policy" / "policy.yaml"
PACKAGED_CHANNELS = Path(__file__).parent / "channels.yaml"


def policy_yaml_path() -> Path:
    user = CONFIG_DIR / "policy.yaml"
    return user if user.exists() else PACKAGED_POLICY


def channels_yaml_path() -> Path:
    user = CONFIG_DIR / "channels.yaml"
    return user if user.exists() else PACKAGED_CHANNELS


def load_channels() -> dict:
    p = channels_yaml_path()
    if not p.exists():
        return {"channels": {}}
    return yaml.safe_load(p.read_text()) or {"channels": {}}


def install_token_path() -> Path:
    return CONFIG_DIR / "install_token"


def get_or_create_install_token() -> str:
    """Per-installation token used to authenticate WS adapter connections
    and /v1/control/* requests. Generated once and persisted to disk."""
    env_tok = os.getenv("GLC_INSTALL_TOKEN")
    if env_tok:
        return env_tok.strip()

    p = install_token_path()
    if p.exists():
        return p.read_text().strip()
    import secrets

    tok = secrets.token_urlsafe(32)
    p.write_text(tok)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return tok


def get_scoped_token(name: str) -> str:
    """Derive a cryptographically secure token for a specific channel name
    by hashing the master installation token combined with the channel name."""

    master = get_or_create_install_token()
    return hmac.new(master.encode(), name.encode(), hashlib.sha256).hexdigest()


def generate_tool_call_token(tool_call_id: str, tool_name: str, ttl_seconds: int = 60) -> str:
    """Generate a stateless, signed tool call token (similar to a JWT)."""

    master = get_or_create_install_token()
    payload = {"id": tool_call_id, "name": tool_name, "exp": int(time.time()) + ttl_seconds}
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(master.encode(), payload_b64.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"tc.{payload_b64}.{sig_b64}"


def verify_tool_call_token(token_str: str) -> dict | None:
    """Verify a signed tool call token and return the payload if valid."""

    if not token_str.startswith("tc."):
        return None
    parts = token_str.split(".")
    if len(parts) != 3:
        return None
    _, payload_b64, sig_b64 = parts

    def decode_b64url(s: str) -> bytes:
        padding = 4 - (len(s) % 4)
        if padding < 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s.encode())

    try:
        payload_bytes = decode_b64url(payload_b64)
        sig_bytes = decode_b64url(sig_b64)
        payload = json.loads(payload_bytes.decode())
    except Exception:
        return None

    if payload.get("exp", 0) < time.time():
        return None

    master = get_or_create_install_token()
    expected_sig = hmac.new(master.encode(), payload_b64.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(sig_bytes, expected_sig):
        return None
    return payload
