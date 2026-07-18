"""DM pairing flow.

A rotating six-digit code is issued per pairing request and expires after
five minutes. The owner enters the code through the WebUI to confirm.
Per-pairing trust levels live in ~/.glc/pairings.sqlite: owner_paired for
the installation owner, user_paired for explicitly-paired users.

The pairing store is sqlite-backed so it survives restarts.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from glc.config import get_or_create_install_token
import hmac
import hashlib

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CODE_TTL_SECONDS = 5 * 60


def _resolve_path() -> str:
    return os.getenv("GLC_PAIRING_DB", str(DEFAULT_DIR / "pairings.sqlite"))


def _calculate_signature(channel: str, channel_user_id: str, trust_level: str, paired_at: float) -> str:
    master = get_or_create_install_token()
    payload = f"{channel}|{channel_user_id}|{trust_level}|{paired_at}"
    return hmac.new(master.encode(), payload.encode(), hashlib.sha256).hexdigest()



@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


@dataclass
class PairingRecord:
    channel: str
    channel_user_id: str
    user_handle: str
    trust_level: str
    paired_at: float


class PairingStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with _conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS pairings (
                    channel TEXT NOT NULL,
                    channel_user_id TEXT NOT NULL,
                    user_handle TEXT,
                    trust_level TEXT NOT NULL,
                    paired_at REAL NOT NULL,
                    signature TEXT,
                    PRIMARY KEY (channel, channel_user_id)
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS pending_codes (
                    code TEXT PRIMARY KEY,
                    channel TEXT NOT NULL,
                    channel_user_id TEXT NOT NULL,
                    user_handle TEXT,
                    requested_trust_level TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )
            # Migration check: if signature column is missing:
            row = c.execute("PRAGMA table_info(pairings)").fetchall()
            cols = [r["name"] for r in row]
            if "signature" not in cols:
                c.execute("ALTER TABLE pairings ADD COLUMN signature TEXT")

            # Retroactively sign any unsigned pairings:
            unsigned = c.execute("SELECT * FROM pairings WHERE signature IS NULL").fetchall()
            for r in unsigned:
                sig = _calculate_signature(r["channel"], r["channel_user_id"], r["trust_level"], float(r["paired_at"]))
                c.execute(
                    "UPDATE pairings SET signature = ? WHERE channel = ? AND channel_user_id = ?",
                    (sig, r["channel"], r["channel_user_id"])
                )

    def issue_code(
        self,
        channel: str,
        channel_user_id: str,
        user_handle: str = "",
        *,
        requested_trust_level: str = "user_paired",
    ) -> tuple[str, float]:
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires_at = time.time() + CODE_TTL_SECONDS
        with _conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO pending_codes
                   (code, channel, channel_user_id, user_handle,
                    requested_trust_level, expires_at) VALUES (?,?,?,?,?,?)""",
                (code, channel, channel_user_id, user_handle, requested_trust_level, expires_at),
            )
        return code, expires_at

    def confirm_code(self, code: str) -> PairingRecord | None:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM pending_codes WHERE code=?",
                (code,),
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] < time.time():
                c.execute("DELETE FROM pending_codes WHERE code=?", (code,))
                return None
            paired_at = time.time()
            sig = _calculate_signature(row["channel"], row["channel_user_id"], row["requested_trust_level"], paired_at)
            c.execute(
                """INSERT OR REPLACE INTO pairings
                   (channel, channel_user_id, user_handle, trust_level, paired_at, signature)
                   VALUES (?,?,?,?,?,?)""",
                (
                    row["channel"],
                    row["channel_user_id"],
                    row["user_handle"],
                    row["requested_trust_level"],
                    paired_at,
                    sig,
                ),
            )
            c.execute("DELETE FROM pending_codes WHERE code=?", (code,))
            return PairingRecord(
                channel=row["channel"],
                channel_user_id=row["channel_user_id"],
                user_handle=row["user_handle"] or "",
                trust_level=row["requested_trust_level"],
                paired_at=paired_at,
            )

    def lookup(self, channel: str, channel_user_id: str) -> PairingRecord | None:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM pairings WHERE channel=? AND channel_user_id=?",
                (channel, channel_user_id),
            ).fetchone()
            if row is None:
                return None
            expected = _calculate_signature(row["channel"], row["channel_user_id"], row["trust_level"], float(row["paired_at"]))
            stored = row["signature"]
            if not stored or not hmac.compare_digest(stored, expected):
                return None
            return PairingRecord(
                channel=row["channel"],
                channel_user_id=row["channel_user_id"],
                user_handle=row["user_handle"] or "",
                trust_level=row["trust_level"],
                paired_at=float(row["paired_at"]),
            )

    def owners(self, channel: str | None = None) -> list[PairingRecord]:
        q = "SELECT * FROM pairings WHERE trust_level='owner_paired'"
        args: list = []
        if channel:
            q += " AND channel=?"
            args.append(channel)
        with _conn() as c:
            res = []
            for r in c.execute(q, args).fetchall():
                expected = _calculate_signature(r["channel"], r["channel_user_id"], r["trust_level"], float(r["paired_at"]))
                stored = r["signature"]
                if stored and hmac.compare_digest(stored, expected):
                    res.append(
                        PairingRecord(
                            channel=r["channel"],
                            channel_user_id=r["channel_user_id"],
                            user_handle=r["user_handle"] or "",
                            trust_level=r["trust_level"],
                            paired_at=float(r["paired_at"]),
                        )
                    )
            return res

    def all_pairings(self) -> list[PairingRecord]:
        import hmac
        with _conn() as c:
            rows = c.execute("SELECT * FROM pairings").fetchall()
            res = []
            for r in rows:
                expected = _calculate_signature(r["channel"], r["channel_user_id"], r["trust_level"], float(r["paired_at"]))
                stored = r["signature"]
                if stored and hmac.compare_digest(stored, expected):
                    res.append(
                        PairingRecord(
                            channel=r["channel"],
                            channel_user_id=r["channel_user_id"],
                            user_handle=r["user_handle"] or "",
                            trust_level=r["trust_level"],
                            paired_at=float(r["paired_at"]),
                        )
                    )
            return res

    def revoke(self, channel: str, channel_user_id: str) -> bool:
        with _conn() as c:
            cur = c.execute(
                "DELETE FROM pairings WHERE channel=? AND channel_user_id=?",
                (channel, channel_user_id),
            )
            return cur.rowcount > 0

    def force_pair_owner(
        self, channel: str, channel_user_id: str, user_handle: str = "owner"
    ) -> PairingRecord:
        """Out-of-band pairing for the installation owner. Used by the
        installer to bootstrap the first owner identity. Not exposed
        through HTTP."""
        paired_at = time.time()
        sig = _calculate_signature(channel, channel_user_id, "owner_paired", paired_at)
        with _conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO pairings
                   (channel, channel_user_id, user_handle, trust_level, paired_at, signature)
                   VALUES (?,?,?,?,?,?)""",
                (channel, channel_user_id, user_handle, "owner_paired", paired_at, sig),
            )
        return PairingRecord(
            channel=channel,
            channel_user_id=channel_user_id,
            user_handle=user_handle,
            trust_level="owner_paired",
            paired_at=paired_at,
        )


_singleton: PairingStore | None = None


def get_pairing_store() -> PairingStore:
    global _singleton
    if _singleton is None:
        _singleton = PairingStore()
    return _singleton
