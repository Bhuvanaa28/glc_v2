"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
import hashlib

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())
        # Dynamic check if hash column is missing
        row = c.execute("PRAGMA table_info(audit_log)").fetchall()
        cols = [r["name"] for r in row]
        if "hash" not in cols:
            c.execute("ALTER TABLE audit_log ADD COLUMN hash TEXT")

        # Chain any existing rows that do not have a hash value populated
        unhashed = c.execute("SELECT * FROM audit_log WHERE hash IS NULL ORDER BY id ASC").fetchall()
        if unhashed:
            import hashlib
            for row in unhashed:
                id_ = row["id"]
                ts = row["ts"]
                session_id = row["session_id"]
                channel = row["channel"]
                channel_user_id = row["channel_user_id"]
                trust_level = row["trust_level"]
                event_type = row["event_type"]
                tool = row["tool"]
                policy_verdict = row["policy_verdict"]
                params_json = row["params_json"]
                result_json = row["result_json"]

                prev_row = c.execute("SELECT hash FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT 1", (id_,)).fetchone()
                prev_hash = prev_row["hash"] if (prev_row and prev_row["hash"]) else ""

                payload = f"{ts}|{session_id or ''}|{channel}|{channel_user_id}|{trust_level}|{event_type}|{tool or ''}|{policy_verdict or ''}|{params_json or ''}|{result_json or ''}|{prev_hash}"
                expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                c.execute("UPDATE audit_log SET hash = ? WHERE id = ?", (expected_hash, id_))


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        with _conn() as c:
            # 1. Fetch previous hash
            prev_row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = prev_row["hash"] if (prev_row and prev_row["hash"]) else ""

            # 2. Prepare content
            ts = time.time()
            params_json = _jsonify(params)
            result_json = _jsonify(result)

            # 3. Calculate chain hash
            payload = f"{ts}|{session_id or ''}|{channel}|{channel_user_id}|{trust_level}|{event_type}|{tool or ''}|{policy_verdict or ''}|{params_json or ''}|{result_json or ''}|{prev_hash}"
            entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            # 4. Insert row
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json, hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts,
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    params_json,
                    result_json,
                    entry_hash,
                ),
            )
            return int(cur.lastrowid or 0)


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def verify_chain() -> bool:
    """Verify that all entries in the audit log form a valid, untampered cryptographic hash chain."""
    with _conn() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        prev_hash = ""
        for row in rows:
            ts = row["ts"]
            session_id = row["session_id"]
            channel = row["channel"]
            channel_user_id = row["channel_user_id"]
            trust_level = row["trust_level"]
            event_type = row["event_type"]
            tool = row["tool"]
            policy_verdict = row["policy_verdict"]
            params_json = row["params_json"]
            result_json = row["result_json"]
            stored_hash = row["hash"]

            payload = f"{ts}|{session_id or ''}|{channel}|{channel_user_id}|{trust_level}|{event_type}|{tool or ''}|{policy_verdict or ''}|{params_json or ''}|{result_json or ''}|{prev_hash}"
            expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            if not stored_hash or stored_hash != expected_hash:
                return False
            prev_hash = stored_hash
    return True


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)
