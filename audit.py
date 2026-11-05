"""The audit trail: who did what, when, and whether it was allowed.

Every row stores the hash of the row before it (a chain). If anyone changes
or removes an old row, verify_chain() finds the first row that no longer fits.
"""
import hashlib
import json
from datetime import datetime, timezone

from flask import g, has_request_context, request

GENESIS = "0" * 64      # the "previous hash" of the very first row
LOCK_KEY = 727001       # any fixed number: makes audit writers take turns


def _hash(prev_hash, at, actor_id, actor_username, action, document_id,
          target_user_id, outcome, detail, ip):
    fields = [
        prev_hash, at.astimezone(timezone.utc).isoformat(), actor_id,
        actor_username, action, document_id, target_user_id, outcome,
        detail, ip,
    ]
    text = json.dumps(fields, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def record(conn, action, outcome="ok", document_id=None, target_user_id=None,
           detail=None, actor_id=None, actor_username=None):
    """Add one row. Pass the SAME connection the action itself uses, so the
    action and its record are saved together or not at all."""
    if actor_id is None and has_request_context() and getattr(g, "user", None):
        actor_id = g.user["id"]
        actor_username = g.user["username"]
    ip = request.remote_addr if has_request_context() else None

    # Only one writer at a time, so two rows can never share one "previous".
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_KEY,))
    last = conn.execute(
        "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = last["row_hash"] if last else GENESIS

    at = datetime.now(timezone.utc)
    row_hash = _hash(prev_hash, at, actor_id, actor_username, action,
                     document_id, target_user_id, outcome, detail, ip)
    conn.execute(
        "INSERT INTO audit_log (at, actor_id, actor_username, action, "
        "document_id, target_user_id, outcome, detail, ip, prev_hash, row_hash) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (at, actor_id, actor_username, action, document_id, target_user_id,
         outcome, detail, ip, prev_hash, row_hash),
    )


def verify_chain(conn):
    """Recompute every hash. Returns (ok, rows_checked, first_bad_id)."""
    prev = GENESIS
    checked = 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
        expected = _hash(prev, row["at"], row["actor_id"], row["actor_username"],
                         row["action"], row["document_id"], row["target_user_id"],
                         row["outcome"], row["detail"], row["ip"])
        if row["prev_hash"] != prev or row["row_hash"] != expected:
            return False, checked, row["id"]
        prev = row["row_hash"]
        checked += 1
    return True, checked, None