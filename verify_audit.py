"""Checks the audit chain and prints the latest entries.

Run:  python verify_audit.py
"""
import audit
from db import get_conn

with get_conn() as conn:
    ok, checked, bad_id = audit.verify_chain(conn)
    latest = conn.execute(
        "SELECT id, at, actor_username, action, outcome, document_id "
        "FROM audit_log ORDER BY id DESC LIMIT 10"
    ).fetchall()

if ok:
    print(f"Audit chain OK: {checked} entries, none altered or removed.")
else:
    print(f"AUDIT CHAIN BROKEN at entry id {bad_id} (after {checked} good entries).")

print("\nLatest entries (newest first):")
for r in latest:
    print(f"  #{r['id']} {r['at']:%Y-%m-%d %H:%M:%S} "
          f"{r['actor_username'] or '-':<10} {r['action']:<14} {r['outcome']:<7} doc={r['document_id']}")