"""Adds a few sample documents and shares, so a fresh install has something to look at.

Run once:  python seed_demo.py
Safe to run again: a document that already exists is skipped.
"""
import hashlib
import json

import audit
from db import get_conn

# owner, title, category, filename, text, [(username, permission), ...]
SAMPLES = [
    ("alice", "Salary letter - Carol", "Salary letter", "salary-letter.txt",
     "Demo salary letter for Carol. This is sample text, not real data.\n",
     [("carol", "read")]),
    ("alice", "Site drawing rev B", "Drawing", "drawing-notes.txt",
     "Demo drawing notes. Sample text only.\n",
     [("dave", "edit"), ("carol", "read")]),
    ("bob", "Customer contract - Acme", "Contract", "acme-contract.txt",
     "Demo contract text. Sample text only. Not shared with anyone.\n", []),
    ("bob", "Audit paper 2026", "Audit paper", "audit-paper.txt",
     "Demo audit paper. Sample text only.\n", [("dave", "read")]),
]


def main():
    with get_conn() as conn:
        users = {u["username"]: u for u in conn.execute(
            "SELECT id, username FROM users").fetchall()}

        for owner, title, category, filename, text, shares in SAMPLES:
            owner_id = users[owner]["id"]
            exists = conn.execute(
                "SELECT id FROM documents WHERE owner_id = %s AND title = %s",
                (owner_id, title)).fetchone()
            if exists:
                print(f"skip   {title}")
                continue

            data = text.encode()
            sha256 = hashlib.sha256(data).hexdigest()
            doc = conn.execute(
                "INSERT INTO documents (owner_id, title, category, filename, mime_type, "
                "size_bytes, sha256, content) "
                "VALUES (%s, %s, %s, %s, 'text/plain; charset=utf-8', %s, %s, %s) RETURNING id",
                (owner_id, title, category, filename, len(data), sha256, data)).fetchone()
            audit.record(conn, "doc.upload", document_id=doc["id"], actor_id=owner_id,
                         actor_username=owner,
                         detail=json.dumps({"filename": filename, "size": len(data),
                                            "sha256": sha256}))
            for username, permission in shares:
                target = users[username]
                conn.execute(
                    "INSERT INTO grants (document_id, user_id, permission, granted_by) "
                    "VALUES (%s, %s, %s, %s)",
                    (doc["id"], target["id"], permission, owner_id))
                audit.record(conn, "grant.add", document_id=doc["id"], actor_id=owner_id,
                             actor_username=owner, target_user_id=target["id"],
                             detail=permission)
            print(f"added  {title}")


if __name__ == "__main__":
    main()