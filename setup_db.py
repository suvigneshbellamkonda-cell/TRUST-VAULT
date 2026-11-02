"""Creates the tables and the demo users.

Run once:  python setup_db.py
Safe to run again: existing tables and users are left alone.
"""
from pathlib import Path

from werkzeug.security import generate_password_hash

from db import get_conn

# Demo accounts. These passwords are published in the README so the
# evaluators can log in. That is an accepted risk (see THREATS.md).
DEMO_USERS = [
    # username,  full name,       role,     password
    ("admin",    "Asha Admin",    "admin",  "Admin@TV2026"),
    ("alice",    "Alice Owner",   "owner",  "Alice@TV2026"),
    ("bob",      "Bob Owner",     "owner",  "Bob@TV2026"),
    ("carol",    "Carol Viewer",  "viewer", "Carol@TV2026"),
    ("dave",     "Dave Viewer",   "viewer", "Dave@TV2026"),
]


def main():
    schema = Path(__file__).with_name("schema.sql").read_text()

    with get_conn() as conn:
        conn.execute(schema)
        print("Tables created (or already existed).")

        for username, full_name, role, password in DEMO_USERS:
            # %s placeholders: psycopg fills them in safely (no SQL injection).
            conn.execute(
                """
                INSERT INTO users (username, full_name, password_hash, role)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING
                """,
                (username, full_name, generate_password_hash(password), role),
            )

        users = conn.execute(
            "SELECT id, username, role, is_active FROM users ORDER BY id"
        ).fetchall()

    print("Users in the database:")
    for u in users:
        print(f"  {u['id']}: {u['username']} ({u['role']})")


if __name__ == "__main__":
    main()