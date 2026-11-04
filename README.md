# TrustVault

Secure document sharing where the wrong person cannot reach a document, and every access is recorded in a tamper-evident audit trail.

> Status: in progress. This README lists only what is actually built.

## Live site
https://trust-vault-kutu.onrender.com

The free plan sleeps after 15 minutes without visitors. The first visit can take about a minute to wake up.

## Demo accounts
| Role | Username | Password |
|---|---|---|
| Admin | admin | Admin@TV2026 |
| Owner | alice | Alice@TV2026 |
| Owner | bob | Bob@TV2026 |
| Viewer | carol | Carol@TV2026 |
| Viewer | dave | Dave@TV2026 |

These are demo accounts with no real data. After 5 wrong passwords for one username, login is locked for 15 minutes.

## What works today
- Live deployment on Render, connected to a Neon PostgreSQL database
- Database tables (users, documents, grants, login attempts) and five demo users
- Login and logout with three roles (admin, owner, viewer)
- Login lockout after repeated wrong passwords
- Admin page to create users and to disable or enable them
- /health check that confirms the database is reachable

## Stack
Python, Flask, PostgreSQL (Neon), Jinja2 templates. Tests: pytest. Hosting: Render.

## Roles
- Admin: creates and disables users, sees all activity and the audit log. Cannot read document contents unless granted.
- Owner: uploads documents, grants and revokes read/edit access to named people.
- Viewer: can only open documents granted to them.

## Run locally
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python setup_db.py
    flask --app app run

You need a `.env` file with two lines: `DATABASE_URL=` followed by your own Postgres connection string, and `SECRET_KEY=` followed by a long random string.

## Unfinished
Documents, permissions, the audit trail and search are not built yet.