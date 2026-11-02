# TrustVault

Secure document sharing where the wrong person cannot reach a document, and every access is recorded in a tamper-evident audit trail.

> Status: in progress. This README lists only what is actually built.

## Live site
https://trust-vault-kutu.onrender.com

The free plan sleeps after 15 minutes without visitors. The first visit can take about a minute to wake up.

## What works today
- Live deployment on Render, connected to a Neon PostgreSQL database
- Database tables (users, documents, grants) and five demo users
- /health check that confirms the database is reachable

## Stack
Python, Flask, PostgreSQL (Neon), Jinja2 templates. Tests: pytest. Hosting: Render.

## Roles (planned)
- Admin: creates and disables users, sees all activity and the audit log. Cannot read document contents unless granted.
- Owner: uploads documents, grants and revokes read/edit access to named people.
- Viewer: can only open documents granted to them.

## Run locally
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python setup_db.py
    flask --app app run

You need a `.env` file containing `DATABASE_URL=` followed by your own Postgres connection string.

## Unfinished
Login, documents, permissions, the audit trail and search are not built yet.