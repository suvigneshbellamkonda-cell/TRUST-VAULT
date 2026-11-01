# TrustVault

Secure document sharing where the wrong person cannot reach a document, and every access is recorded in a tamper-evident audit trail.

> Status: in progress. This README lists only what is actually built.

## What works today
- A minimal Flask app with a home page and a /health check.

## Stack
Python, Flask, PostgreSQL, Jinja2 templates. Tests: pytest. Hosting: Render.

## Roles (planned)
- Admin: creates and disables users, sees all activity and the audit log. Cannot read document contents unless granted.
- Owner: uploads documents, grants and revokes read/edit access to named people.
- Viewer: can only open documents granted to them.

## Run locally
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    flask --app app run

## Unfinished
Everything except the minimal app above.# TRUST-VAULT
Secure document sharing platform with document-level access control and tamper-evident audit logs.
