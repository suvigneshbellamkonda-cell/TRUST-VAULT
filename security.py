"""Helpers every route shares: the CSRF token and the two route guards."""
import secrets
from functools import wraps

from flask import abort, g, redirect, request, session, url_for

import audit
from db import get_conn


def csrf_token():
    """The secret value every form must send back with a POST."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf_token", "").encode()
    expected = session.get("csrf", "").encode()
    if not expected or not secrets.compare_digest(sent, expected):
        abort(400)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    """Use AFTER login_required. Answers 404 (not 403) so a visitor cannot
    even tell the page exists, and records the refused attempt."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.user["role"] not in allowed_roles:
                with get_conn() as conn:
                    audit.record(conn, "access.denied", outcome="denied",
                                 detail=f"{request.method} {request.path}"[:200])
                abort(404)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def password_problem(password):
    """Why a new password is not acceptable, or None when it is fine.
    Rule: 8+ characters with a capital letter, a number and a special character."""
    if not 8 <= len(password) <= 200:
        return "Password must be 8 to 200 characters."
    if not any(c.isupper() for c in password):
        return "Password needs at least one capital letter."
    if not any(c.isdigit() for c in password):
        return "Password needs at least one number."
    if all(c.isalnum() for c in password):
        return "Password needs at least one special character, such as @ # ! or ?."
    return None