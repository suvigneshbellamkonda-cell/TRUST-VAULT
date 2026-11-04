import os
import re
import secrets
from datetime import timedelta
from functools import wraps

import psycopg
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_conn  # importing db also loads the .env file

app = Flask(__name__)

# Signs the login cookie. Without it nobody can start the app.
app.secret_key = os.environ["SECRET_KEY"]

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",   # browser does not send it on cross-site POSTs
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),  # https only on Render
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Render puts a proxy in front of the app. This makes request.remote_addr the
# real visitor address (the last entry the proxy added), not the proxy's.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ROLES = ("admin", "owner", "viewer")
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,30}$")

MAX_FAILS_PER_USERNAME = 5
MAX_FAILS_PER_IP = 20
LOCKOUT_MINUTES = 15

# Used so a login for a username that does not exist takes as long as one that
# does. Otherwise response time would reveal which usernames are real.
DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------------------------------------------------------------- CSRF

def csrf_token():
    """The secret value every form must send back with a POST."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def check_csrf():
    sent = request.form.get("csrf_token", "").encode()
    expected = session.get("csrf", "").encode()
    if not expected or not secrets.compare_digest(sent, expected):
        abort(400)


# ------------------------------------------------- who is the visitor?

@app.before_request
def load_user():
    """Runs before EVERY request. Works out who is logged in by asking the
    database each time, so disabling a user takes effect immediately."""
    if request.endpoint == "static":
        return

    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        with get_conn() as conn:
            user = conn.execute(
                "SELECT id, username, full_name, role, is_active, session_version "
                "FROM users WHERE id = %s",
                (user_id,),
            ).fetchone()
        if (
            user is not None
            and user["is_active"]
            and user["session_version"] == session.get("sv")
        ):
            g.user = user
        else:
            session.clear()  # disabled, deleted, or logged out elsewhere

    # Every POST in the whole app must carry the CSRF token.
    if request.method == "POST":
        check_csrf()


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    """Use AFTER login_required. Answers 404 (not 403) so a visitor cannot
    even tell the page exists."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.user["role"] not in allowed_roles:
                abort(404)
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------------------------------------------- login

def too_many_failures(conn, username, ip):
    window = timedelta(minutes=LOCKOUT_MINUTES)
    by_username = conn.execute(
        "SELECT count(*) AS n FROM login_attempts "
        "WHERE username = %s AND NOT success AND attempted_at > now() - %s",
        (username, window),
    ).fetchone()["n"]
    by_ip = conn.execute(
        "SELECT count(*) AS n FROM login_attempts "
        "WHERE ip = %s AND NOT success AND attempted_at > now() - %s",
        (ip, window),
    ).fetchone()["n"]
    return by_username >= MAX_FAILS_PER_USERNAME or by_ip >= MAX_FAILS_PER_IP


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip().lower()[:50]
    password = request.form.get("password", "")[:200]
    ip = request.remote_addr or "unknown"

    with get_conn() as conn:
        # Locked out? Checked BEFORE the password, so a correct guess
        # during a lockout is still refused.
        if too_many_failures(conn, username, ip):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html"), 429

        user = conn.execute(
            "SELECT id, password_hash, is_active, session_version "
            "FROM users WHERE username = %s",
            (username,),
        ).fetchone()

        password_ok = check_password_hash(
            user["password_hash"] if user else DUMMY_HASH, password
        )
        success = bool(user and user["is_active"] and password_ok)

        conn.execute(
            "INSERT INTO login_attempts (username, ip, success) VALUES (%s, %s, %s)",
            (username, ip, success),
        )

    if not success:
        # Same message whether the username, the password or the account
        # status was the problem.
        flash("Wrong username or password.", "error")
        return render_template("login.html"), 401

    session.clear()  # drop anything an attacker may have planted before login
    session.permanent = True
    session["user_id"] = user["id"]
    session["sv"] = user["session_version"]
    return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    with get_conn() as conn:
        # Bumping the version makes every cookie issued so far worthless,
        # even a copy someone saved before I logged out.
        conn.execute(
            "UPDATE users SET session_version = session_version + 1 WHERE id = %s",
            (g.user["id"],),
        )
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------- pages

@app.route("/")
@login_required
def home():
    return render_template("dashboard.html")


@app.route("/health")
def health():
    # Lets the hosting platform check the app and database are alive.
    # Never shows the error itself: that could leak internal details.
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok"}
    except Exception:
        return {"status": "database unavailable"}, 503


# ------------------------------------------------------ admin: users

@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    with get_conn() as conn:
        users = conn.execute(
            "SELECT id, username, full_name, role, is_active, created_at "
            "FROM users ORDER BY id"
        ).fetchall()
    return render_template("admin_users.html", users=users, roles=ROLES)


@app.route("/admin/users", methods=["POST"])
@login_required
@role_required("admin")
def create_user():
    # Only these four fields are read from the form. Anything else the
    # browser sends is ignored.
    username = request.form.get("username", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "")
    password = request.form.get("password", "")

    problem = None
    if not USERNAME_RE.match(username):
        problem = "Username must be 3-30 characters: a-z, 0-9 and underscore."
    elif not 1 <= len(full_name) <= 80:
        problem = "Full name must be 1-80 characters."
    elif role not in ROLES:
        problem = "Choose a valid role."
    elif not 10 <= len(password) <= 200:
        problem = "Password must be at least 10 characters."

    if problem is None:
        try:
            with get_conn() as conn:
                conn.execute(
                    "INSERT INTO users (username, full_name, password_hash, role) "
                    "VALUES (%s, %s, %s, %s)",
                    (username, full_name, generate_password_hash(password), role),
                )
            flash(f"User {username} created.", "ok")
        except psycopg.errors.UniqueViolation:
            problem = "That username is already taken."

    if problem:
        flash(problem, "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def toggle_user(user_id):
    if user_id == g.user["id"]:
        flash("You cannot disable your own account.", "error")
        return redirect(url_for("admin_users"))

    with get_conn() as conn:
        # Flips active/disabled. Bumping session_version also kills any login
        # cookie the user already holds, so re-enabling later does not bring
        # an old cookie back to life.
        row = conn.execute(
            "UPDATE users SET is_active = NOT is_active, "
            "session_version = session_version + 1 "
            "WHERE id = %s RETURNING username, is_active",
            (user_id,),
        ).fetchone()
    if row is None:
        abort(404)

    state = "enabled" if row["is_active"] else "disabled"
    flash(f"User {row['username']} {state}.", "ok")
    return redirect(url_for("admin_users"))


# ---------------------------------------------- headers and error pages

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if os.environ.get("RENDER"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"  # nothing kept after logout
    return response


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def error_page(error):
    code = getattr(error, "code", 500)
    messages = {400: "Bad request.", 404: "Page not found.", 500: "Something went wrong."}
    # Never show the real error text or a stack trace to visitors.
    return render_template("error.html", code=code, message=messages.get(code, "Error.")), code