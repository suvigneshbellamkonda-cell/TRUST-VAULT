import os
from datetime import timedelta

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import audit
import notify  # noqa: F401
from accounts import bp as accounts_bp, invitation_rows
from admin_audit import bp as admin_audit_bp
from admin_pages import bp as admin_pages_bp
from db import get_conn  # importing db also loads the .env file
from documents import bp as documents_bp
from security import check_csrf, csrf_token, login_required, role_required

app = Flask(__name__)

# Signs the login cookie. Without it nobody can start the app.
app.secret_key = os.environ["SECRET_KEY"]

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",   # browser does not send it on cross-site POSTs
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),  # https only on Render
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=102 * 1024 * 1024,  # refuse any request over 102 MB (100 MB of files plus form data)
)

# Render puts a proxy in front of the app. This makes request.remote_addr the
# real visitor address (the last entry the proxy added), not the proxy's.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.jinja_env.globals["csrf_token"] = csrf_token


@app.context_processor
def bell():
    """Number of unread notifications, shown on the bell on every page."""
    if getattr(g, "user", None) is None:
        return {"unread": 0, "alert_count": 0}
    with get_conn() as conn:
        unread = conn.execute("SELECT count(*) AS n FROM notifications "
                              "WHERE user_id = %s AND read_at IS NULL", (g.user["id"],)).fetchone()["n"]
        alerts = 0
        if g.user["role"] == "admin":
            from admin_pages import count_alerts
            alerts = count_alerts(conn, g.user["id"])
    return {"unread": unread, "alert_count": alerts}


app.register_blueprint(documents_bp)
app.register_blueprint(admin_audit_bp)
app.register_blueprint(accounts_bp)
app.register_blueprint(admin_pages_bp)


MAX_FAILS_PER_USERNAME = 5
MAX_FAILS_PER_IP = 20
LOCKOUT_MINUTES = 15

# Used so a login for a username that does not exist takes as long as one that
# does. Otherwise response time would reveal which usernames are real.
DUMMY_HASH = generate_password_hash("not-a-real-password")


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
                "SELECT id, username, full_name, role, organisation, is_active, "
                "session_version FROM users WHERE id = %s",
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
            audit.record(conn, "login.locked", outcome="denied",
                         actor_username=username, detail="too many failures")
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
        audit.record(
            conn,
            "login.ok" if success else "login.fail",
            outcome="ok" if success else "denied",
            actor_id=user["id"] if success else None,
            actor_username=username,
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
        audit.record(conn, "logout")
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------- pages

@app.route("/")
@login_required
def home():
    from authz import visible_documents
    stats, recent = {}, []
    with get_conn() as conn:
        role, uid = g.user["role"], g.user["id"]
        if role == "admin":
            q = lambda sql: conn.execute(sql).fetchone()["n"]
            stats = {
                "owners": q("SELECT count(*) AS n FROM users WHERE role = 'owner'"),
                "viewers": q("SELECT count(*) AS n FROM users WHERE role = 'viewer'"),
                "documents": q("SELECT count(*) AS n FROM documents WHERE deleted_at IS NULL"),
                "bin": q("SELECT count(*) AS n FROM documents WHERE deleted_at IS NOT NULL"),
                "pending": q("SELECT count(*) AS n FROM invitations WHERE used_at IS NULL AND expires_at > now()"),
            }
            recent = conn.execute(
                "SELECT at, actor_username, action, outcome FROM audit_log ORDER BY id DESC LIMIT 6").fetchall()
        else:
            mine = visible_documents(conn, g.user, scope="mine" if role == "owner" else "shared")
            stats = {"count": len(mine),
                     "starred": len(visible_documents(conn, g.user, starred_only=True))}
            if role == "owner":
                stats["shared"] = conn.execute(
                    "SELECT count(DISTINCT g.document_id) AS n FROM grants g JOIN documents d "
                    "ON d.id = g.document_id WHERE d.owner_id = %s AND d.deleted_at IS NULL "
                    "AND g.revoked_at IS NULL", (uid,)).fetchone()["n"]
            else:
                stats["editable"] = len([d for d in mine if d["access"] == "edit"])
            recent = mine[:5]
    return render_template("dashboard.html", stats=stats, recent=recent)


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
    role = request.args.get("role", "")
    state = request.args.get("state", "")
    q = request.args.get("q", "").strip()[:80]
    istatus = request.args.get("istatus", "")
    where, params = ["TRUE"], {}
    if role in ("owner", "viewer", "admin"):
        where.append("role = %(role)s")
        params["role"] = role
    if state in ("active", "disabled"):
        where.append("is_active = %(active)s")
        params["active"] = state == "active"
    if q:
        where.append("(full_name ILIKE %(q)s OR username ILIKE %(q)s OR email ILIKE %(q)s)")
        params["q"] = "%" + q.replace("%", "").replace("_", "") + "%"
    with get_conn() as conn:
        users = conn.execute(
            "SELECT id, username, full_name, email, role, is_active, created_at "
            "FROM users WHERE " + " AND ".join(where) + " ORDER BY id", params).fetchall()
        invites = invitation_rows(conn, None, istatus, "")
    return render_template("admin_users.html", users=users, invites=invites,
                           role=role, state=state, q=q, istatus=istatus)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def toggle_user(user_id):
    if user_id == g.user["id"]:
        with get_conn() as conn:
            audit.record(conn, "user.disable", outcome="denied",
                         target_user_id=user_id, detail="cannot disable yourself")
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
        if row is not None:
            audit.record(
                conn,
                "user.enable" if row["is_active"] else "user.disable",
                target_user_id=user_id,
                detail=f"username={row['username']}",
            )
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
    # setdefault: a route may set a stricter policy of its own (downloads do),
    # and this must not overwrite it.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    if os.environ.get("RENDER"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"  # nothing kept after logout
    return response


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(500)
def error_page(error):
    code = getattr(error, "code", 500)
    messages = {
        400: "Bad request.",
        404: "Page not found.",
        413: "That upload is too large (the limit is 100 MB in total).",
        500: "Something went wrong.",
    }
    # Never show the real error text or a stack trace to visitors.
    return render_template("error.html", code=code, message=messages.get(code, "Error.")), code