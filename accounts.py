"""Accounts: invitations, joining, "Forgot password", Settings, Profile and
notifications. Nobody can create an account except through an invitation:
the administrator invites owners, and owners invite viewers."""
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import timedelta

import psycopg
from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import audit
import mailer
import notify
from db import get_conn
from security import login_required, password_problem, role_required

bp = Blueprint("accounts", __name__)

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
INVITE_HOURS = 48
OTP_MINUTES = 10
OTP_MAX_TRIES = 5
STATUS_SQL = ("CASE WHEN i.used_at IS NOT NULL THEN 'accepted' "
              "WHEN i.expires_at < now() THEN 'expired' ELSE 'pending' END")


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def app_url():
    return (os.environ.get("APP_URL") or request.host_url).rstrip("/")


# ------------------------------------------------------- invitations

def send_invitation(role, form, back_endpoint):
    """Create an invitation and e-mail it. Used by the admin (owners) and by
    owners (viewers). Returns a redirect."""
    full_name = form.get("full_name", "").strip()
    email = form.get("email", "").strip().lower()
    problem = None
    if not 1 <= len(full_name) <= 80:
        problem = "Enter the person's full name (up to 80 characters)."
    elif len(email) > 120 or not EMAIL_RE.match(email):
        problem = "Enter a valid e-mail address."
    elif not mailer.domain_exists(email):
        problem = f"The e-mail domain \"{email.rsplit('@', 1)[-1]}\" does not exist. Please check the spelling."
    if problem:
        flash(problem, "error")
        return redirect(url_for(back_endpoint))

    token = secrets.token_urlsafe(32)
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE lower(email) = %s", (email,)).fetchone():
            flash("An account with that e-mail address already exists.", "error")
            return redirect(url_for(back_endpoint))
        # An earlier unused invitation to the same address stops working.
        conn.execute("UPDATE invitations SET expires_at = now() "
                     "WHERE lower(email) = %s AND used_at IS NULL AND expires_at > now()",
                     (email,))
        conn.execute(
            "INSERT INTO invitations (token_hash, full_name, email, role, invited_by, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, now() + %s)",
            (hash_token(token), full_name, email, role, g.user["id"],
             timedelta(hours=INVITE_HOURS)))
        audit.record(conn, "invite.send", detail=f"role={role} email={email}"[:200])

    link = f"{app_url()}/join/{token}"
    word = "document owner" if role == "owner" else "viewer"
    sent = mailer.send(
        email, full_name, "You have been invited to join TrustVault",
        f"Dear {full_name},\n\n{g.user['full_name']} has invited you to join TrustVault as a "
        f"{word}. Please use the link below to complete your registration:\n\n{link}\n\n"
        f"The link can be used once and expires in {INVITE_HOURS} hours. If you were not "
        "expecting this invitation, please ignore this e-mail.\n\nRegards,\nTrustVault")
    if sent:
        flash(f"The invitation e-mail was handed to the mail service for {email}. "
              "If that address does not exist it will not arrive, and the invitation stays Pending.", "ok")
    else:
        flash(f"E-mail is not set up on this server, so nothing was sent. "
              f"Give this one-time link to {full_name} yourself: {link}", "error")
    return redirect(url_for(back_endpoint))


def invitation_rows(conn, inviter_id=None, status="", q=""):
    where, params = [], {}
    if inviter_id is not None:
        where.append("i.invited_by = %(inviter)s")
        params["inviter"] = inviter_id
    else:
        where.append("i.role = 'owner'")
    if status in ("pending", "accepted", "expired"):
        where.append(STATUS_SQL + " = %(status)s")
        params["status"] = status
    if q:
        where.append("(i.full_name ILIKE %(q)s OR i.email ILIKE %(q)s)")
        params["q"] = "%" + q.replace("%", "").replace("_", "") + "%"
    return conn.execute(
        f"SELECT i.full_name, i.email, i.role, i.created_at, i.expires_at, {STATUS_SQL} AS status "
        "FROM invitations i WHERE " + " AND ".join(where) + " ORDER BY i.id DESC LIMIT 200",
        params).fetchall()


@bp.route("/admin/invitations", methods=["POST"])
@login_required
@role_required("admin")
def admin_invite():
    return send_invitation("owner", request.form, "admin_users")


@bp.route("/viewers")
@login_required
@role_required("owner")
def viewers():
    status = request.args.get("status", "")
    q = request.args.get("q", "").strip()[:80]
    with get_conn() as conn:
        invites = invitation_rows(conn, g.user["id"], status, q)
        people = conn.execute(
            "SELECT username, full_name, email, is_active FROM users "
            "WHERE invited_by = %s AND role = 'viewer' ORDER BY id DESC", (g.user["id"],)
        ).fetchall()
    return render_template("viewers.html", invites=invites, people=people, status=status, q=q)


@bp.route("/viewers/invitations", methods=["POST"])
@login_required
@role_required("owner")
def owner_invite():
    return send_invitation("viewer", request.form, "accounts.viewers")


# --------------------------------------------------------- joining

def find_invitation(conn, token):
    return conn.execute(
        "SELECT i.*, u.organisation FROM invitations i JOIN users u ON u.id = i.invited_by "
        "WHERE i.token_hash = %s AND i.used_at IS NULL AND i.expires_at > now()",
        (hash_token(token[:200]),)).fetchone()


@bp.route("/join/<token>", methods=["GET", "POST"])
def join(token):
    # Works even if someone else is signed in on this browser (for example the
    # inviter opening the link on the same computer): the page is a public page.
    with get_conn() as conn:
        invite = find_invitation(conn, token)
    if invite is None:
        return render_template("join_invalid.html"), 404
    if request.method == "GET":
        return render_template("join.html", invite=invite, form={})

    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    form = {"full_name": full_name or invite["full_name"], "username": username}
    problem = None
    if not 1 <= len(full_name) <= 80:
        problem = "Full name must be 1-80 characters."
    elif not USERNAME_RE.match(username):
        problem = "Username must be 3-30 characters: a-z, 0-9 and underscore."
    else:
        problem = password_problem(password)
    if problem is None and password != request.form.get("confirm_password", ""):
        problem = "The two passwords are not the same."

    if problem is None:
        try:
            with get_conn() as conn:
                # Marking the invitation used is the very first write, and only
                # one request can win it: a second use of the link finds nothing.
                taken = conn.execute(
                    "UPDATE invitations SET used_at = now() WHERE id = %s "
                    "AND used_at IS NULL AND expires_at > now() RETURNING id",
                    (invite["id"],)).fetchone()
                if taken is None:
                    return render_template("join_invalid.html"), 404
                user = conn.execute(
                    "INSERT INTO users (username, full_name, password_hash, role, email, "
                    "organisation, invited_by) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (username, full_name, generate_password_hash(password), invite["role"],
                     invite["email"], invite["organisation"], invite["invited_by"])).fetchone()
                conn.execute("UPDATE invitations SET used_by = %s WHERE id = %s",
                             (user["id"], invite["id"]))
                audit.record(conn, "invite.accept", actor_id=user["id"],
                             actor_username=username, target_user_id=invite["invited_by"],
                             detail=f"role={invite['role']}")
                notify.add(conn, invite["invited_by"],
                           f"{full_name} accepted your invitation and joined as a {invite['role']}.",
                           "/viewers" if invite["role"] == "viewer" else "/admin/users")
        except psycopg.errors.UniqueViolation:
            problem = "That username is already taken. Please choose another."

    if problem:
        flash(problem, "error")
        return render_template("join.html", invite=invite, form=form), 400
    if g.user is not None:
        session.clear()          # the new person signs in fresh, not as the inviter
    return redirect(url_for("accounts.joined"))


@bp.route("/joined")
def joined():
    return render_template("joined.html")


# -------------------------------------------------- forgot password

def otp_hash(user_id, otp):
    return hmac.new(current_app.secret_key.encode(), f"{user_id}:{otp}".encode(),
                    hashlib.sha256).hexdigest()


@bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "GET":
        return render_template("forgot.html")
    from app import too_many_failures        # same lockout helper the login uses
    email = request.form.get("email", "").strip().lower()[:120]
    ip = request.remote_addr or "unknown"
    session.pop("reset_id", None)
    session["reset_email"] = email
    with get_conn() as conn:
        key = f"forgot:{ip}"
        if too_many_failures(conn, key, ip):
            flash("Too many requests. Try again in 15 minutes.", "error")
            return render_template("forgot.html"), 429
        conn.execute("INSERT INTO login_attempts (username, ip, success) VALUES (%s, %s, FALSE)",
                     (key, ip))
        # The administrator has no e-mail reset: that password changes in the database.
        user = conn.execute(
            "SELECT id, full_name, email FROM users WHERE lower(email) = %s "
            "AND is_active AND role <> 'admin'", (email,)).fetchone()
        recent = 0
        if user:
            recent = conn.execute(
                "SELECT count(*) AS n FROM password_resets WHERE user_id = %s "
                "AND created_at > now() - interval '1 hour'", (user["id"],)).fetchone()["n"]
        if user and recent < 3:
            otp = f"{secrets.randbelow(10**6):06d}"
            conn.execute("UPDATE password_resets SET used_at = now() "
                         "WHERE user_id = %s AND used_at IS NULL", (user["id"],))
            conn.execute(
                "INSERT INTO password_resets (user_id, otp_hash, expires_at) VALUES (%s, %s, now() + %s)",
                (user["id"], otp_hash(user["id"], otp), timedelta(minutes=OTP_MINUTES)))
            audit.record(conn, "password.otp_sent", actor_id=user["id"],
                         actor_username=None, target_user_id=user["id"])
            mailer.send(user["email"], user["full_name"], "Your TrustVault verification code",
                        f"Dear {user['full_name']},\n\nYour one-time code is {otp}. It expires in "
                        f"{OTP_MINUTES} minutes and can be used once. If you did not ask for it, "
                        "please ignore this e-mail; your password has not changed.\n\nRegards,\nTrustVault")
    # The same answer whether or not the address belongs to an account.
    flash("If that address belongs to an account, a code has been sent to it.", "ok")
    return redirect(url_for("accounts.forgot_code"))


@bp.route("/forgot/code", methods=["GET", "POST"])
def forgot_code():
    email = session.get("reset_email")
    if not email:
        return redirect(url_for("accounts.forgot"))
    if request.method == "GET":
        return render_template("forgot_code.html")
    code = re.sub(r"\s", "", request.form.get("otp", ""))[:10]
    wrong = False
    with get_conn() as conn:
        row = conn.execute(
            "SELECT r.id, r.user_id, r.otp_hash, r.attempts FROM password_resets r "
            "JOIN users u ON u.id = r.user_id WHERE lower(u.email) = %s AND r.used_at IS NULL "
            "AND r.expires_at > now() ORDER BY r.id DESC LIMIT 1", (email,)).fetchone()
        if row is None or row["attempts"] >= OTP_MAX_TRIES:
            wrong = True
            flash("That code is no longer valid. Please request a new one.", "error")
            session.pop("reset_email", None)
            target = "accounts.forgot"
        elif hmac.compare_digest(row["otp_hash"], otp_hash(row["user_id"], code)):
            conn.execute("UPDATE password_resets SET verified_at = now() WHERE id = %s", (row["id"],))
            audit.record(conn, "password.otp_ok", actor_id=row["user_id"], target_user_id=row["user_id"])
            session["reset_id"] = row["id"]
            return redirect(url_for("accounts.forgot_new"))
        else:
            wrong = True
            conn.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE id = %s", (row["id"],))
            audit.record(conn, "password.otp_fail", outcome="denied", actor_id=row["user_id"],
                         target_user_id=row["user_id"])
            flash("That code is not correct.", "error")
            target = None
    if wrong and target:
        return redirect(url_for(target))
    return render_template("forgot_code.html"), 400


@bp.route("/forgot/new", methods=["GET", "POST"])
def forgot_new():
    reset_id = session.get("reset_id")
    if not reset_id:
        return redirect(url_for("accounts.forgot"))
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, user_id FROM password_resets WHERE id = %s AND verified_at IS NOT NULL "
            "AND used_at IS NULL AND verified_at > now() - interval '15 minutes'",
            (reset_id,)).fetchone()
        if row is None:
            session.pop("reset_id", None)
            flash("Please start again: the code check has expired.", "error")
            return redirect(url_for("accounts.forgot"))
        if request.method == "GET":
            return render_template("forgot_new.html")
        password = request.form.get("password", "")
        problem = password_problem(password)
        if problem is None and password != request.form.get("confirm_password", ""):
            problem = "The two passwords are not the same."
        if problem is None:
            # The database trigger ends every session of this user.
            conn.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                         (generate_password_hash(password), row["user_id"]))
            conn.execute("UPDATE password_resets SET used_at = now() WHERE id = %s", (row["id"],))
            audit.record(conn, "password.reset", actor_id=row["user_id"], target_user_id=row["user_id"])
    if problem:
        flash(problem, "error")
        return render_template("forgot_new.html"), 400
    session.clear()
    flash("Your password has been changed. Please sign in.", "ok")
    return redirect(url_for("login"))


# ------------------------------------------- settings and profile

@bp.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@bp.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password", "")[:200]
    new = request.form.get("new_password", "")
    with get_conn() as conn:
        stored = conn.execute("SELECT password_hash FROM users WHERE id = %s",
                              (g.user["id"],)).fetchone()["password_hash"]
        if not check_password_hash(stored, current):
            audit.record(conn, "password.change", outcome="denied", detail="wrong current password")
            problem = "Your current password is not correct."
        else:
            problem = password_problem(new)
            if problem is None and new != request.form.get("confirm_password", ""):
                problem = "The two new passwords are not the same."
            if problem is None and check_password_hash(stored, new):
                problem = "Choose a password different from the current one."
        if problem is None:
            # The trigger raises session_version: every other device is signed out.
            row = conn.execute("UPDATE users SET password_hash = %s WHERE id = %s "
                               "RETURNING session_version",
                               (generate_password_hash(new), g.user["id"])).fetchone()
            audit.record(conn, "password.change")
            session["sv"] = row["session_version"]      # this device stays signed in
    if problem:
        flash(problem, "error")
    else:
        flash("Your password has been changed. Other devices were signed out.", "ok")
    return redirect(url_for("accounts.settings"))


@bp.route("/profile/edit", methods=["POST"])
@login_required
def profile_edit():
    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("current_password", "")[:200]
    problem = None
    if not 1 <= len(full_name) <= 80:
        problem = "Full name must be 1-80 characters."
    elif not USERNAME_RE.match(username):
        problem = "Username must be 3-30 characters: a-z, 0-9 and underscore."
    elif len(email) > 120 or not EMAIL_RE.match(email):
        problem = "Enter a valid e-mail address."
    if problem is None:
        try:
            with get_conn() as conn:
                me = conn.execute("SELECT username, full_name, email, password_hash FROM users "
                                  "WHERE id = %s", (g.user["id"],)).fetchone()
                if not check_password_hash(me["password_hash"], password):
                    audit.record(conn, "profile.edit", outcome="denied", detail="wrong password")
                    problem = "Your current password is not correct."
                else:
                    changed = {k: [old, new] for k, old, new in (
                        ("full_name", me["full_name"], full_name),
                        ("username", me["username"], username),
                        ("email", (me["email"] or "").lower(), email)) if old != new}
                    if changed:
                        conn.execute("UPDATE users SET full_name = %s, username = %s, email = %s "
                                     "WHERE id = %s", (full_name, username, email, g.user["id"]))
                        if "email" in changed:      # a code sent to the old address stops working
                            conn.execute("UPDATE password_resets SET used_at = now() "
                                         "WHERE user_id = %s AND used_at IS NULL", (g.user["id"],))
                        audit.record(conn, "profile.edit", detail=json.dumps(changed)[:400])
        except psycopg.errors.UniqueViolation:
            problem = "That username or e-mail address is already in use."
    if problem:
        flash(problem, "error")
    else:
        flash("Profile updated.", "ok")
    return redirect(url_for("accounts.profile"))


@bp.route("/profile")
@login_required
def profile():
    with get_conn() as conn:
        me = conn.execute("SELECT username, full_name, email, role, organisation, created_at "
                          "FROM users WHERE id = %s", (g.user["id"],)).fetchone()
        last = conn.execute(
            "SELECT at FROM audit_log WHERE actor_id = %s AND action = 'login.ok' "
            "ORDER BY id DESC LIMIT 1 OFFSET 1", (g.user["id"],)).fetchone()
    return render_template("profile.html", me=me, last=last)


# --------------------------------------------------- notifications

@bp.route("/notifications")
@login_required
def notifications():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, message, created_at, read_at FROM notifications "
            "WHERE user_id = %s ORDER BY id DESC LIMIT 100", (g.user["id"],)).fetchall()
    return render_template("notifications.html", rows=rows)


@bp.route("/notifications/<int:note_id>/go")
@login_required
def notification_go(note_id):
    with get_conn() as conn:
        row = conn.execute(
            "UPDATE notifications SET read_at = COALESCE(read_at, now()) "
            "WHERE id = %s AND user_id = %s RETURNING link", (note_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    link = row["link"]
    if not link.startswith("/") or link.startswith("//"):
        abort(404)
    return redirect(link)


@bp.route("/notifications/clear", methods=["POST"])
@login_required
def notifications_clear():
    """Delete the person's own notifications: the ones already read, or all."""
    if request.form.get("which") == "all":
        sql = "DELETE FROM notifications WHERE user_id = %s"
    else:
        sql = "DELETE FROM notifications WHERE user_id = %s AND read_at IS NOT NULL"
    with get_conn() as conn:
        conn.execute(sql, (g.user["id"],))
    return redirect(url_for("accounts.notifications"))


@bp.route("/notifications/read-all", methods=["POST"])
@login_required
def notifications_read_all():
    with get_conn() as conn:
        conn.execute("UPDATE notifications SET read_at = now() WHERE user_id = %s AND read_at IS NULL",
                     (g.user["id"],))
    return redirect(url_for("accounts.notifications"))