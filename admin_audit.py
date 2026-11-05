"""Admin-only pages for the audit trail: browse it and check the hash chain."""
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

import audit
from db import get_conn
from security import login_required, role_required

bp = Blueprint("admin_audit", __name__)

PAGE_SIZE = 50


@bp.route("/admin/audit")
@login_required
@role_required("admin")
def audit_view():
    action = request.args.get("action", "").strip()[:40]
    outcome = request.args.get("outcome", "")
    username = request.args.get("username", "").strip().lower()[:50]
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1

    # Each filter adds a fixed piece of SQL plus a parameter. User text is
    # never joined into the SQL string itself.
    where, params = [], {}
    if action:
        where.append("action = %(action)s")
        params["action"] = action
    if outcome in ("ok", "denied"):
        where.append("outcome = %(outcome)s")
        params["outcome"] = outcome
    else:
        outcome = ""
    if username:
        where.append("actor_username = %(username)s")
        params["username"] = username
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    params["limit"] = PAGE_SIZE + 1          # one extra row tells us there is a next page
    params["offset"] = (page - 1) * PAGE_SIZE

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, at, actor_username, action, outcome, document_id, "
            "target_user_id, detail, ip FROM audit_log " + clause +
            " ORDER BY id DESC LIMIT %(limit)s OFFSET %(offset)s",
            params,
        ).fetchall()
        actions = [r["action"] for r in conn.execute(
            "SELECT DISTINCT action FROM audit_log ORDER BY action").fetchall()]

    has_next = len(rows) > PAGE_SIZE
    return render_template(
        "audit.html", rows=rows[:PAGE_SIZE], actions=actions, action=action,
        outcome=outcome, username=username, page=page, has_next=has_next,
    )


@bp.route("/admin/audit/verify", methods=["POST"])
@login_required
@role_required("admin")
def audit_verify():
    with get_conn() as conn:
        ok, checked, bad_id = audit.verify_chain(conn)
        # The check itself is recorded too (after it ran, so it is not part of it).
        audit.record(conn, "audit.verify", outcome="ok" if ok else "denied",
                     detail=f"checked={checked}" + ("" if ok else f" broken_at={bad_id}"))
    if ok:
        flash(f"Chain intact: {checked} entries, none altered or removed.", "ok")
    else:
        flash(f"CHAIN BROKEN at entry #{bad_id}. {checked} entries before it are fine.", "error")
    return redirect(url_for("admin_audit.audit_view"))