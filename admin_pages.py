"""Administrator pages: documents log, the bin (15 days), and security alerts.
The administrator sees document details here, never document contents."""
import json

from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, url_for)

import audit
import notify
from db import get_conn
from documents import CATEGORIES, parse_date
from security import login_required, role_required

bp = Blueprint("admin_pages", __name__)

BIN_DAYS = 15


# ---------------------------------------------------- documents log

@bp.route("/admin/documents")
@login_required
@role_required("admin")
def documents_log():
    title = request.args.get("title", "").strip()[:120]
    owner = request.args.get("owner", "").strip()[:80]
    category = request.args.get("category", "")
    state = request.args.get("state", "")
    date_from = parse_date(request.args.get("date_from", "").strip())
    date_to = parse_date(request.args.get("date_to", "").strip())
    where, params = ["TRUE"], {}
    if title:
        where.append("d.title ILIKE %(title)s")
        params["title"] = "%" + title.replace("%", "").replace("_", "") + "%"
    if owner:
        where.append("(u.full_name ILIKE %(owner)s OR u.username ILIKE %(owner)s)")
        params["owner"] = "%" + owner.replace("%", "").replace("_", "") + "%"
    if category in CATEGORIES:
        where.append("d.category = %(category)s")
        params["category"] = category
    else:
        category = ""
    if state == "active":
        where.append("d.deleted_at IS NULL")
    elif state == "deleted":
        where.append("d.deleted_at IS NOT NULL")
    else:
        state = ""
    if date_from:
        where.append("d.created_at >= %(date_from)s")
        params["date_from"] = date_from
    if date_to:
        where.append("d.created_at < (%(date_to)s::date + 1)")
        params["date_to"] = date_to
    with get_conn() as conn:
        # Details only: the content column is never selected here.
        docs = conn.execute(
            "SELECT d.id, d.title, d.category, d.size_bytes, d.created_at, d.deleted_at, "
            "u.full_name AS owner_name, "
            "(SELECT count(*) FROM grants g WHERE g.document_id = d.id AND g.revoked_at IS NULL) AS shares "
            "FROM documents d JOIN users u ON u.id = d.owner_id WHERE " + " AND ".join(where) +
            " ORDER BY d.created_at DESC LIMIT 300", params).fetchall()
    return render_template("documents_log.html", docs=docs, categories=CATEGORIES, title=title,
                           owner=owner, category=category, state=state,
                           date_from=request.args.get("date_from", "")[:10],
                           date_to=request.args.get("date_to", "")[:10])


# ---------------------------------------------------------- bin

def purge_expired(conn):
    """Delete for good every document that has been in the bin over 15 days."""
    old = conn.execute(
        "SELECT id, title FROM documents WHERE deleted_at IS NOT NULL "
        "AND deleted_at < now() - %s * interval '1 day' FOR UPDATE", (BIN_DAYS,)).fetchall()
    for doc in old:
        conn.execute("DELETE FROM grants WHERE document_id = %s", (doc["id"],))
        conn.execute("DELETE FROM stars WHERE document_id = %s", (doc["id"],))
        conn.execute("DELETE FROM notifications WHERE document_id = %s", (doc["id"],))
        conn.execute("DELETE FROM documents WHERE id = %s", (doc["id"],))
        audit.record(conn, "doc.purge", document_id=doc["id"],
                     detail=json.dumps({"title": doc["title"], "after_days": BIN_DAYS}))
    return len(old)


@bp.route("/admin/bin")
@login_required
@role_required("admin")
def bin_view():
    with get_conn() as conn:
        purge_expired(conn)
        docs = conn.execute(
            "SELECT d.id, d.title, d.category, d.size_bytes, d.deleted_at, "
            "u.full_name AS owner_name, x.full_name AS deleted_by_name, "
            "GREATEST(0, %s - floor(extract(epoch FROM (now() - d.deleted_at)) / 86400))::int AS days_left "
            "FROM documents d JOIN users u ON u.id = d.owner_id "
            "LEFT JOIN users x ON x.id = d.deleted_by "
            "WHERE d.deleted_at IS NOT NULL ORDER BY d.deleted_at DESC", (BIN_DAYS,)).fetchall()
    return render_template("bin.html", docs=docs, days=BIN_DAYS)


@bp.route("/admin/bin/restore", methods=["POST"])
@login_required
@role_required("admin")
def bin_restore():
    """Restore one, several (ids) or all (all=1). Documents go back to their
    original owner with the sharing they had."""
    ids = None
    if request.form.get("all") != "1":
        try:
            if request.form.get("one"):               # the Restore button on one row
                ids = [int(request.form["one"])]
            else:                                     # "Restore selected"
                ids = [int(i) for i in request.form.getlist("ids")][:500]
        except ValueError:
            abort(400)
        if not ids:
            flash("Select at least one document to restore.", "error")
            return redirect(url_for("admin_pages.bin_view"))
    with get_conn() as conn:
        purge_expired(conn)
        if ids is None:
            rows = conn.execute(
                "UPDATE documents SET deleted_at = NULL, deleted_by = NULL "
                "WHERE deleted_at IS NOT NULL RETURNING id, owner_id, title").fetchall()
        else:
            rows = conn.execute(
                "UPDATE documents SET deleted_at = NULL, deleted_by = NULL "
                "WHERE deleted_at IS NOT NULL AND id = ANY(%s) RETURNING id, owner_id, title",
                (ids,)).fetchall()
        for r in rows:
            audit.record(conn, "doc.restore", document_id=r["id"], target_user_id=r["owner_id"],
                         detail=json.dumps({"title": r["title"]}))
            notify.add(conn, r["owner_id"],
                       f"The administrator restored your document \"{r['title']}\".",
                       f"/documents/{r['id']}", r["id"])
    flash(f"{len(rows)} document(s) restored to their owners." if rows else
          "Nothing to restore.", "ok" if rows else "error")
    return redirect(url_for("admin_pages.bin_view"))


# -------------------------------------------------------- alerts

def alert_items(conn, since):
    """Unusual events since the administrator last looked (at most 7 days back)."""
    floor = "GREATEST(%s, now() - interval '7 days')"
    items = []

    for r in conn.execute(
            f"SELECT at, actor_username, document_id, detail FROM audit_log "
            f"WHERE action = 'doc.delete' AND outcome = 'ok' AND at > {floor} ORDER BY id DESC",
            (since,)).fetchall():
        title = ""
        try:
            title = json.loads(r["detail"] or "{}").get("title", "")
        except ValueError:
            pass
        items.append({"at": r["at"], "text": f"{r['actor_username']} deleted the document \"{title}\".",
                      "link": f"/admin/audit?action=doc.delete"})
    for r in conn.execute(
            f"SELECT actor_username, max(at) AS at FROM audit_log WHERE action = 'login.locked' "
            f"AND at > {floor} GROUP BY actor_username", (since,)).fetchall():
        items.append({"at": r["at"], "text": f"The account \"{r['actor_username']}\" was locked after repeated wrong passwords.",
                      "link": f"/admin/audit?action=login.locked"})
    for r in conn.execute(
            f"SELECT actor_username, count(*) AS n, max(at) AS at FROM audit_log "
            f"WHERE action = 'login.fail' AND at > {floor} GROUP BY actor_username HAVING count(*) >= 3",
            (since,)).fetchall():
        items.append({"at": r["at"], "text": f"{r['n']} wrong passwords were typed for \"{r['actor_username']}\".",
                      "link": f"/admin/audit?action=login.fail&username={r['actor_username']}"})
    for r in conn.execute(
            f"SELECT actor_username, count(*) AS n, max(at) AS at FROM audit_log "
            f"WHERE outcome = 'denied' AND (action LIKE 'doc.%%' OR action = 'access.denied') "
            f"AND at > {floor} AND actor_username IS NOT NULL GROUP BY actor_username HAVING count(*) >= 3",
            (since,)).fetchall():
        items.append({"at": r["at"], "text": f"{r['actor_username']} was refused access {r['n']} times.",
                      "link": f"/admin/audit?outcome=denied&username={r['actor_username']}"})
    for r in conn.execute(
            f"SELECT a.actor_username, max(a.at) AS at, count(*) AS n FROM audit_log a "
            f"WHERE a.action IN ('doc.open', 'doc.download') AND a.outcome = 'ok' AND a.at > {floor} "
            f"AND (SELECT count(*) FROM audit_log b WHERE b.actor_id = a.actor_id "
            f"     AND b.action IN ('doc.open', 'doc.download') AND b.outcome = 'ok' "
            f"     AND b.at BETWEEN a.at AND a.at + interval '10 minutes') >= 10 "
            f"GROUP BY a.actor_username", (since,)).fetchall():
        items.append({"at": r["at"], "text": f"{r['actor_username']} opened or downloaded 10 or more documents within 10 minutes.",
                      "link": f"/admin/audit?username={r['actor_username']}"})
    for r in conn.execute(
            f"SELECT at, detail FROM audit_log WHERE action = 'audit.verify' AND outcome = 'denied' "
            f"AND at > {floor}", (since,)).fetchall():
        items.append({"at": r["at"], "text": "The audit chain check FAILED: the record may have been altered.",
                      "link": "/admin/audit?action=audit.verify"})
    items.sort(key=lambda i: i["at"], reverse=True)
    return items


def _since(conn, admin_id):
    row = conn.execute("SELECT alerts_seen_at FROM users WHERE id = %s", (admin_id,)).fetchone()
    return row["alerts_seen_at"] or conn.execute("SELECT now() - interval '7 days' AS t").fetchone()["t"]


def count_alerts(conn, admin_id):
    return len(alert_items(conn, _since(conn, admin_id)))


@bp.route("/admin/alerts")
@login_required
@role_required("admin")
def alerts():
    with get_conn() as conn:
        items = alert_items(conn, _since(conn, g.user["id"]))
    return render_template("alerts.html", items=items)


@bp.route("/admin/alerts/seen", methods=["POST"])
@login_required
@role_required("admin")
def alerts_seen():
    with get_conn() as conn:
        conn.execute("UPDATE users SET alerts_seen_at = now() WHERE id = %s", (g.user["id"],))
    flash("All alerts marked as seen.", "ok")
    return redirect(url_for("admin_pages.alerts"))