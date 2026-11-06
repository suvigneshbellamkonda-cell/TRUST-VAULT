"""Document pages: list, upload, view and download (Stage 2),
then edit, delete and sharing (Stage 3)."""
import hashlib
import json
from datetime import datetime

from flask import (Blueprint, Response, abort, flash, g, redirect,
                   render_template, request, url_for)

import audit
import uploads
from authz import authorize, can, visible_documents
from db import get_conn
from security import login_required, role_required

bp = Blueprint("documents", __name__)

CATEGORIES = ("Contract", "Salary letter", "Drawing", "Audit paper", "Other")


def clean_title(raw):
    title = raw.strip()
    return title if 1 <= len(title) <= 120 else None


def parse_date(text):
    """'2026-11-04' -> a date, or None if empty or not a real date."""
    try:
        return datetime.strptime(text, "%Y-%m-%d").date() if text else None
    except ValueError:
        return None


@bp.route("/documents")
@login_required
def list_documents():
    # Search words come from the address bar (?title=...). They only narrow the
    # list: visible_documents() still applies the access rule to every result.
    title = request.args.get("title", "").strip()[:120]
    category = request.args.get("category", "")
    owner = request.args.get("owner", "").strip()[:80]
    date_from_text = request.args.get("date_from", "").strip()
    date_to_text = request.args.get("date_to", "").strip()
    date_from, date_to = parse_date(date_from_text), parse_date(date_to_text)
    if category not in CATEGORIES:
        category = ""
    if (date_from_text and date_from is None) or (date_to_text and date_to is None):
        flash("Dates must look like 2026-11-04. That date filter was ignored.", "error")

    with get_conn() as conn:
        docs = visible_documents(conn, g.user, title=title, category=category,
                                 owner=owner, date_from=date_from, date_to=date_to)
    searching = bool(title or category or owner or date_from or date_to)
    return render_template(
        "documents.html", docs=docs, categories=CATEGORIES, searching=searching,
        title=title, category=category, owner=owner,
        date_from=date_from_text if date_from else "", date_to=date_to_text if date_to else "",
    )


@bp.route("/documents/upload")
@login_required
@role_required("owner")
def upload_form():
    return render_template("upload.html", categories=CATEGORIES)


@bp.route("/documents/upload", methods=["POST"])
@login_required
@role_required("owner")
def upload():
    # The owner is always the logged-in user. No owner field is read from the form.
    category = request.form.get("category", "")
    files = [f for f in request.files.getlist("file") if f and f.filename]

    problem = None
    checked = []          # (title, filename, mime_type, data) for every file
    if category not in CATEGORIES:
        problem = "Choose a category from the list."
    elif not files:
        problem = "Choose a file to upload."
    elif len(files) > uploads.MAX_FILES:
        problem = f"You can upload at most {uploads.MAX_FILES} files at a time."
    else:
        typed = request.form.get("title", "").strip()
        single_title = clean_title(typed)
        if (len(files) == 1 or typed) and single_title is None:
            problem = "Title must be 1-120 characters."
        total = 0
        for f in files:
            if problem:
                break
            try:
                filename, mime_type, data = uploads.check_upload(f)
            except uploads.UploadError as error:
                problem = f"{f.filename[:60]}: {error}"
                break
            total += len(data)
            if total > uploads.MAX_BATCH_BYTES:
                problem = "These files are more than 30 MB together. Upload fewer files at a time."
                break
            # One file uses the title typed in the form. With several files, the typed
            # title goes in front of each file's name ("test1 - report"); with no typed
            # title, each file's name is the title.
            stem = filename.rsplit(".", 1)[0]
            if len(files) == 1:
                title = single_title
            elif single_title:
                title = f"{single_title} - {stem}"[:120].strip()
            else:
                title = clean_title(stem) or "Untitled"
            checked.append((title, filename, mime_type, data))

    if problem:
        # All or nothing: if one file is refused, none of them is stored.
        flash(problem, "error")
        return render_template("upload.html", categories=CATEGORIES), 400

    saved_ids = []
    with get_conn() as conn:   # one transaction: every document and its audit entry, or none
        for title, filename, mime_type, data in checked:
            sha256 = hashlib.sha256(data).hexdigest()
            row = conn.execute(
                "INSERT INTO documents (owner_id, title, category, filename, mime_type, "
                "size_bytes, sha256, content) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                "RETURNING id",
                (g.user["id"], title, category, filename, mime_type, len(data), sha256, data),
            ).fetchone()
            audit.record(conn, "doc.upload", document_id=row["id"],
                         detail=json.dumps({"filename": filename, "size": len(data),
                                            "sha256": sha256}))
            saved_ids.append(row["id"])

    if len(saved_ids) == 1:
        flash("Document uploaded.", "ok")
        return redirect(url_for("documents.view_document", doc_id=saved_ids[0]))
    flash(f"{len(saved_ids)} documents uploaded.", "ok")
    return redirect(url_for("documents.list_documents"))


@bp.route("/documents/<int:doc_id>")
@login_required
def view_document(doc_id):
    grants = []
    with get_conn() as conn:
        doc = authorize(conn, g.user, doc_id, "read")
        if doc is not None and can(doc, "share"):
            grants = conn.execute(
                "SELECT gr.id, u.username, u.full_name, gr.permission, gr.granted_at "
                "FROM grants gr JOIN users u ON u.id = gr.user_id "
                "WHERE gr.document_id = %s AND gr.revoked_at IS NULL "
                "ORDER BY gr.granted_at",
                (doc_id,),
            ).fetchall()
    if doc is None:
        abort(404)
    return render_template(
        "document.html", doc=doc, grants=grants, categories=CATEGORIES,
        can_edit=can(doc, "edit"), can_share=can(doc, "share"),
        can_delete=can(doc, "delete"),
        can_open=doc["mime_type"] in PREVIEW_TYPES,
    )


@bp.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    with get_conn() as conn:
        doc = authorize(conn, g.user, doc_id, "read")
        if doc is not None:
            content = conn.execute(
                "SELECT content FROM documents WHERE id = %s", (doc_id,)
            ).fetchone()["content"]
            audit.record(conn, "doc.download", document_id=doc_id,
                         detail=json.dumps({"filename": doc["filename"],
                                            "sha256": doc["sha256"]}))
    if doc is None:
        abort(404)

    response = Response(bytes(content), mimetype=doc["mime_type"])
    # Always a download, never shown inside the site, never cached.
    response.headers["Content-Disposition"] = f'attachment; filename="{doc["filename"]}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


# Types a browser can show safely. Word and Excel files can only be downloaded.
PREVIEW_TYPES = ("application/pdf", "image/png", "image/jpeg", "text/plain; charset=utf-8")


@bp.route("/documents/<int:doc_id>/open")
@login_required
def open_document(doc_id):
    """Show the file in the browser. The same read rule as download applies."""
    with get_conn() as conn:
        doc = authorize(conn, g.user, doc_id, "read")
        if doc is not None and doc["mime_type"] in PREVIEW_TYPES:
            content = conn.execute(
                "SELECT content FROM documents WHERE id = %s", (doc_id,)
            ).fetchone()["content"]
            audit.record(conn, "doc.open", document_id=doc_id,
                         detail=json.dumps({"filename": doc["filename"],
                                            "sha256": doc["sha256"]}))
    if doc is None:
        abort(404)
    if doc["mime_type"] not in PREVIEW_TYPES:
        return redirect(url_for("documents.download", doc_id=doc_id))

    response = Response(bytes(content), mimetype=doc["mime_type"])
    response.headers["Content-Disposition"] = f'inline; filename="{doc["filename"]}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    # The file can never run scripts or load anything. (A PDF is shown by the browser's
    # own viewer, which does not work inside a sandboxed page, so it gets no "sandbox".)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'" if doc["mime_type"] == "application/pdf"
        else "default-src 'none'; sandbox")
    return response


# ---- Stage 3 routes are added below this line ----

# ------------------------------------------------ edit, delete, sharing

@bp.route("/documents/<int:doc_id>/edit", methods=["POST"])
@login_required
def edit(doc_id):
    # Only title and category can change. Nothing else is read from the form.
    title = clean_title(request.form.get("title", ""))
    category = request.form.get("category", "")

    with get_conn() as conn:
        doc = authorize(conn, g.user, doc_id, "edit")
        if doc is not None and title is not None and category in CATEGORIES:
            conn.execute(
                "UPDATE documents SET title = %s, category = %s, updated_at = now() "
                "WHERE id = %s",
                (title, category, doc_id),
            )
            audit.record(conn, "doc.edit", document_id=doc_id, detail=json.dumps({
                "title": [doc["title"], title], "category": [doc["category"], category]}))
            flash("Document updated.", "ok")
        elif doc is not None:
            flash("Title must be 1-120 characters and the category must be from the list.", "error")
    if doc is None:
        abort(404)
    return redirect(url_for("documents.view_document", doc_id=doc_id))


@bp.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    with get_conn() as conn:
        doc = authorize(conn, g.user, doc_id, "delete")
        if doc is not None:
            # Soft delete: hidden from everyone at once, kept for recovery.
            conn.execute("UPDATE documents SET deleted_at = now() WHERE id = %s", (doc_id,))
            audit.record(conn, "doc.delete", document_id=doc_id,
                         detail=json.dumps({"title": doc["title"], "sha256": doc["sha256"]}))
    if doc is None:
        abort(404)
    flash("Document deleted.", "ok")
    return redirect(url_for("documents.list_documents"))


@bp.route("/documents/<int:doc_id>/grants", methods=["POST"])
@login_required
def add_grant(doc_id):
    username = request.form.get("username", "").strip().lower()[:50]
    permission = request.form.get("permission", "")

    with get_conn() as conn:
        doc = authorize(conn, g.user, doc_id, "share")
        if doc is not None:
            target = conn.execute(
                "SELECT id, username FROM users WHERE username = %s AND is_active",
                (username,),
            ).fetchone()
            if permission not in ("read", "edit"):
                flash("Choose read or edit.", "error")
            elif target is None:
                flash("There is no active user with that username.", "error")
            elif target["id"] == g.user["id"]:
                flash("You already own this document.", "error")
            else:
                existing = conn.execute(
                    "SELECT id, permission FROM grants "
                    "WHERE document_id = %s AND user_id = %s AND revoked_at IS NULL",
                    (doc_id, target["id"]),
                ).fetchone()
                if existing:
                    conn.execute("UPDATE grants SET permission = %s WHERE id = %s",
                                 (permission, existing["id"]))
                    action = "grant.change"
                    detail = f"{existing['permission']} -> {permission}"
                else:
                    conn.execute(
                        "INSERT INTO grants (document_id, user_id, permission, granted_by) "
                        "VALUES (%s, %s, %s, %s)",
                        (doc_id, target["id"], permission, g.user["id"]),
                    )
                    action = "grant.add"
                    detail = permission
                audit.record(conn, action, document_id=doc_id,
                             target_user_id=target["id"], detail=detail)
                flash(f"{target['username']} now has {permission} access.", "ok")
    if doc is None:
        abort(404)
    return redirect(url_for("documents.view_document", doc_id=doc_id))


@bp.route("/documents/<int:doc_id>/grants/<int:grant_id>/revoke", methods=["POST"])
@login_required
def revoke_grant(doc_id, grant_id):
    with get_conn() as conn:
        doc = authorize(conn, g.user, doc_id, "share")
        if doc is not None:
            # "document_id = doc_id" stops an owner revoking a grant that
            # belongs to somebody else's document.
            row = conn.execute(
                "UPDATE grants SET revoked_at = now(), revoked_by = %s "
                "WHERE id = %s AND document_id = %s AND revoked_at IS NULL "
                "RETURNING user_id",
                (g.user["id"], grant_id, doc_id),
            ).fetchone()
            if row is not None:
                audit.record(conn, "grant.revoke", document_id=doc_id,
                             target_user_id=row["user_id"])
                flash("Access removed. It stops working immediately.", "ok")
            else:
                flash("That grant was not found.", "error")
    if doc is None:
        abort(404)
    return redirect(url_for("documents.view_document", doc_id=doc_id))