"""The ONE place that decides who may touch a document.

Every document route calls authorize(). The list page uses
visible_documents(). No other file decides access.

Admins get no special access to document contents: they need a grant like
anyone else (separation of duties).
"""
import audit

# Which access levels may do which action.
#   owner = uploaded the document; read / edit = granted by the owner.
ALLOWED = {
    "read":   {"owner", "edit", "read"},
    "edit":   {"owner", "edit"},
    "share":  {"owner"},     # grant, revoke, see who has access
    "delete": {"owner"},
}


def authorize(conn, user, doc_id, action):
    """Return the document if `user` may do `action` on it, otherwise None.

    A refused attempt is written to the audit log. The caller must answer
    404 when this returns None, so a visitor cannot tell "no access" from
    "does not exist".
    """
    doc = conn.execute(
        "SELECT id, owner_id, title, category, filename, mime_type, size_bytes, "
        "sha256, created_at, updated_at "
        "FROM documents WHERE id = %s AND deleted_at IS NULL",
        (doc_id,),
    ).fetchone()

    level = None
    if doc is not None:
        if doc["owner_id"] == user["id"]:
            level = "owner"
        else:
            grant = conn.execute(
                "SELECT permission FROM grants "
                "WHERE document_id = %s AND user_id = %s AND revoked_at IS NULL",
                (doc_id, user["id"]),
            ).fetchone()
            level = grant["permission"] if grant else None

    if level in ALLOWED[action]:   # an unknown action raises KeyError: fails closed
        doc["access"] = level
        return doc

    audit.record(conn, f"doc.{action}", outcome="denied", document_id=doc_id,
                 detail="not found" if doc is None else "no permission")
    conn.commit()   # keep the record even if the caller aborts straight after
    return None


def can(doc, action):
    """For pages: may the person who loaded `doc` do `action`?"""
    return doc["access"] in ALLOWED[action]


def _like(text):
    """Make user text safe to use inside ILIKE: % and _ lose their wildcard meaning."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def visible_documents(conn, user, title=None, category=None, owner=None,
                      date_from=None, date_to=None):
    """Every document this user owns or holds an active grant for, optionally
    narrowed by search. The access rule is part of the SAME query as the
    search, so a search can never return a document the user may not open.

    date_from / date_to are datetime.date values (or None); date_to is inclusive.
    """
    where = ["d.deleted_at IS NULL",
             "(d.owner_id = %(uid)s OR g.id IS NOT NULL)"]
    params = {"uid": user["id"]}
    if title:
        where.append("d.title ILIKE %(title)s ESCAPE '\\'")
        params["title"] = _like(title)
    if category:
        where.append("d.category = %(category)s")
        params["category"] = category
    if owner:
        where.append("(u.full_name ILIKE %(owner)s ESCAPE '\\' OR u.username ILIKE %(owner)s ESCAPE '\\')")
        params["owner"] = _like(owner)
    if date_from:
        where.append("d.created_at >= %(date_from)s")
        params["date_from"] = date_from
    if date_to:
        where.append("d.created_at < (%(date_to)s::date + 1)")
        params["date_to"] = date_to

    return conn.execute(
        "SELECT d.id, d.title, d.category, d.filename, d.size_bytes, d.created_at, "
        "       u.full_name AS owner_name, "
        "       CASE WHEN d.owner_id = %(uid)s THEN 'owner' ELSE g.permission END AS access "
        "FROM documents d "
        "JOIN users u ON u.id = d.owner_id "
        "LEFT JOIN grants g ON g.document_id = d.id AND g.user_id = %(uid)s "
        "                  AND g.revoked_at IS NULL "
        "WHERE " + " AND ".join(where) + " "
        "ORDER BY d.created_at DESC",
        params,
    ).fetchall()