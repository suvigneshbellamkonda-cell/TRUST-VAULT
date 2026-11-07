"""The notification bell: add one, clear the ones that no longer apply."""


def add(conn, user_id, message, link, document_id=None):
    conn.execute(
        "INSERT INTO notifications (user_id, message, link, document_id) "
        "VALUES (%s, %s, %s, %s)", (user_id, message[:200], link, document_id))


def clear_for_document(conn, document_id, user_id=None):
    """Remove notifications about a document (for one person, or for everyone)."""
    if user_id is None:
        conn.execute("DELETE FROM notifications WHERE document_id = %s", (document_id,))
    else:
        conn.execute("DELETE FROM notifications WHERE document_id = %s AND user_id = %s",
                     (document_id, user_id))