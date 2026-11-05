"""The audit trail: what is recorded, and that tampering is detected."""
import threading
from contextlib import contextmanager

import psycopg
import pytest

import audit
from db import get_conn
from helpers import (active_grant_id, give, login, make_doc, post, query, text, unique)


@contextmanager
def tampered(row_id, new_username):
    """Change one old audit row behind the application's back (the way an
    attacker with database access would), then put it back."""
    original = query("SELECT actor_username FROM audit_log WHERE id = %s", row_id)[0]["actor_username"]
    with get_conn() as conn:
        conn.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change")
        conn.execute("UPDATE audit_log SET actor_username = %s WHERE id = %s", (new_username, row_id))
        conn.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_change")
    try:
        yield
    finally:
        with get_conn() as conn:
            conn.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change")
            conn.execute("UPDATE audit_log SET actor_username = %s WHERE id = %s", (original, row_id))
            conn.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_change")


def a_middle_row_id():
    rows = query("SELECT id FROM audit_log ORDER BY id")
    return rows[len(rows) // 2]["id"]


# ------------------------------------------------------------------ what gets recorded

def test_every_kind_of_document_action_is_recorded(alice, carol):
    doc = make_doc(alice, title=unique("audited"))
    carol.get(f"/documents/{doc}")                                   # refused
    give(alice, doc, "carol", "edit")
    carol.get(f"/documents/{doc}/download")
    post(carol, f"/documents/{doc}/edit", title=unique("renamed"), category="Other")
    post(alice, f"/documents/{doc}/grants/{active_grant_id(doc, 'carol')}/revoke")
    post(alice, f"/documents/{doc}/delete")

    rows = query("SELECT action, outcome, actor_username FROM audit_log WHERE document_id = %s", doc)
    seen = {(r["action"], r["outcome"], r["actor_username"]) for r in rows}
    assert ("doc.upload", "ok", "alice") in seen
    assert ("doc.read", "denied", "carol") in seen            # the refused attempt
    assert ("grant.add", "ok", "alice") in seen
    assert ("doc.download", "ok", "carol") in seen
    assert ("doc.edit", "ok", "carol") in seen
    assert ("grant.revoke", "ok", "alice") in seen
    assert ("doc.delete", "ok", "alice") in seen


def test_login_logout_and_failures_are_recorded(app, alice):
    from helpers import try_login
    try_login(app, "alice", "wrong-password")
    post(alice, "/logout")
    actions = {r["action"] for r in query("SELECT action FROM audit_log WHERE actor_username = 'alice'")}
    assert {"login.ok", "login.fail", "logout"} <= actions


def test_download_record_names_the_exact_file(alice):
    doc = make_doc(alice, title=unique("fp"), data=b"fingerprint me")
    alice.get(f"/documents/{doc}/download")
    detail = query("SELECT detail FROM audit_log WHERE document_id = %s AND action = 'doc.download'", doc)[0]["detail"]
    assert "sha256" in detail


def test_a_refusal_is_saved_even_if_the_caller_crashes_afterwards(app):
    from flask import g

    from authz import authorize
    doc = query("SELECT id FROM documents LIMIT 1")[0]["id"]
    before = query("SELECT count(*) n FROM audit_log WHERE outcome = 'denied' AND actor_username = 'ghost'")[0]["n"]
    with pytest.raises(RuntimeError):
        with app.test_request_context("/"):
            g.user = {"id": 999999, "username": "ghost"}
            with get_conn() as conn:
                authorize(conn, g.user, doc, "read")
                raise RuntimeError("the route blew up after authorize()")
    after = query("SELECT count(*) n FROM audit_log WHERE outcome = 'denied' AND actor_username = 'ghost'")[0]["n"]
    assert after == before + 1


# ------------------------------------------------------------------ the chain

def test_chain_verifies(alice):
    make_doc(alice, title=unique("chain"))
    with get_conn() as conn:
        ok, checked, bad = audit.verify_chain(conn)
    assert ok and checked > 10 and bad is None


@pytest.mark.parametrize("statement", [
    "UPDATE audit_log SET outcome = 'ok' WHERE id = 1",
    "DELETE FROM audit_log WHERE id = 1",
    "TRUNCATE audit_log",
])
def test_the_database_refuses_to_change_or_remove_audit_rows(app, statement):
    with pytest.raises(psycopg.Error) as caught:
        with get_conn() as conn:
            conn.execute(statement)
    assert "append-only" in str(caught.value)


def test_changing_an_old_row_is_detected_at_that_row(app):
    row_id = a_middle_row_id()
    with tampered(row_id, "someone_else"):
        with get_conn() as conn:
            ok, checked, bad = audit.verify_chain(conn)
        assert not ok and bad == row_id
    with get_conn() as conn:
        assert audit.verify_chain(conn)[0]          # restored, chain fine again


def test_writers_that_run_at_the_same_time_keep_one_chain(app):
    def worker(n):
        with app.test_request_context("/"):
            for i in range(3):
                with get_conn() as conn:
                    audit.record(conn, "test.concurrent", detail=f"{n}-{i}")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with get_conn() as conn:
        assert audit.verify_chain(conn)[0]
    assert query("SELECT count(*) n FROM audit_log WHERE action = 'test.concurrent'")[0]["n"] == 12


# ------------------------------------------------------------------ the admin page

@pytest.mark.parametrize("who", ["alice", "bob", "carol", "dave"])
def test_only_admin_can_open_the_audit_pages(app, who):
    client = login(app, who)
    assert client.get("/admin/audit").status_code == 404
    assert post(client, "/admin/audit/verify").status_code == 404


def test_admin_sees_the_trail_and_can_filter_it(admin, alice):
    make_doc(alice, title=unique("shown"))
    page = admin.get("/admin/audit")
    assert page.status_code == 200 and "doc.upload" in text(page)

    denied = text(admin.get("/admin/audit?outcome=denied")).split("<table>")[-1]
    assert "doc.upload" not in denied and "denied" in denied
    by_user = text(admin.get("/admin/audit?username=alice")).split("<table>")[-1]
    assert "alice" in by_user


def test_hostile_filter_values_do_not_break_the_page(admin):
    response = admin.get("/admin/audit", query_string={
        "action": "x' OR '1'='1", "username": "'; DROP TABLE users;--",
        "outcome": "zzz", "page": "abc"})
    assert response.status_code == 200
    assert query("SELECT count(*) n FROM users")[0]["n"] >= 5
    assert admin.get("/admin/audit?page=99999").status_code == 200


def test_verify_button_reports_ok_and_is_itself_recorded(admin):
    response = post(admin, "/admin/audit/verify")
    assert response.status_code == 302
    assert "Chain intact" in text(admin.get("/admin/audit"))
    assert query("SELECT count(*) n FROM audit_log WHERE action = 'audit.verify'")[0]["n"] >= 1


def test_verify_button_needs_the_csrf_token(admin):
    assert admin.post("/admin/audit/verify", data={}).status_code == 400


def test_verify_button_reports_tampering(admin):
    with tampered(a_middle_row_id(), "someone_else"):
        post(admin, "/admin/audit/verify")
        assert "CHAIN BROKEN" in text(admin.get("/admin/audit"))