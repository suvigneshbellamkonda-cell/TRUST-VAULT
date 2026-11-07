"""Who may open, change, share and delete a document."""
import hashlib
import io
import re
import zipfile

import pytest

import uploads

from helpers import (active_grant_id, csrf, give, login, make_doc, make_user, post,
                     query, text, unique, upload)


# ------------------------------------------------------------------ the main rule
# A person with NO grant must get 404 on every route, and nothing may change.

@pytest.fixture(scope="module")
def secret(app):
    """A document owned by alice, shared with one throwaway user."""
    alice = login(app, "alice")
    title = unique("secret")
    doc = make_doc(alice, title=title, data=b"TOP SECRET PLAN")
    grantee, _ = make_user(role="viewer")
    assert give(alice, doc, grantee, "read").status_code == 302
    return {"doc": doc, "title": title, "gid": active_grant_id(doc, grantee)}


ROUTES = {
    "view":     ("get",  "/documents/{doc}", {}),
    "download": ("get",  "/documents/{doc}/download", {}),
    "open":     ("get",  "/documents/{doc}/open", {}),
    "edit":     ("post", "/documents/{doc}/edit", {"title": "hacked", "category": "Other"}),
    "delete":   ("post", "/documents/{doc}/delete", {}),
    "grant":    ("post", "/documents/{doc}/grants", {"username": "{who}", "permission": "edit"}),
    "revoke":   ("post", "/documents/{doc}/grants/{gid}/revoke", {}),
}


@pytest.mark.parametrize("route", list(ROUTES))
@pytest.mark.parametrize("who", ["bob", "carol", "dave", "admin"])
def test_no_grant_means_404_and_nothing_changes(app, secret, who, route):
    client = login(app, who)
    method, url, form = ROUTES[route]
    url = url.format(doc=secret["doc"], gid=secret["gid"])
    form = {k: v.format(who=who) for k, v in form.items()}

    if method == "get":
        response = client.get(url)
    else:
        response = post(client, url, **form)
    assert response.status_code == 404

    row = query("SELECT title, deleted_at FROM documents WHERE id = %s", secret["doc"])[0]
    assert row["title"] == secret["title"] and row["deleted_at"] is None
    grants = query("SELECT user_id FROM grants WHERE document_id = %s AND revoked_at IS NULL",
                   secret["doc"])
    assert len(grants) == 1                      # still only the throwaway grantee


@pytest.mark.parametrize("who", ["bob", "carol", "admin"])
def test_list_does_not_show_other_peoples_documents(app, secret, who):
    assert secret["title"] not in text(login(app, who).get("/documents"))


def test_forbidden_and_nonexistent_look_identical(bob, secret):
    strip = lambda r: re.sub(r'value="[0-9a-f]+"', "", text(r))
    forbidden = bob.get(f"/documents/{secret['doc']}")
    missing = bob.get("/documents/999999")
    assert forbidden.status_code == missing.status_code == 404
    assert strip(forbidden) == strip(missing)


def test_anonymous_visitors_are_sent_to_login(anon, secret):
    for url in (f"/documents/{secret['doc']}", f"/documents/{secret['doc']}/download",
                f"/documents/{secret['doc']}/open", "/documents", "/documents/upload", "/", "/admin/users", "/admin/audit"):
        response = anon.get(url)
        assert response.status_code == 302 and "/login" in response.location, url


def test_anonymous_posts_are_refused(anon, secret):
    for url in (f"/documents/{secret['doc']}/edit", f"/documents/{secret['doc']}/delete",
                f"/documents/{secret['doc']}/grants", "/documents/upload",
                "/admin/users", "/admin/audit/verify"):
        assert anon.post(url, data={}).status_code in (302, 400), url


def test_refused_attempt_is_written_to_the_audit_log(app, secret):
    carol = login(app, "carol")
    before = query("SELECT count(*) n FROM audit_log WHERE actor_username = 'carol' "
                   "AND outcome = 'denied' AND document_id = %s", secret["doc"])[0]["n"]
    assert carol.get(f"/documents/{secret['doc']}").status_code == 404
    after = query("SELECT count(*) n FROM audit_log WHERE actor_username = 'carol' "
                  "AND outcome = 'denied' AND document_id = %s", secret["doc"])[0]["n"]
    assert after == before + 1


# ------------------------------------------------------------------ who can upload

def test_only_owners_can_upload(alice, bob, carol, dave, admin):
    for outsider in (admin, carol, dave):             # administrator and viewers
        assert outsider.get("/documents/upload").status_code == 404
        assert upload(outsider).status_code == 404
    for person in (alice, bob):                        # owners
        assert person.get("/documents/upload").status_code == 200


def test_an_owner_owns_the_file_and_can_share_it_with_a_viewer(bob, dave, alice):
    title = unique("ownerdoc")
    doc = make_doc(bob, title=title, data=b"BOBS FILE")
    assert query("SELECT u.username FROM documents d JOIN users u ON u.id = d.owner_id "
                 "WHERE d.id = %s", doc)[0]["username"] == "bob"
    assert dave.get(f"/documents/{doc}").status_code == 404           # nobody else sees it
    assert give(bob, doc, "dave", "read").status_code == 302           # he can share it
    assert dave.get(f"/documents/{doc}/download").data == b"BOBS FILE"
    assert post(dave, f"/documents/{doc}/delete").status_code == 404   # dave cannot delete
    assert post(bob, f"/documents/{doc}/delete").status_code == 302    # bob can


def test_documents_can_be_shared_only_with_viewers(alice, bob):
    doc = make_doc(alice, title=unique("viewersonly"))
    give(alice, doc, "bob", "read")                                    # bob is an owner
    assert active_grant_id(doc, "bob") is None


def test_owner_is_always_the_logged_in_user(alice):
    carol_id = query("SELECT id FROM users WHERE username = 'carol'")[0]["id"]
    title = unique("owner")
    response = upload(alice, title=title, owner_id=str(carol_id))   # forged field
    assert response.status_code == 302
    row = query("SELECT u.username FROM documents d JOIN users u ON u.id = d.owner_id "
                "WHERE d.title = %s", title)[0]
    assert row["username"] == "alice"


# ------------------------------------------------------------------ read access

def test_read_grant_allows_view_and_download_only(alice, carol):
    title = unique("readonly")
    doc = make_doc(alice, title=title, data=b"THE BYTES")
    assert carol.get(f"/documents/{doc}").status_code == 404

    assert give(alice, doc, "carol", "read").status_code == 302
    page = carol.get(f"/documents/{doc}")
    assert page.status_code == 200
    for hidden in ("Give access", "Edit details", "Delete document", "Who has access"):
        assert hidden not in text(page)
    assert carol.get(f"/documents/{doc}/download").data == b"THE BYTES"
    assert title in text(carol.get("/documents"))

    gid = active_grant_id(doc, "carol")
    assert post(carol, f"/documents/{doc}/edit", title="x", category="Other").status_code == 404
    assert post(carol, f"/documents/{doc}/delete").status_code == 404
    assert give(carol, doc, "dave", "read").status_code == 404
    assert post(carol, f"/documents/{doc}/grants/{gid}/revoke").status_code == 404
    assert query("SELECT title FROM documents WHERE id = %s", doc)[0]["title"] == title


def test_edit_grant_can_change_details_but_not_owner_delete_or_share(alice, carol):
    doc = make_doc(alice, title=unique("editable"))
    give(alice, doc, "carol", "edit")
    carol_id = query("SELECT id FROM users WHERE username = 'carol'")[0]["id"]

    new_title = unique("renamed")
    response = post(carol, f"/documents/{doc}/edit", title=new_title, category="Drawing",
                    owner_id=str(carol_id))                          # forged field
    assert response.status_code == 302
    row = query("SELECT title, category, owner_id FROM documents WHERE id = %s", doc)[0]
    assert (row["title"], row["category"]) == (new_title, "Drawing")
    assert row["owner_id"] != carol_id

    assert post(carol, f"/documents/{doc}/delete").status_code == 404
    assert give(carol, doc, "dave", "read").status_code == 404
    assert "Delete document" not in text(carol.get(f"/documents/{doc}"))


def test_edit_rejects_bad_input(alice):
    title = unique("keep")
    doc = make_doc(alice, title=title, category="Contract")
    for form in ({"title": "   ", "category": "Other"},
                 {"title": "x" * 121, "category": "Other"},
                 {"title": "fine", "category": "Hacking"}):
        post(alice, f"/documents/{doc}/edit", **form)
    row = query("SELECT title, category FROM documents WHERE id = %s", doc)[0]
    assert (row["title"], row["category"]) == (title, "Contract")


# ------------------------------------------------------------------ revoke

def test_revoke_works_at_once_in_an_already_logged_in_session(alice, carol):
    title = unique("revoke")
    doc = make_doc(alice, title=title, data=b"data")
    give(alice, doc, "carol", "read")
    assert carol.get(f"/documents/{doc}").status_code == 200       # carol is logged in

    gid = active_grant_id(doc, "carol")
    assert post(alice, f"/documents/{doc}/grants/{gid}/revoke").status_code == 302

    assert carol.get(f"/documents/{doc}").status_code == 404       # same session, now refused
    assert carol.get(f"/documents/{doc}/download").status_code == 404
    assert title not in text(carol.get("/documents"))

    row = query("SELECT revoked_at, revoked_by FROM grants WHERE id = %s", gid)[0]
    assert row["revoked_at"] is not None and row["revoked_by"] is not None   # history is kept

    give(alice, doc, "carol", "read")                              # can be granted again
    assert carol.get(f"/documents/{doc}").status_code == 200
    assert query("SELECT count(*) n FROM grants WHERE document_id = %s", doc)[0]["n"] == 2


def test_cannot_revoke_a_grant_that_belongs_to_another_document(alice, bob, dave):
    bobs_doc = make_doc(bob, title=unique("bobs"))
    give(bob, bobs_doc, "dave", "read")
    bobs_grant = active_grant_id(bobs_doc, "dave")
    alices_doc = make_doc(alice, title=unique("alices"))

    post(alice, f"/documents/{alices_doc}/grants/{bobs_grant}/revoke")   # guessed id
    assert query("SELECT revoked_at FROM grants WHERE id = %s", bobs_grant)[0]["revoked_at"] is None
    assert dave.get(f"/documents/{bobs_doc}/download").status_code == 200


# ------------------------------------------------------------------ granting

def _flash_after_grant(client, doc, username, permission):
    response = client.post(f"/documents/{doc}/grants", follow_redirects=True, data={
        "csrf_token": csrf(client), "username": username, "permission": permission})
    return text(response)


def test_grant_input_is_checked(alice):
    doc = make_doc(alice, title=unique("grants"))
    disabled, _ = make_user(active=False)
    cases = [
        ("nobody_here", "read", "no active user"),
        (disabled, "read", "no active user"),
        ("alice", "read", "already own"),
        ("carol", "superuser", "Choose read or edit"),
    ]
    for username, permission, message in cases:
        assert message in _flash_after_grant(alice, doc, username, permission)
    assert query("SELECT count(*) n FROM grants WHERE document_id = %s", doc)[0]["n"] == 0


def test_changing_a_grant_updates_it_instead_of_adding_another(alice):
    doc = make_doc(alice, title=unique("change"))
    give(alice, doc, "carol", "read")
    give(alice, doc, "carol", "edit")
    rows = query("SELECT permission FROM grants WHERE document_id = %s AND revoked_at IS NULL", doc)
    assert [r["permission"] for r in rows] == ["edit"]


def test_grant_for_a_user_who_is_later_disabled_stops_working(app, alice, admin):
    username, password = make_user(role="viewer")
    doc = make_doc(alice, title=unique("disable"))
    give(alice, doc, username, "read")
    from helpers import try_login
    client, response = try_login(app, username, password)
    assert response.status_code == 302
    assert client.get(f"/documents/{doc}").status_code == 200

    user_id = query("SELECT id FROM users WHERE username = %s", username)[0]["id"]
    post(admin, f"/admin/users/{user_id}/toggle")                  # disable
    assert client.get(f"/documents/{doc}").status_code == 302      # kicked out at once
    post(admin, f"/admin/users/{user_id}/toggle")                  # enable again
    assert client.get(f"/documents/{doc}").status_code == 302      # old cookie stays dead


# ------------------------------------------------------------------ delete

def test_delete_hides_the_document_from_everyone_but_keeps_the_row(alice, carol):
    title = unique("delete")
    doc = make_doc(alice, title=title)
    give(alice, doc, "carol", "edit")
    assert carol.get(f"/documents/{doc}").status_code == 200

    assert post(alice, f"/documents/{doc}/delete").status_code == 302
    for client in (alice, carol):
        assert client.get(f"/documents/{doc}").status_code == 404
        assert client.get(f"/documents/{doc}/download").status_code == 404
        assert title not in text(client.get("/documents"))
    assert post(alice, f"/documents/{doc}/edit", title="x", category="Other").status_code == 404
    assert give(alice, doc, "dave", "read").status_code == 404
    assert query("SELECT deleted_at FROM documents WHERE id = %s", doc)[0]["deleted_at"] is not None


# ------------------------------------------------------------------ CSRF

def test_every_document_form_needs_the_csrf_token(alice):
    title = unique("csrf")
    doc = make_doc(alice, title=title)
    give(alice, doc, "carol", "read")
    gid = active_grant_id(doc, "carol")

    assert alice.post(f"/documents/{doc}/edit", data={"title": "x", "category": "Other"}).status_code == 400
    assert alice.post(f"/documents/{doc}/delete", data={}).status_code == 400
    assert alice.post(f"/documents/{doc}/grants", data={"username": "dave", "permission": "read"}).status_code == 400
    assert alice.post(f"/documents/{doc}/grants/{gid}/revoke", data={}).status_code == 400
    assert alice.post("/documents/upload", content_type="multipart/form-data", data={
        "title": "t", "category": "Other", "file": (io.BytesIO(b"x"), "a.txt")}).status_code == 400

    assert query("SELECT title, deleted_at FROM documents WHERE id = %s", doc)[0]["title"] == title
    assert active_grant_id(doc, "carol") == gid
    assert active_grant_id(doc, "dave") is None


def test_a_wrong_csrf_token_is_refused(alice):
    doc = make_doc(alice, title=unique("csrf2"))
    response = alice.post(f"/documents/{doc}/delete", data={"csrf_token": "0" * 32})
    assert response.status_code == 400
    assert query("SELECT deleted_at FROM documents WHERE id = %s", doc)[0]["deleted_at"] is None


# ------------------------------------------------------------------ uploads

def _zip(*names):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for name in names:
            z.writestr(name, "<x/>")
    return buffer.getvalue()


REFUSED = [
    # (file name, file bytes, what the error message must say)
    ("x.html", b"<script>alert(1)</script>", "not allowed"),
    ("x.svg", b"<svg onload=alert(1)>", "not allowed"),
    ("x.exe", b"MZ\x90\x00", "not allowed"),
    ("README", b"no extension", "not allowed"),
    ("x.txt.html", b"abc", "not allowed"),
    ("x.pdf", b"<html>not a pdf</html>", "do not match"),
    ("x.png", b"not a png", "do not match"),
    ("x.jpg", b"not a jpeg", "do not match"),
    ("x.txt", b"has\x00nul", "do not match"),
    ("x.txt", b"\xff\xfe\xfa", "do not match"),
    ("x.txt", b"", "empty"),
    ("x.docx", _zip("evil.txt"), "do not match"),
    ("x.xlsx", _zip("[Content_Types].xml", "word/document.xml"), "do not match"),
]


@pytest.mark.parametrize("name,data,message", REFUSED)
def test_bad_files_are_refused_and_not_stored(alice, name, data, message):
    title = unique("bad")
    response = upload(alice, title=title, name=name, data=data)
    assert response.status_code == 400
    assert message in text(response)
    assert query("SELECT count(*) n FROM documents WHERE title = %s", title)[0]["n"] == 0


ACCEPTED = [
    ("a.pdf", b"%PDF-1.4 hi"),
    ("a.png", b"\x89PNG\r\n\x1a\nxxxx"),
    ("a.jpg", b"\xff\xd8\xff\xe0abc"),
    ("a.csv", b"a,b\n1,2\n"),
    ("a.txt", "héllo".encode()),
    ("a.docx", _zip("[Content_Types].xml", "word/document.xml")),
    ("a.xlsx", _zip("[Content_Types].xml", "xl/workbook.xml")),
]


@pytest.mark.parametrize("name,data", ACCEPTED)
def test_real_files_are_accepted(alice, name, data):
    assert upload(alice, title=unique("ok"), name=name, data=data).status_code == 302


def test_title_and_category_are_checked(alice):
    assert upload(alice, title="   ").status_code == 400
    assert upload(alice, title="x" * 121).status_code == 400
    assert upload(alice, category="Hacking").status_code == 400


def test_there_is_no_limit_per_file(alice):
    title = unique("big")
    response = upload(alice, title=title, name="big.txt", data=b"a" * (12 * 1024 * 1024))
    assert response.status_code == 302


def test_a_file_over_the_total_limit_is_refused_with_a_clear_message(alice, monkeypatch):
    monkeypatch.setattr(uploads, "MAX_BATCH_BYTES", 1024 * 1024)       # a small limit, to keep the test quick
    title = unique("toobig")
    response = upload(alice, title=title, data=b"a" * (1024 * 1024 + 1))
    assert response.status_code == 400
    assert "more than 100 MB" in text(response)
    assert query("SELECT count(*) n FROM documents WHERE title = %s", title)[0]["n"] == 0


def test_a_request_over_the_cap_gets_the_413_page(app, alice, monkeypatch):
    monkeypatch.setitem(app.config, "MAX_CONTENT_LENGTH", 1024 * 1024)
    response = upload(alice, title=unique("huge"), data=b"a" * (2 * 1024 * 1024))
    assert response.status_code == 413
    assert "100 MB in total" in text(response)


# ------------------------------------------------------------------ several files at once

def upload_many(client, files, category="Contract", title=""):
    """files = [(name, bytes), ...] sent under the same form field, as the browser does."""
    form = {"csrf_token": csrf(client), "title": title, "category": category,
            "file": [(io.BytesIO(data), name) for name, data in files]}
    return client.post("/documents/upload", data=form, content_type="multipart/form-data")


def test_several_files_are_all_stored_owned_and_audited(alice):
    stem = unique("batch")
    names = [f"{stem}-{n}.txt" for n in "abc"]
    response = upload_many(alice, [(n, f"text {n}".encode()) for n in names])
    assert response.status_code == 302 and response.location.endswith("/documents")
    rows = query("SELECT id, title, filename, owner_id FROM documents WHERE title LIKE %s ORDER BY id",
                 stem + "%")
    assert len(rows) == 3
    assert {r["title"] for r in rows} == {f"{stem}-{n}" for n in "abc"}   # titles come from file names
    owner = query("SELECT id FROM users WHERE username = 'alice'")[0]["id"]
    assert all(r["owner_id"] == owner for r in rows)
    for r in rows:
        logged = query("SELECT count(*) n FROM audit_log WHERE action = 'doc.upload' "
                       "AND outcome = 'ok' AND document_id = %s", r["id"])[0]["n"]
        assert logged == 1


def test_typed_title_is_put_in_front_of_every_file_name_and_found_by_search(alice):
    word = unique("test")
    stem = unique("report")
    response = upload_many(alice, [(f"{stem}-{n}.txt", b"x") for n in "ab"], title=word)
    assert response.status_code == 302
    rows = query("SELECT title FROM documents WHERE title LIKE %s ORDER BY id", word + "%")
    assert {r["title"] for r in rows} == {f"{word} - {stem}-{n}" for n in "ab"}
    page = text(alice.get(f"/documents?title={word}"))
    assert f"{word} - {stem}-a" in page and f"{word} - {stem}-b" in page
    assert f"{word} - {stem}-a" in text(alice.get(f"/documents?title={stem}"))   # file name still finds it


def test_a_too_long_typed_title_is_refused_for_several_files(alice):
    stem = unique("longtitle")
    response = upload_many(alice, [(f"{stem}-{n}.txt", b"x") for n in "ab"], title="x" * 121)
    assert response.status_code == 400
    assert query("SELECT count(*) n FROM documents WHERE title LIKE %s", "%" + stem + "%")[0]["n"] == 0


def test_fifty_one_files_are_refused_and_none_are_saved(alice):
    stem = unique("toomany")
    response = upload_many(alice, [(f"{stem}-{n}.txt", b"x") for n in range(51)])
    assert response.status_code == 400
    assert "at most 50 files" in text(response)
    assert query("SELECT count(*) n FROM documents WHERE title LIKE %s", stem + "%")[0]["n"] == 0


def test_ten_files_are_accepted(alice):
    stem = unique("ten")
    response = upload_many(alice, [(f"{stem}-{n}.txt", b"x") for n in range(10)])
    assert response.status_code == 302
    assert query("SELECT count(*) n FROM documents WHERE title LIKE %s", stem + "%")[0]["n"] == 10


def test_one_bad_file_means_none_are_saved_and_the_bad_one_is_named(alice):
    stem = unique("mixed")
    response = upload_many(alice, [(f"{stem}-good.txt", b"fine"),
                                   (f"{stem}-bad.pdf", b"this is not a pdf"),
                                   (f"{stem}-also-good.txt", b"fine too")])
    assert response.status_code == 400
    assert f"{stem}-bad.pdf" in text(response)
    assert "do not match" in text(response)
    assert query("SELECT count(*) n FROM documents WHERE title LIKE %s", stem + "%")[0]["n"] == 0


def test_files_over_the_total_limit_together_are_refused(alice, monkeypatch):
    monkeypatch.setattr(uploads, "MAX_BATCH_BYTES", 1024 * 1024)
    stem = unique("heavy")
    chunk = b"a" * (600 * 1024)
    response = upload_many(alice, [(f"{stem}-{n}.txt", chunk) for n in range(3)])
    assert response.status_code == 400
    assert "100 MB together" in text(response)
    assert query("SELECT count(*) n FROM documents WHERE title LIKE %s", stem + "%")[0]["n"] == 0


def test_admin_and_viewers_cannot_upload_several_files_but_an_owner_can(carol, admin, bob):
    assert upload_many(admin, [("a.txt", b"x"), ("b.txt", b"y")]).status_code == 404
    assert upload_many(carol, [("a.txt", b"x"), ("b.txt", b"y")]).status_code == 404
    stem = unique("ownerbatch")
    assert upload_many(bob, [(f"{stem}-a.txt", b"x"), (f"{stem}-b.txt", b"y")]).status_code == 302
    assert query("SELECT count(*) n FROM documents WHERE title LIKE %s", stem + "%")[0]["n"] == 2


def test_several_files_need_a_valid_category(alice):
    stem = unique("cat")
    response = upload_many(alice, [(f"{stem}-a.txt", b"x"), (f"{stem}-b.txt", b"y")], category="Nonsense")
    assert response.status_code == 400
    assert query("SELECT count(*) n FROM documents WHERE title LIKE %s", stem + "%")[0]["n"] == 0


def test_stored_file_is_exact_and_fingerprinted(alice):
    doc = make_doc(alice, title=unique("hash"), data=b"TOP SECRET PLAN")
    row = query("SELECT sha256, content FROM documents WHERE id = %s", doc)[0]
    assert bytes(row["content"]) == b"TOP SECRET PLAN"
    assert row["sha256"] == hashlib.sha256(b"TOP SECRET PLAN").hexdigest()


def test_filename_cannot_climb_folders_or_carry_markup(alice):
    doc = make_doc(alice, title=unique("trav"), name="../../etc/passwd.txt")
    assert query("SELECT filename FROM documents WHERE id = %s", doc)[0]["filename"] == "passwd.txt"
    doc = make_doc(alice, title=unique("odd"), name="a<img src=x onerror=alert(1)>.txt")
    name = query("SELECT filename FROM documents WHERE id = %s", doc)[0]["filename"]
    assert re.fullmatch(r"[A-Za-z0-9._ -]+\.txt", name)


def test_titles_are_escaped_so_scripts_cannot_run(alice):
    marker = unique("xss")
    title = f"<script>alert('{marker}')</script>"
    doc = make_doc(alice, title=title)
    for page in (alice.get("/documents"), alice.get(f"/documents/{doc}")):
        assert title not in text(page)
        assert "&lt;script&gt;" in text(page)


def test_download_headers_make_it_a_safe_download(alice):
    doc = make_doc(alice, title=unique("headers"), data=b"hello", name="note.txt")
    response = alice.get(f"/documents/{doc}/download")
    assert response.data == b"hello"
    assert response.headers["Content-Disposition"] == 'attachment; filename="note.txt"'
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert "sandbox" in response.headers["Content-Security-Policy"]
    assert response.mimetype == "text/plain"


# ------------------------------------------------------------------ upload page script

def test_upload_page_loads_its_script_and_the_policy_allows_it(alice):
    page = alice.get("/documents/upload")
    body = text(page)
    assert '/static/upload.js' in body
    assert "<script>" not in body                      # no inline script anywhere
    policy = page.headers["Content-Security-Policy"]
    assert "script-src" not in policy and "default-src 'self'" in policy
    script = alice.get("/static/upload.js")
    assert script.status_code == 200 and "javascript" in script.headers["Content-Type"]
    assert "innerHTML" not in text(script)             # file names are shown as text only


# ------------------------------------------------------------------ opening a file in the browser

def test_open_shows_the_file_inline_with_safe_headers(alice):
    doc = make_doc(alice, data=b"HELLO OPEN")
    response = alice.get(f"/documents/{doc}/open")
    assert response.status_code == 200 and response.data == b"HELLO OPEN"
    assert response.headers["Content-Disposition"].startswith("inline")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert "sandbox" in response.headers["Content-Security-Policy"]
    assert response.mimetype == "text/plain"


def test_open_is_audited_and_the_document_page_has_the_button(alice):
    doc = make_doc(alice)
    assert alice.get(f"/documents/{doc}/open").status_code == 200
    n = query("SELECT count(*) n FROM audit_log WHERE action = 'doc.open' AND outcome = 'ok' "
              "AND document_id = %s", doc)[0]["n"]
    assert n == 1
    assert f"/documents/{doc}/open" in text(alice.get(f"/documents/{doc}"))


def test_a_person_with_a_read_grant_can_open_but_others_cannot(alice, carol, bob):
    doc = make_doc(alice, data=b"SHARED TEXT")
    assert bob.get(f"/documents/{doc}/open").status_code == 404
    assert give(alice, doc, "carol", "read").status_code == 302
    assert carol.get(f"/documents/{doc}/open").data == b"SHARED TEXT"
    assert f"/documents/{doc}/open" in text(carol.get(f"/documents/{doc}"))
    gid = active_grant_id(doc, "carol")
    assert post(alice, f"/documents/{doc}/grants/{gid}/revoke").status_code == 302
    assert carol.get(f"/documents/{doc}/open").status_code == 404


def test_word_files_cannot_be_shown_so_open_sends_them_to_download(alice):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>")
    doc = make_doc(alice, name="letter.docx", data=buf.getvalue())
    response = alice.get(f"/documents/{doc}/open")
    assert response.status_code == 302 and response.location.endswith(f"/documents/{doc}/download")
    assert f"/documents/{doc}/open" not in text(alice.get(f"/documents/{doc}"))