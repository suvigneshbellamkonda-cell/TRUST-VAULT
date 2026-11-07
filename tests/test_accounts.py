"""Invitations, joining, Forgot password, Settings, notifications, stars, the bin and alerts."""
import io
import re
import uuid

import pytest

import mailer
from helpers import (active_grant_id, csrf, give, login, make_doc, make_user, post, query,
                     text, try_login, unique, upload)


@pytest.fixture
def outbox(monkeypatch):
    """Catches every e-mail the app tries to send (nothing really leaves)."""
    sent = []
    monkeypatch.setattr(mailer, "send", lambda to, name, subject, body: sent.append(
        {"to": to, "name": name, "subject": subject, "body": body}) or True)
    return sent


def ip():
    return "10.9." + ".".join(str(b) for b in uuid.uuid4().bytes[:2])


def anon_post(app, path, source_ip, client=None, page=None, **form):
    """POST as a visitor who is not signed in (fetches a CSRF token first)."""
    client = client or app.test_client()
    env = {"REMOTE_ADDR": source_ip}
    html = client.get(page or "/login", environ_base=env).get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)
    form["csrf_token"] = token
    return client, client.post(path, data=form, environ_base=env)


def invite(admin, name="New Person", email=None):
    email = email or f"{unique('p')}@example.com"
    response = post(admin, "/admin/invitations", full_name=name, email=email)
    assert response.status_code == 302
    return email


def link_in(outbox):
    return re.search(r"/join/([A-Za-z0-9_-]+)", outbox[-1]["body"]).group(1)


# ------------------------------------------------------------------ invitations

def test_admin_invites_owners_and_owners_invite_viewers(admin, alice, carol, outbox):
    email = invite(admin)
    assert outbox[-1]["to"] == email and "/join/" in outbox[-1]["body"]
    assert query("SELECT role FROM invitations WHERE email = %s", email)[0]["role"] == "owner"

    viewer_email = f"{unique('v')}@example.com"
    assert post(alice, "/viewers/invitations", full_name="Vee Viewer", email=viewer_email).status_code == 302
    assert query("SELECT role FROM invitations WHERE email = %s", viewer_email)[0]["role"] == "viewer"


def test_nobody_else_can_invite(admin, alice, carol, dave, outbox):
    for who in (alice, carol, dave):
        assert post(who, "/admin/invitations", full_name="X", email="x1@example.com").status_code == 404
    for who in (admin, carol, dave):
        assert post(who, "/viewers/invitations", full_name="X", email="x2@example.com").status_code == 404
        assert who.get("/viewers").status_code == 404
    assert outbox == []


def test_only_a_hash_of_the_link_is_stored(admin, outbox):
    email = invite(admin)
    token = link_in(outbox)
    row = query("SELECT token_hash FROM invitations WHERE email = %s", email)[0]
    assert token not in row["token_hash"] and len(row["token_hash"]) == 64


def join(app, token, source_ip, **over):
    form = {"full_name": "Joined Person", "username": "j_" + uuid.uuid4().hex[:8],
            "password": "Strong@Pass1", "confirm_password": "Strong@Pass1"}
    form.update(over)
    return anon_post(app, f"/join/{token}", source_ip, page=f"/join/{token}", **form)


def test_joining_works_once_and_the_new_owner_can_sign_in(app, admin, outbox):
    invite(admin)
    token, address = link_in(outbox), ip()
    assert app.test_client().get(f"/join/{token}").status_code == 200
    username = "j_" + uuid.uuid4().hex[:8]
    client, response = join(app, token, address, username=username)
    assert response.status_code == 302 and response.location.endswith("/joined")
    assert "Registered successfully" in text(client.get("/joined"))
    row = query("SELECT role, invited_by FROM users WHERE username = %s", username)[0]
    assert row["role"] == "owner" and row["invited_by"] is not None
    assert try_login(app, username, "Strong@Pass1", ip())[1].status_code == 302
    # the same link again: nothing
    assert app.test_client().get(f"/join/{token}").status_code == 404


def test_a_used_link_cannot_create_a_second_account(app, admin, outbox):
    invite(admin)
    token = link_in(outbox)
    client = app.test_client()
    env = {"REMOTE_ADDR": ip()}
    html = client.get(f"/join/{token}", environ_base=env).get_data(as_text=True)   # form opened twice
    tok = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)
    data = {"csrf_token": tok, "full_name": "A", "username": "j_" + uuid.uuid4().hex[:8],
            "password": "Strong@Pass1", "confirm_password": "Strong@Pass1"}
    assert client.post(f"/join/{token}", data=data, environ_base=env).status_code == 302
    data["username"] = "j_" + uuid.uuid4().hex[:8]
    assert client.post(f"/join/{token}", data=data, environ_base=env).status_code == 404
    assert query("SELECT count(*) n FROM users WHERE username = %s", data["username"])[0]["n"] == 0


def test_an_expired_or_made_up_link_is_refused(app, admin, outbox):
    email = invite(admin)
    token = link_in(outbox)
    query("UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE email = %s RETURNING 1", email)
    assert app.test_client().get(f"/join/{token}").status_code == 404
    assert app.test_client().get("/join/not-a-real-token").status_code == 404


@pytest.mark.parametrize("password,message", [
    ("short1!A", None),                     # fine: 8 characters, all rules met -> used below
    ("alllowercase1!", "capital letter"),
    ("NoNumbers!!", "number"),
    ("NoSpecial123", "special character"),
    ("Sh0rt!", "8 to 200"),
])
def test_password_rule_at_joining(app, admin, outbox, password, message):
    invite(admin)
    token = link_in(outbox)
    _, response = join(app, token, ip(), password=password, confirm_password=password)
    if message is None:
        assert response.status_code == 302
    else:
        assert response.status_code == 400 and message in text(response)
        assert app.test_client().get(f"/join/{token}").status_code == 200    # link not used up


def test_mismatch_and_taken_username_do_not_use_up_the_link(app, admin, outbox):
    invite(admin)
    token = link_in(outbox)
    _, response = join(app, token, ip(), confirm_password="Different@1")
    assert response.status_code == 400 and "not the same" in text(response)
    _, response = join(app, token, ip(), username="alice")
    assert response.status_code == 400 and "already taken" in text(response)
    assert app.test_client().get(f"/join/{token}").status_code == 200


def test_the_invited_address_cannot_be_changed_by_the_form(app, admin, outbox):
    email = invite(admin)
    token = link_in(outbox)
    username = "j_" + uuid.uuid4().hex[:8]
    join(app, token, ip(), username=username, email="attacker@example.com", role="admin")
    row = query("SELECT email, role FROM users WHERE username = %s", username)[0]
    assert row["email"] == email and row["role"] == "owner"


def test_inviting_an_existing_address_is_refused_and_a_new_invite_replaces_the_old(admin, outbox):
    response = admin.post("/admin/invitations", follow_redirects=True,
                          data={"csrf_token": csrf(admin), "full_name": "Dup", "email": "alice@trustvault.example"})
    assert "already exists" in text(response) and outbox == []
    email = invite(admin)
    first = link_in(outbox)
    invite(admin, email=email)
    assert re.search(r"/join/", outbox[-1]["body"]) and link_in(outbox) != first


def test_bad_invitation_input_is_refused(admin, outbox):
    for form in ({"full_name": "", "email": "a@example.com"}, {"full_name": "Ok", "email": "nope"}):
        response = admin.post("/admin/invitations", follow_redirects=True,
                              data={"csrf_token": csrf(admin), **form})
        assert "full name" in text(response) or "valid e-mail" in text(response)
    assert outbox == []


def test_without_a_mail_service_the_inviter_is_shown_the_link(admin, monkeypatch):
    monkeypatch.setattr(mailer, "send", lambda *a, **k: False)
    response = admin.post("/admin/invitations", follow_redirects=True,
                          data={"csrf_token": csrf(admin), "full_name": "No Mail", "email": f"{unique('n')}@example.com"})
    assert "not set up" in text(response) and "/join/" in text(response)


def test_the_inviter_is_notified_when_the_invitation_is_accepted(app, admin, outbox):
    invite(admin, name="Accepter")
    token = link_in(outbox)
    join(app, token, ip())
    page = text(admin.get("/notifications"))
    assert "accepted your invitation" in page


def test_admin_and_owner_invitation_pages_have_filters(admin, alice, outbox):
    email = invite(admin)
    assert email in text(admin.get("/admin/users?istatus=pending"))
    assert email not in text(admin.get("/admin/users?istatus=accepted"))
    assert "carol" in text(admin.get("/admin/users?role=viewer"))
    assert "carol" not in text(admin.get("/admin/users?role=owner"))
    assert alice.get("/viewers?status=pending").status_code == 200


# ------------------------------------------------------------------ forgot password

def request_code(app, email, source_ip):
    return anon_post(app, "/forgot", source_ip, page="/forgot", email=email)


def otp_from(outbox):
    return re.search(r"code is (\d{6})", outbox[-1]["body"]).group(1)


def test_forgot_password_with_a_code_sets_a_new_password(app, outbox):
    username, old = make_user()
    address = ip()
    client, response = request_code(app, f"{username}@example.com", address)
    assert response.status_code == 302 and len(outbox) == 1
    otp = otp_from(outbox)
    _, wrong = anon_post(app, "/forgot/code", address, client=client, page="/forgot/code", otp="000000" if otp != "000000" else "111111")
    assert wrong.status_code == 400
    _, good = anon_post(app, "/forgot/code", address, client=client, page="/forgot/code", otp=otp)
    assert good.status_code == 302 and good.location.endswith("/forgot/new")
    _, weak = anon_post(app, "/forgot/new", address, client=client, page="/forgot/new", password="weak", confirm_password="weak")
    assert weak.status_code == 400
    _, done = anon_post(app, "/forgot/new", address, client=client, page="/forgot/new",
                        password="Brand@New9", confirm_password="Brand@New9")
    assert done.status_code == 302
    assert try_login(app, username, "Brand@New9", ip())[1].status_code == 302
    assert try_login(app, username, old, ip())[1].status_code == 401


def test_five_wrong_codes_block_the_right_one(app, outbox):
    username, _ = make_user()
    address = ip()
    client, _ = request_code(app, f"{username}@example.com", address)
    otp = otp_from(outbox)
    bad = "123456" if otp != "123456" else "654321"
    for _ in range(5):
        anon_post(app, "/forgot/code", address, client=client, page="/forgot/code", otp=bad)
    _, response = anon_post(app, "/forgot/code", address, client=client, page="/forgot/code", otp=otp)
    assert response.status_code == 302 and "/forgot/new" not in response.location


def test_an_expired_code_is_refused(app, outbox):
    username, _ = make_user()
    address = ip()
    client, _ = request_code(app, f"{username}@example.com", address)
    otp = otp_from(outbox)
    query("UPDATE password_resets SET expires_at = now() - interval '1 minute' "
          "WHERE user_id = (SELECT id FROM users WHERE username = %s) RETURNING 1", username)
    _, response = anon_post(app, "/forgot/code", address, client=client, page="/forgot/code", otp=otp)
    assert "/forgot/new" not in (response.location or "")


def test_unknown_addresses_and_the_admin_get_the_same_answer_and_no_mail(app, outbox):
    seen = []
    for email in ("nobody@example.com", "admin@trustvault.example"):
        client, response = request_code(app, email, ip())
        assert response.status_code == 302 and response.location.endswith("/forgot/code")
        seen.append(text(client.get("/forgot/code")))
    assert outbox == []
    assert query("SELECT count(*) n FROM password_resets r JOIN users u ON u.id = r.user_id WHERE u.role = 'admin'")[0]["n"] == 0


def test_the_code_is_stored_only_as_a_hash_and_requests_are_limited(app, outbox):
    username, _ = make_user()
    address = ip()
    for _ in range(5):
        request_code(app, f"{username}@example.com", address)
    assert len(outbox) == 3                                  # at most 3 codes per hour per person
    otp = otp_from(outbox)
    assert otp not in query("SELECT otp_hash FROM password_resets ORDER BY id DESC LIMIT 1")[0]["otp_hash"]
    client, response = request_code(app, f"{username}@example.com", address)
    assert response.status_code == 429                       # too many from one address


def test_forgot_password_link_is_on_the_sign_in_page_and_there_is_no_register_link(anon):
    page = text(anon.get("/login"))
    assert "Forgot password?" in page and "Register" not in page


# ------------------------------------------------------------------ settings

def test_every_role_has_settings_profile_and_notifications(admin, alice, carol):
    for who in (admin, alice, carol):
        for path in ("/settings", "/profile", "/notifications"):
            assert who.get(path).status_code == 200
        page = text(who.get("/settings"))
        assert "Change password" in page and 'data-theme-choice="dark"' in page


def test_change_password_signs_out_other_devices_but_not_this_one(app):
    username, password = make_user()
    this_device, _ = try_login(app, username, password, ip())
    other_device, _ = try_login(app, username, password, ip())
    assert this_device.get("/settings").status_code == 200 and other_device.get("/settings").status_code == 200
    response = post(this_device, "/settings/password", current_password=password,
                    new_password="Changed@Pass1", confirm_password="Changed@Pass1")
    assert response.status_code == 302
    assert this_device.get("/settings").status_code == 200           # still signed in
    assert other_device.get("/settings").status_code == 302          # signed out
    assert try_login(app, username, "Changed@Pass1", ip())[1].status_code == 302


@pytest.mark.parametrize("current,new,confirm,message", [
    ("wrong", "Changed@Pass1", "Changed@Pass1", "not correct"),
    ("OLD", "weakpass", "weakpass", "capital"),
    ("OLD", "Changed@Pass1", "Other@Pass12", "not the same"),
    ("OLD", "OLD", "OLD", "different"),
])
def test_change_password_refusals(app, current, new, confirm, message):
    username, password = make_user(password="Old@Pass123")
    client, _ = try_login(app, username, password, ip())
    fix = lambda v: password if v == "OLD" else v
    response = client.post("/settings/password", follow_redirects=True, data={
        "csrf_token": csrf(client), "current_password": fix(current),
        "new_password": fix(new), "confirm_password": fix(confirm)})
    assert message in text(response)
    assert try_login(app, username, password, ip())[1].status_code == 302   # unchanged


def test_changing_a_password_in_the_database_signs_that_user_out_everywhere(app, admin):
    before = query("SELECT session_version FROM users WHERE username = 'admin'")[0]["session_version"]
    assert admin.get("/admin/users").status_code == 200
    query("UPDATE users SET password_hash = password_hash || '' WHERE username = 'admin' RETURNING 1")
    assert query("SELECT session_version FROM users WHERE username = 'admin'")[0]["session_version"] == before   # same hash: no change
    from werkzeug.security import generate_password_hash
    with __import__("db").get_conn() as conn:
        conn.execute("UPDATE users SET password_hash = %s WHERE username = 'admin'",
                     (generate_password_hash("Admin@TV2026"),))               # new hash, same password
    assert admin.get("/admin/users").status_code == 302                       # old cookie is dead


def test_admin_cannot_reset_anyones_password(admin):
    for path in ("/admin/users/2/reset", "/admin/users/2/password", "/admin/reset"):
        assert post(admin, path).status_code in (404, 405)


# ------------------------------------------------------------------ notifications

def note_ids(who_name):
    return query("SELECT n.id, n.message, n.link FROM notifications n JOIN users u ON u.id = n.user_id "
                 "WHERE u.username = %s ORDER BY n.id DESC", who_name)


def test_sharing_notifies_the_recipient_and_the_click_goes_to_the_document(alice, carol):
    title = unique("note")
    doc = make_doc(alice, title=title)
    give(alice, doc, "carol", "read")
    mine = [n for n in note_ids("carol") if title in n["message"]]
    assert len(mine) == 1 and mine[0]["link"] == f"/documents/{doc}"
    assert not [n for n in note_ids("alice") if title in n["message"]]            # not the sender
    response = carol.get(f"/notifications/{mine[0]['id']}/go")
    assert response.status_code == 302 and response.location.endswith(f"/documents/{doc}")
    assert query("SELECT read_at FROM notifications WHERE id = %s", mine[0]["id"])[0]["read_at"] is not None


def test_nobody_can_use_somebody_elses_notification(alice, carol, dave):
    doc = make_doc(alice, title=unique("private-note"))
    give(alice, doc, "carol", "read")
    note = note_ids("carol")[0]
    assert dave.get(f"/notifications/{note['id']}/go").status_code == 404


def test_the_bell_count_shows_and_mark_all_read_clears_it(alice, dave):
    doc = make_doc(alice, title=unique("bell"))
    give(alice, doc, "dave", "read")
    assert 'class="count"' in text(dave.get("/"))
    post(dave, "/notifications/read-all")
    assert 'aria-label="Notifications"' in text(dave.get("/"))


def test_revoking_or_deleting_removes_the_recipients_notifications(alice, carol, dave):
    title = unique("clear")
    doc = make_doc(alice, title=title)
    give(alice, doc, "carol", "read")
    give(alice, doc, "dave", "read")
    post(alice, f"/documents/{doc}/grants/{active_grant_id(doc, 'carol')}/revoke")
    assert not [n for n in note_ids("carol") if title in n["message"]]
    assert [n for n in note_ids("dave") if title in n["message"]]
    post(alice, f"/documents/{doc}/delete")
    assert not [n for n in note_ids("dave") if title in n["message"]]


def test_an_editor_changing_a_document_notifies_the_owner(alice, dave):
    title = unique("edited")
    doc = make_doc(alice, title=title)
    give(alice, doc, "dave", "edit")
    post(dave, f"/documents/{doc}/edit", title=title + "-v2", category="Other")
    assert [n for n in note_ids("alice") if "Dave Iyer edited" in n["message"] and (title + "-v2") in n["message"]]


def test_an_editor_can_replace_the_file_and_a_reader_cannot(alice, carol, dave):
    doc = make_doc(alice, title=unique("replace"), data=b"original")
    give(alice, doc, "dave", "edit")
    give(alice, doc, "carol", "read")
    form = lambda: {"csrf_token": csrf(dave), "title": "Replaced", "category": "Other",
                    "file": (io.BytesIO(b"new content"), "new.txt")}
    assert dave.post(f"/documents/{doc}/edit", data=form(), content_type="multipart/form-data").status_code == 302
    assert dave.get(f"/documents/{doc}/download").data == b"new content"
    assert carol.post(f"/documents/{doc}/edit", data={**form(), "csrf_token": csrf(carol)},
                      content_type="multipart/form-data").status_code == 404
    assert alice.get(f"/documents/{doc}/download").data == b"new content"
    bad = dave.post(f"/documents/{doc}/edit", data={**form(), "file": (io.BytesIO(b"nope"), "x.pdf")},
                    content_type="multipart/form-data", follow_redirects=True)
    assert "do not match" in text(bad)


# ------------------------------------------------------------------ stars and pages

def test_starring_works_for_readable_documents_only(alice, bob, carol):
    title = unique("star")
    doc = make_doc(alice, title=title)
    assert post(bob, f"/documents/{doc}/star").status_code == 404
    give(alice, doc, "carol", "read")
    post(carol, f"/documents/{doc}/star")
    assert title in text(carol.get("/documents/starred"))
    post(carol, f"/documents/{doc}/star")
    assert title not in text(carol.get("/documents/starred"))
    post(alice, f"/documents/{doc}/star")
    assert title in text(alice.get("/documents/starred"))


def test_star_redirect_cannot_leave_the_site(alice):
    doc = make_doc(alice, title=unique("redir"))
    response = post(alice, f"/documents/{doc}/star", next="//evil.example.com")
    assert response.status_code == 302 and "evil" not in response.location


def test_the_owner_sees_what_they_shared_and_can_revoke_from_there(alice, carol, dave):
    title = unique("shared")
    doc = make_doc(alice, title=title)
    give(alice, doc, "carol", "read")
    give(alice, doc, "dave", "edit")
    page = text(alice.get("/documents/shared"))
    assert title in page and "carol" in page and "dave" in page
    only_carol = text(alice.get("/documents/shared?viewer=carol"))
    assert "(carol)" in only_carol and "(dave)" not in only_carol.split("<table>")[-1]
    only_edit = text(alice.get("/documents/shared?access=edit")).split("<table>")[-1]
    assert "(dave)" in only_edit and "(carol)" not in only_edit
    assert carol.get("/documents/shared").status_code == 404                  # viewers have no such page
    gid = active_grant_id(doc, "carol")
    response = post(alice, f"/documents/{doc}/grants/{gid}/revoke", next="/documents/shared")
    assert response.location.endswith("/documents/shared")
    assert active_grant_id(doc, "carol") is None


def test_each_role_sees_its_own_sidebar(admin, alice, carol):
    a, o, v = text(admin.get("/")), text(alice.get("/")), text(carol.get("/"))
    for item in ("Users", "Audit record", "Documents log", "Bin", "Settings"):
        assert item in a
    for item in ("My documents", "Shared documents", "Starred documents", "Viewers", "Settings"):
        assert item in o
    assert "Upload a document" in o and "Upload" not in v
    assert "Shared with me" in v and "Viewers" not in v and "Bin" not in v


def test_viewers_cannot_see_documents_that_were_not_shared(alice, carol):
    title = unique("hidden")
    make_doc(alice, title=title)
    assert title not in text(carol.get("/documents"))


def test_filters_by_access_and_owner_for_viewers(alice, carol):
    t1, t2 = unique("readdoc"), unique("editdoc")
    d1, d2 = make_doc(alice, title=t1), make_doc(alice, title=t2)
    give(alice, d1, "carol", "read")
    give(alice, d2, "carol", "edit")
    page = text(carol.get("/documents?access=edit"))
    assert t2 in page and t1 not in page
    assert t1 in text(carol.get("/documents?owner=alice"))


def test_the_upload_progress_reply_is_json_for_the_page_script(alice):
    form = {"csrf_token": csrf(alice), "title": unique("json"), "category": "Other",
            "file": (io.BytesIO(b"hi"), "a.txt")}
    ok = alice.post("/documents/upload", data=form, content_type="multipart/form-data",
                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert ok.status_code == 200 and "/documents/" in ok.get_json()["redirect"]
    bad = alice.post("/documents/upload", data={**form, "file": (io.BytesIO(b"x"), "a.exe")},
                     content_type="multipart/form-data", headers={"X-Requested-With": "XMLHttpRequest"})
    assert bad.status_code == 400 and "not allowed" in bad.get_json()["error"]


# ------------------------------------------------------------------ the bin

def test_deleted_documents_go_to_the_admin_bin_with_details_only(alice, admin, carol):
    title = unique("bin")
    doc = make_doc(alice, title=title, data=b"SECRET-CONTENT-XYZ")
    post(alice, f"/documents/{doc}/delete")
    page = text(admin.get("/admin/bin"))
    assert title in page and "SECRET-CONTENT-XYZ" not in page and "Restore all" in page
    assert admin.get(f"/documents/{doc}").status_code == 404                   # admin still cannot open it
    for who in (alice, carol):
        assert who.get("/admin/bin").status_code == 404
        assert post(who, "/admin/bin/restore", all="1").status_code == 404


def test_restore_one_returns_the_document_to_its_owner_with_its_sharing(alice, admin, carol):
    title = unique("restore")
    doc = make_doc(alice, title=title, data=b"BACK AGAIN")
    give(alice, doc, "carol", "read")
    post(alice, f"/documents/{doc}/delete")
    assert carol.get(f"/documents/{doc}").status_code == 404
    post(admin, "/admin/bin/restore", one=str(doc))
    assert alice.get(f"/documents/{doc}/download").data == b"BACK AGAIN"
    assert carol.get(f"/documents/{doc}/download").data == b"BACK AGAIN"        # grant intact
    assert [n for n in note_ids("alice") if "restored your document" in n["message"] and title in n["message"]]
    assert query("SELECT count(*) n FROM audit_log WHERE action = 'doc.restore' AND document_id = %s", doc)[0]["n"] == 1


def test_restore_selected_and_restore_all(alice, admin):
    docs = [make_doc(alice, title=unique("many")) for _ in range(3)]
    for d in docs:
        post(alice, f"/documents/{d}/delete")
    post(admin, "/admin/bin/restore", ids=[str(docs[0]), str(docs[1])])
    states = {d: query("SELECT deleted_at FROM documents WHERE id = %s", d)[0]["deleted_at"] for d in docs}
    assert states[docs[0]] is None and states[docs[1]] is None and states[docs[2]] is not None
    post(admin, "/admin/bin/restore", all="1")
    assert query("SELECT deleted_at FROM documents WHERE id = %s", docs[2])[0]["deleted_at"] is None
    assert "Select at least one" in text(admin.post("/admin/bin/restore", follow_redirects=True,
                                                    data={"csrf_token": csrf(admin)}))


def test_documents_in_the_bin_over_15_days_are_removed_for_good(alice, admin, carol):
    title = unique("purge")
    doc = make_doc(alice, title=title)
    give(alice, doc, "carol", "read")
    post(alice, f"/documents/{doc}/delete")
    query("UPDATE documents SET deleted_at = now() - interval '16 days' WHERE id = %s RETURNING 1", doc)
    assert title not in text(admin.get("/admin/bin"))
    assert query("SELECT count(*) n FROM documents WHERE id = %s", doc)[0]["n"] == 0
    assert query("SELECT count(*) n FROM grants WHERE document_id = %s", doc)[0]["n"] == 0
    assert query("SELECT count(*) n FROM audit_log WHERE action = 'doc.purge' AND document_id = %s", doc)[0]["n"] == 1
    young = make_doc(alice, title=unique("young"))
    post(alice, f"/documents/{young}/delete")
    query("UPDATE documents SET deleted_at = now() - interval '14 days' WHERE id = %s RETURNING 1", young)
    admin.get("/admin/bin")
    assert query("SELECT count(*) n FROM documents WHERE id = %s", young)[0]["n"] == 1


def test_the_documents_log_shows_details_only_and_filters(alice, admin, carol):
    title = unique("logged")
    doc = make_doc(alice, title=title, data=b"CONTENT-NOT-FOR-ADMIN")
    page = text(admin.get("/admin/documents"))
    assert title in page and "CONTENT-NOT-FOR-ADMIN" not in page
    assert title in text(admin.get(f"/admin/documents?owner=alice&title={title}"))
    assert title not in text(admin.get(f"/admin/documents?owner=bob&title={title}")).split("</form>")[-1]
    post(alice, f"/documents/{doc}/delete")
    assert title in text(admin.get(f"/admin/documents?state=deleted&title={title}"))
    assert title not in text(admin.get(f"/admin/documents?state=active&title={title}")).split("</form>")[-1]
    assert carol.get("/admin/documents").status_code == 404


# ------------------------------------------------------------------ alerts

def test_wrong_passwords_deletions_and_refusals_raise_alerts_that_can_be_marked_seen(app, admin, alice, carol):
    post(admin, "/admin/alerts/seen")
    assert "No unusual events" in text(admin.get("/admin/alerts"))
    assert 'class="round alert"' not in text(admin.get("/"))
    name = "zz_" + uuid.uuid4().hex[:6]
    address = ip()
    for _ in range(3):
        try_login(app, name, "wrong", address)
    title = unique("alertdoc")
    doc = make_doc(alice, title=title)
    post(alice, f"/documents/{doc}/delete")
    other = make_doc(alice, title=unique("target"))
    for _ in range(3):
        carol.get(f"/documents/{other}")                   # three refused attempts
    page = text(admin.get("/admin/alerts"))
    assert f"3 wrong passwords were typed for &#34;{name}&#34;" in page or f'for "{name}"' in page.replace("&#34;", '"')
    assert title in page and "was refused access" in page
    assert 'class="round alert"' in text(admin.get("/"))
    assert f"username={name}" in page
    post(admin, "/admin/alerts/seen")
    assert 'class="round alert"' not in text(admin.get("/"))
    for who in (alice, carol):
        assert who.get("/admin/alerts").status_code == 404


def test_opening_ten_documents_quickly_is_an_alert(alice, admin, dave):
    post(admin, "/admin/alerts/seen")
    doc = make_doc(alice, title=unique("bulk"))
    give(alice, doc, "dave", "read")
    for _ in range(10):
        dave.get(f"/documents/{doc}/download")
    assert "10 or more documents within 10 minutes" in text(admin.get("/admin/alerts"))