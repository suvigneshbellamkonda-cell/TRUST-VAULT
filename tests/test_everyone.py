"""Every page and action, for every kind of person: administrator, owner, viewer and a visitor."""
import re
import uuid

import pytest

import mailer
from helpers import csrf, give, make_doc, make_user, post, query, text, try_login, unique

REAL_MAILER = mailer.domain_exists            # kept before any test replaces it

SIGNED_IN_PAGES = ["/", "/settings", "/profile", "/notifications", "/documents", "/documents/starred"]
ADMIN_ONLY = ["/admin/users", "/admin/audit", "/admin/documents", "/admin/bin", "/admin/alerts"]
OWNER_ONLY = ["/documents/shared", "/documents/upload", "/viewers"]


def person(request, who):
    return None if who == "visitor" else request.getfixturevalue(who)


@pytest.mark.parametrize("who", ["admin", "alice", "carol"])
@pytest.mark.parametrize("path", SIGNED_IN_PAGES)
def test_every_signed_in_person_can_open_the_shared_pages(request, who, path):
    assert person(request, who).get(path).status_code == 200


@pytest.mark.parametrize("who,expected", [("admin", 200), ("alice", 404), ("carol", 404)])
@pytest.mark.parametrize("path", ADMIN_ONLY)
def test_admin_pages_are_for_the_administrator_only(request, who, path, expected):
    assert person(request, who).get(path).status_code == expected


@pytest.mark.parametrize("who,expected", [("admin", 404), ("alice", 200), ("carol", 404)])
@pytest.mark.parametrize("path", OWNER_ONLY)
def test_owner_pages_are_for_owners_only(request, who, path, expected):
    assert person(request, who).get(path).status_code == expected


@pytest.mark.parametrize("path", SIGNED_IN_PAGES + ADMIN_ONLY + OWNER_ONLY)
def test_a_visitor_is_sent_to_sign_in_from_every_private_page(anon, path):
    response = anon.get(path)
    assert response.status_code == 302 and "/login" in response.location


def test_public_pages_open_for_a_visitor(anon):
    for path in ("/login", "/forgot", "/joined", "/health"):
        assert anon.get(path).status_code == 200
    assert anon.get("/join/nothing-here").status_code == 404


@pytest.mark.parametrize("who", ["admin", "carol"])
def test_only_owners_can_post_an_upload_or_invite_viewers(request, who):
    client = person(request, who)
    assert post(client, "/viewers/invitations", full_name="X", email="x@example.com").status_code == 404
    assert post(client, "/documents/upload", title="x", category="Other").status_code == 404


@pytest.mark.parametrize("who", ["alice", "carol"])
def test_only_the_administrator_can_post_admin_actions(request, who):
    client = person(request, who)
    for path in ("/admin/invitations", "/admin/bin/restore", "/admin/alerts/seen",
                 "/admin/audit/verify", "/admin/users/1/toggle"):
        assert post(client, path, full_name="X", email="x@example.com", all="1").status_code == 404


def test_a_visitors_posts_are_refused(anon):
    for path in ("/documents/1/delete", "/admin/invitations", "/settings/password",
                 "/profile/edit", "/notifications/clear", "/logout"):
        assert anon.post(path, data={}).status_code in (302, 400)


def test_a_viewer_can_do_nothing_beyond_the_grant(alice, carol, dave):
    doc = make_doc(alice, title=unique("everyone"))
    give(alice, doc, "carol", "read")
    assert carol.get(f"/documents/{doc}").status_code == 200
    assert post(carol, f"/documents/{doc}/edit", title="x", category="Other").status_code == 404
    assert post(carol, f"/documents/{doc}/delete").status_code == 404
    assert post(carol, f"/documents/{doc}/grants", username="dave", permission="read").status_code == 404
    assert dave.get(f"/documents/{doc}").status_code == 404


def test_an_owner_cannot_touch_another_owners_document(alice, bob):
    doc = make_doc(bob, title=unique("bobs"))
    for path in (f"/documents/{doc}", f"/documents/{doc}/download", f"/documents/{doc}/open"):
        assert alice.get(path).status_code == 404
    for path in (f"/documents/{doc}/edit", f"/documents/{doc}/delete", f"/documents/{doc}/star"):
        assert post(alice, path, title="x", category="Other").status_code == 404


# ------------------------------------------------------------------ the eight latest changes

def test_light_is_the_default_for_everyone(anon):
    script = text(anon.get("/static/theme.js"))
    assert "prefers-color-scheme" not in script and 'stored === "dark"' in script
    assert 'data-theme="light"' in text(anon.get("/login"))


def test_the_invitation_link_opens_the_register_page_even_when_someone_is_signed_in(app, admin, alice, monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "send", lambda to, name, subject, body: sent.append(body) or True)
    email = f"{unique('same')}@example.com"
    post(admin, "/admin/invitations", full_name="Same Computer", email=email)
    token = re.search(r"/join/([A-Za-z0-9_-]+)", sent[-1]).group(1)
    page = admin.get(f"/join/{token}")                         # opened while signed in as the administrator
    html = text(page)
    assert page.status_code == 200 and "Create your owner account" in html
    assert "Audit record" not in html                          # not the administrator's pages
    username = "s_" + uuid.uuid4().hex[:8]
    response = admin.post(f"/join/{token}", data={
        "csrf_token": csrf(admin), "full_name": "Same Computer", "username": username,
        "password": "Strong@Pass1", "confirm_password": "Strong@Pass1"})
    assert response.status_code == 302 and response.location.endswith("/joined")
    assert admin.get("/admin/users").status_code == 302        # the inviter's session ended
    assert try_login(app, username, "Strong@Pass1", "10.8.1.1")[1].status_code == 302


def test_an_owner_opening_a_viewer_invitation_on_the_same_computer(app, alice, monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "send", lambda to, name, subject, body: sent.append(body) or True)
    post(alice, "/viewers/invitations", full_name="Viewer Same", email=f"{unique('vs')}@example.com")
    token = re.search(r"/join/([A-Za-z0-9_-]+)", sent[-1]).group(1)
    page = alice.get(f"/join/{token}")
    assert page.status_code == 200 and "Create your viewer account" in text(page)
    assert "Upload a document" not in text(page)


def test_profile_can_be_edited_and_is_recorded(app):
    username, password = make_user()
    client, _ = try_login(app, username, password, "10.8.2.1")
    new_user = "n_" + uuid.uuid4().hex[:8]
    response = post(client, "/profile/edit", full_name="New Name", username=new_user,
                    email=f"{new_user}@example.com", current_password=password)
    assert response.status_code == 302
    row = query("SELECT full_name, username, email FROM users WHERE username = %s", new_user)[0]
    assert row["full_name"] == "New Name" and row["email"] == f"{new_user}@example.com"
    assert "New Name" in text(client.get("/profile"))
    assert query("SELECT count(*) n FROM audit_log WHERE action = 'profile.edit' AND outcome = 'ok' "
                 "AND detail LIKE %s", f"%{new_user}%")[0]["n"] == 1
    assert try_login(app, new_user, password, "10.8.2.2")[1].status_code == 302      # signs in with the new username


@pytest.mark.parametrize("change,message", [
    ({"current_password": "wrong"}, "not correct"),
    ({"username": "AB"}, "Username must be"),
    ({"username": "has space"}, "Username must be"),
    ({"full_name": ""}, "Full name"),
    ({"email": "nope"}, "valid e-mail"),
    ({"username": "alice"}, "already in use"),
    ({"email": "ALICE@trustvault.example"}, "already in use"),
])
def test_profile_edit_refusals(app, change, message):
    username, password = make_user()
    client, _ = try_login(app, username, password, "10.8.3.1")
    form = {"full_name": "Ok Name", "username": username, "email": f"{username}@example.com",
            "current_password": password, **change}
    response = client.post("/profile/edit", data={**form, "csrf_token": csrf(client)}, follow_redirects=True)
    assert message in text(response)
    assert query("SELECT username FROM users WHERE username = %s", username)[0]["username"] == username


def test_everyone_can_edit_their_own_profile_and_nobody_elses(admin, alice, carol):
    for client in (admin, alice, carol):
        assert "Edit your details" in text(client.get("/profile"))
    post(carol, "/profile/edit", full_name="Hacked", username="bob", email="b@example.com", current_password="x")
    assert query("SELECT full_name FROM users WHERE username = 'bob'")[0]["full_name"] != "Hacked"


def test_notifications_can_be_cleared(alice, carol, dave):
    doc = make_doc(alice, title=unique("clearme"))
    give(alice, doc, "carol", "read")
    give(alice, doc, "dave", "read")
    note = query("SELECT n.id FROM notifications n JOIN users u ON u.id = n.user_id "
                 "WHERE u.username = 'carol' AND n.document_id = %s", doc)[0]["id"]
    carol.get(f"/notifications/{note}/go")                              # now read
    post(carol, "/notifications/clear", which="read")
    assert query("SELECT count(*) n FROM notifications WHERE id = %s", note)[0]["n"] == 0
    count_dave = lambda: query("SELECT count(*) n FROM notifications n JOIN users u ON u.id = n.user_id "
                               "WHERE u.username = 'dave'")[0]["n"]
    assert count_dave() >= 1                                            # carol clearing did not touch dave's
    post(dave, "/notifications/clear", which="all")
    assert count_dave() == 0


def test_the_unwanted_text_is_gone(alice, carol, admin):
    doc = make_doc(alice, title=unique("clean"))
    give(alice, doc, "carol", "read")
    for client in (alice, carol):
        assert "fingerprint" not in text(client.get(f"/documents/{doc}")).lower()
    for client, path in ((alice, "/settings"), (alice, "/documents/upload"), (admin, "/admin/users"), (alice, "/viewers")):
        page = text(client.get(path))
        for phrase in ("remembered in this browser", "All the files are checked first", "works once and expires in 48 hours"):
            assert phrase not in page


# ------------------------------------------------------------------ invitations to addresses that do not exist

def test_an_invitation_to_a_domain_that_does_not_exist_is_refused(admin, alice, monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "send", lambda *a, **k: sent.append(a) or True)
    monkeypatch.setattr(mailer, "domain_exists", lambda email: False)
    email = f"{unique('ghost')}@no-such-domain-xyz.example"
    for client, path in ((admin, "/admin/invitations"), (alice, "/viewers/invitations")):
        response = client.post(path, follow_redirects=True, data={
            "csrf_token": csrf(client), "full_name": "Ghost", "email": email})
        assert "does not exist" in text(response)
    assert sent == []
    assert query("SELECT count(*) n FROM invitations WHERE email = %s", email)[0]["n"] == 0


def test_the_domain_check_is_only_certain_when_the_dns_says_no(monkeypatch):
    import socket
    real = REAL_MAILER                                   # the real function, not the test double
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [("ok",)])
    assert real("a@company.com") is True
    def no_such(*a, **k):
        raise socket.gaierror("no such domain")
    monkeypatch.setattr(socket, "getaddrinfo", no_such)
    assert real("a@no-such-domain-xyz.example") is False
    def broken(*a, **k):
        raise OSError("DNS is down")
    monkeypatch.setattr(socket, "getaddrinfo", broken)
    assert real("a@company.com") is True   # unclear: never block a real person


def test_the_success_message_does_not_promise_delivery(admin, monkeypatch):
    monkeypatch.setattr(mailer, "send", lambda *a, **k: True)
    response = admin.post("/admin/invitations", follow_redirects=True, data={
        "csrf_token": csrf(admin), "full_name": "Maybe", "email": f"{unique('maybe')}@example.com"})
    page = text(response)
    assert "handed to the mail service" in page and "will not arrive" in page and "Invitation sent to" not in page


def test_logging_out_works_for_a_viewer(app):
    username, password = make_user(role="viewer")
    client, _ = try_login(app, username, password, "10.8.9.1")
    assert client.get("/").status_code == 200
    assert post(client, "/logout").status_code == 302
    assert client.get("/").status_code == 302


@pytest.mark.parametrize("who", ["admin", "alice", "carol"])
def test_sidebar_has_log_out_directly_below_settings(request, who):
    html = person(request, who).get("/").get_data(as_text=True)
    nav = html.split("<nav")[1].split("</nav>")[0]
    assert nav.index("Settings</a>") < nav.index('action="/logout"') < nav.index("Log out")


def test_opening_the_logout_address_directly_is_not_an_error(app):
    username, password = make_user(role="viewer")
    client, _ = try_login(app, username, password, "10.8.9.2")
    assert client.get("/logout").status_code == 302
    assert client.get("/").status_code == 200  # a GET did not log me out
    post(client, "/logout")
    after = client.get("/logout")
    assert after.status_code == 302 and "/login" in after.headers["Location"]