"""Login, sessions, brute-force protection, headers, and the admin user pages."""
import re

from helpers import (csrf, make_user, post, query, text, try_login, unique)


# ------------------------------------------------------------------ login

def test_all_login_failures_look_the_same(app):
    disabled, password = make_user(active=False)
    cases = [
        try_login(app, "no_such_user", "whatever-123"),         # unknown user
        try_login(app, "alice", "wrong-password"),              # wrong password
        try_login(app, disabled, password),                     # right password, disabled
    ]
    strip = lambda r: re.sub(r'value="[0-9a-f]+"', "", text(r))
    for _, response in cases:
        assert response.status_code == 401
    assert strip(cases[0][1]) == strip(cases[1][1]) == strip(cases[2][1])
    assert "Wrong username or password." in text(cases[0][1])


def test_five_failures_lock_the_account_even_for_the_right_password(app):
    username, password = make_user()
    ip = "10.20.30.40"
    for _ in range(5):
        assert try_login(app, username, "wrong-password", ip)[1].status_code == 401
    _, response = try_login(app, username, password, ip)         # correct password now
    assert response.status_code == 429
    assert "Too many failed attempts" in text(response)
    assert query("SELECT count(*) n FROM audit_log WHERE action = 'login.locked' "
                 "AND actor_username = %s", username)[0]["n"] >= 1


def test_one_address_trying_many_usernames_gets_locked(app):
    ip = "10.50.60.70"
    for i in range(20):
        try_login(app, f"guess_{i}", "wrong-password", ip)
    _, response = try_login(app, "alice", "Alice@TV2026", ip)    # a real, correct login
    assert response.status_code == 429


def test_login_needs_the_csrf_token(anon):
    assert anon.post("/login", data={"username": "alice", "password": "Alice@TV2026"}).status_code == 400


def test_login_cookie_flags(app):
    _, response = try_login(app, "alice", "Alice@TV2026")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_session_is_replaced_at_login(app):
    from werkzeug.test import Client
    client = app.test_client()
    client.get("/login")
    before = client.get_cookie("session").value
    page = text(client.get("/login"))
    token = re.search(r'csrf_token" value="([0-9a-f]+)"', page).group(1)
    client.post("/login", data={"username": "alice", "password": "Alice@TV2026", "csrf_token": token})
    assert client.get_cookie("session").value != before


# ------------------------------------------------------------------ sessions

def test_logout_kills_a_copied_cookie(app, alice):
    stolen = app.test_client()
    stolen.set_cookie("session", alice.get_cookie("session").value)
    assert stolen.get("/documents").status_code == 200          # works before logout
    post(alice, "/logout")
    assert stolen.get("/documents").status_code == 302          # worthless afterwards


def test_logout_needs_post_and_csrf(alice):
    assert alice.get("/logout").status_code == 302                 # a GET never logs out
    assert alice.get("/documents").status_code == 200              # still signed in
    assert alice.post("/logout", data={}).status_code == 400       # POST without CSRF refused


def test_disabling_a_user_ends_their_session_at_once(app, admin):
    username, password = make_user()
    client, response = try_login(app, username, password)
    assert response.status_code == 302 and client.get("/documents").status_code == 200
    user_id = query("SELECT id FROM users WHERE username = %s", username)[0]["id"]
    post(admin, f"/admin/users/{user_id}/toggle")
    assert client.get("/documents").status_code == 302
    assert try_login(app, username, password)[1].status_code == 401   # cannot log in either


def test_a_deactivated_account_is_refused_even_if_its_cookie_is_still_current(app):
    username, password = make_user()
    client, _ = try_login(app, username, password)
    assert client.get("/documents").status_code == 200
    from db import get_conn
    with get_conn() as conn:               # switched off WITHOUT changing the session version
        conn.execute("UPDATE users SET is_active = FALSE WHERE username = %s", (username,))
    assert client.get("/documents").status_code == 302


# ------------------------------------------------------------------ headers and errors

def test_security_headers_are_on_every_page(alice):
    response = alice.get("/documents")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_errors_never_show_internals(alice):
    response = alice.get("/documents/999999")
    assert response.status_code == 404
    assert "Page not found." in text(response)
    assert "Traceback" not in text(response) and "werkzeug" not in text(response).lower()


def test_debug_mode_is_off(app):
    assert app.debug is False


def test_health_check(anon):
    assert anon.get("/health").get_json() == {"status": "ok"}


# ------------------------------------------------------------------ admin: users

def test_only_admin_can_manage_users(alice, bob, carol, dave):
    for client in (alice, bob, carol, dave):
        assert client.get("/admin/users").status_code == 404
        assert post(client, "/admin/invitations", full_name="Evil",
                    email="evil@example.com").status_code == 404
        assert post(client, "/admin/users/1/toggle").status_code == 404
    assert query("SELECT count(*) n FROM invitations WHERE email = 'evil@example.com'")[0]["n"] == 0


def test_the_old_create_user_and_register_pages_are_gone(admin, anon):
    assert post(admin, "/admin/users", username="x", full_name="X", email="x@example.com",
                role="admin", password="Long-enough-1!").status_code in (404, 405)
    assert anon.get("/register").status_code == 404


def test_admin_cannot_disable_their_own_account(admin):
    admin_id = query("SELECT id FROM users WHERE username = 'admin'")[0]["id"]
    response = admin.post(f"/admin/users/{admin_id}/toggle", follow_redirects=True,
                          data={"csrf_token": csrf(admin)})
    assert "cannot disable your own" in text(response)
    assert query("SELECT is_active FROM users WHERE id = %s", admin_id)[0]["is_active"] is True


def test_admin_user_actions_are_recorded(admin):
    username, _ = make_user()
    user_id = query("SELECT id FROM users WHERE username = %s", username)[0]["id"]
    post(admin, f"/admin/users/{user_id}/toggle")
    row = query("SELECT actor_username FROM audit_log WHERE action = 'user.disable' "
                "AND target_user_id = %s", user_id)
    assert row and row[0]["actor_username"] == "admin"


def test_static_files_are_served(anon):
    assert anon.get("/static/style.css").status_code == 200