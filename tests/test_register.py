"""Admin registration: the secret setup code, the form checks, and the two roles."""
import re
import uuid

import pytest
from werkzeug.security import check_password_hash

from helpers import csrf, give, login, make_doc, post, query, text, try_login, unique

CODE = "test-setup-code-123"


@pytest.fixture(autouse=True)
def setup_code(monkeypatch):
    monkeypatch.setenv("SETUP_CODE", CODE)


def new_name():
    return "t_" + uuid.uuid4().hex[:8]


def register(client, ip="127.0.0.1", **overrides):
    """Open the registration page, then send the form (the way a browser would)."""
    env = {"REMOTE_ADDR": ip}
    page = client.get("/register", environ_base=env)
    token = re.search(r'csrf_token" value="([0-9a-f]+)"', text(page)).group(1)
    name = new_name()
    data = {"csrf_token": token, "full_name": "New Admin", "email": f"{name}@example.com",
            "username": name, "organisation": "Acme Ltd", "password": "a-long-password-1",
            "confirm_password": "a-long-password-1", "setup_code": CODE}
    data.update(overrides)
    return client.post("/register", data=data, environ_base=env), data


# ------------------------------------------------------------------ switched on and off

def test_page_does_not_exist_without_a_setup_code(anon, monkeypatch):
    monkeypatch.delenv("SETUP_CODE")
    assert anon.get("/register").status_code == 404
    assert anon.post("/register", data={}).status_code in (400, 404)
    assert "Register as administrator" not in text(anon.get("/login"))


def test_a_short_setup_code_counts_as_switched_off(anon, monkeypatch):
    monkeypatch.setenv("SETUP_CODE", "short")
    assert anon.get("/register").status_code == 404


def test_page_and_link_exist_with_a_setup_code(anon):
    page = anon.get("/register")
    assert page.status_code == 200
    for field in ("full_name", "email", "username", "organisation", "password",
                  "confirm_password", "setup_code"):
        assert f'name="{field}"' in text(page)
    assert "Register as administrator" in text(anon.get("/login"))
    assert CODE not in text(page) and CODE not in text(anon.get("/login"))


def test_logged_in_people_are_sent_away_from_the_page(alice):
    assert alice.get("/register").status_code == 302


# ------------------------------------------------------------------ success

def test_registration_creates_an_admin_who_can_sign_in(app, anon):
    response, data = register(anon)
    assert response.status_code == 302 and response.location.endswith("/login")
    row = query("SELECT role, email, organisation, full_name, password_hash, is_active "
                "FROM users WHERE username = %s", data["username"])[0]
    assert row["role"] == "admin" and row["is_active"] is True
    assert row["email"] == data["email"] and row["organisation"] == "Acme Ltd"
    assert row["password_hash"] != data["password"]
    assert check_password_hash(row["password_hash"], data["password"])
    assert try_login(app, data["username"], data["password"])[1].status_code == 302
    logged = query("SELECT count(*) n FROM audit_log WHERE action = 'admin.register' "
                   "AND outcome = 'ok' AND actor_username = %s", data["username"])[0]["n"]
    assert logged == 1
    assert data["password"] not in str(query("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 5"))


def test_a_new_admin_manages_users_but_cannot_read_documents(app, anon, alice):
    doc = make_doc(alice, title=unique("private"))
    response, data = register(anon)
    assert response.status_code == 302
    client = login(app, data["username"], data["password"])
    assert client.get("/admin/users").status_code == 200
    assert client.get("/admin/audit").status_code == 200
    assert client.get(f"/documents/{doc}").status_code == 404
    assert client.get("/documents/upload").status_code == 404


def test_an_admin_who_creates_users_gives_them_the_same_organisation(admin):
    name = new_name()
    response = post(admin, "/admin/users", username=name, full_name="Org Test",
                    email=f"{name}@example.com", role="user", password="a-long-password-1")
    assert response.status_code == 302
    org = query("SELECT organisation FROM users WHERE username = 'admin'")[0]["organisation"]
    assert query("SELECT organisation FROM users WHERE username = %s", name)[0]["organisation"] == org


def test_an_admin_can_add_another_admin(app, admin):
    name = new_name()
    post(admin, "/admin/users", username=name, full_name="Second Admin",
         email=f"{name}@example.com", role="admin", password="a-long-password-1")
    assert query("SELECT role FROM users WHERE username = %s", name)[0]["role"] == "admin"
    assert try_login(app, name, "a-long-password-1")[1].status_code == 302


# ------------------------------------------------------------------ refusals

def test_wrong_setup_code_creates_nothing_and_is_audited(anon):
    response, data = register(anon, ip="10.1.1.1", setup_code="not-the-code-at-all")
    assert response.status_code == 403
    assert "setup code is not correct" in text(response)
    assert "not-the-code-at-all" not in text(response)
    assert query("SELECT count(*) n FROM users WHERE username = %s", data["username"])[0]["n"] == 0
    assert query("SELECT count(*) n FROM audit_log WHERE action = 'register.fail' "
                 "AND outcome = 'denied' AND actor_username = 'register:10.1.1.1'")[0]["n"] == 1


def test_an_empty_setup_code_is_refused(anon):
    response, data = register(anon, ip="10.1.1.2", setup_code="")
    assert response.status_code == 403
    assert query("SELECT count(*) n FROM users WHERE username = %s", data["username"])[0]["n"] == 0


def test_guessing_the_setup_code_gets_locked_out(anon):
    for _ in range(5):
        assert register(anon, ip="10.2.2.2", setup_code="wrong-guess-123")[0].status_code == 403
    response, data = register(anon, ip="10.2.2.2")                  # now the RIGHT code
    assert response.status_code == 429
    assert query("SELECT count(*) n FROM users WHERE username = %s", data["username"])[0]["n"] == 0
    other, _ = register(anon, ip="10.3.3.3")                        # another address is fine
    assert other.status_code == 302


BAD_FORMS = [
    ({"full_name": ""}, "Full name"),
    ({"email": "not-an-email"}, "valid e-mail"),
    ({"email": "a b@example.com"}, "valid e-mail"),
    ({"username": "AB"}, "Username must be"),
    ({"username": "has space"}, "Username must be"),
    ({"username": "x'; DROP TABLE users;--"}, "Username must be"),
    ({"organisation": ""}, "Organisation name"),
    ({"organisation": "x" * 101}, "Organisation name"),
    ({"password": "short", "confirm_password": "short"}, "at least 10"),
    ({"confirm_password": "a-different-password"}, "not the same"),
]


@pytest.mark.parametrize("change,message", BAD_FORMS)
def test_bad_registration_input_is_refused_with_a_message(anon, change, message):
    response, data = register(anon, ip="10.4.4.4", **change)
    assert response.status_code == 400 and message in text(response)
    assert data["password"] not in text(response)                   # password never shown again
    assert query("SELECT count(*) n FROM users WHERE username = %s", data["username"])[0]["n"] == 0


def test_duplicate_username_and_duplicate_email_are_refused(anon):
    response, _ = register(anon, ip="10.5.5.5", username="alice")
    assert response.status_code == 400 and "already used" in text(response)
    existing = query("SELECT email FROM users WHERE username = 'alice'")[0]["email"]
    response, _ = register(anon, ip="10.5.5.5", email=existing.upper())    # same e-mail, other case
    assert response.status_code == 400 and "already used" in text(response)
    assert query("SELECT count(*) n FROM users WHERE username = 'alice'")[0]["n"] == 1


def test_registration_needs_the_csrf_token(anon):
    anon.get("/register")
    response = anon.post("/register", data={"setup_code": CODE, "username": new_name()})
    assert response.status_code == 400


def test_registration_cannot_make_anything_but_an_admin_or_set_forged_fields(anon):
    response, data = register(anon, ip="10.6.6.6", role="user", is_active="false",
                              session_version="99")
    assert response.status_code == 302
    row = query("SELECT role, is_active, session_version FROM users WHERE username = %s",
                data["username"])[0]
    assert row["role"] == "admin" and row["is_active"] is True and row["session_version"] == 0


# ------------------------------------------------------------------ the two roles

def test_only_admin_and_user_roles_exist():
    import psycopg
    from db import get_conn
    for bad in ("owner", "viewer", "superadmin"):
        with pytest.raises(psycopg.errors.CheckViolation):
            with get_conn() as conn:
                conn.execute("INSERT INTO users (username, full_name, password_hash, role) "
                             "VALUES (%s, 'x', 'x', %s)", (new_name(), bad))
    roles = {r["role"] for r in query("SELECT DISTINCT role FROM users")}
    assert roles <= {"admin", "user"}


def test_an_older_database_with_owner_and_viewer_is_converted(app):
    import setup_db
    from db import get_conn
    name = new_name()
    with get_conn() as conn:
        conn.execute("INSERT INTO users (username, full_name, password_hash, role) "
                     "VALUES (%s, 'Old Owner', 'x', 'user')", (name,))
        conn.execute("ALTER TABLE users DROP CONSTRAINT users_role_check")
        conn.execute("UPDATE users SET role = 'owner' WHERE username = %s", (name,))
    try:
        setup_db.main()                       # the same script the live database runs
    finally:
        setup_db.main()
    assert query("SELECT role FROM users WHERE username = %s", name)[0]["role"] == "user"