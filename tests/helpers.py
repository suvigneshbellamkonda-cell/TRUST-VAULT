"""Small helpers shared by the test files."""
import io
import re
import uuid

from werkzeug.security import generate_password_hash

from db import get_conn

PASSWORDS = {
    "admin": "Admin@TV2026",
    "alice": "Alice@TV2026",
    "bob": "Bob@TV2026",
    "carol": "Carol@TV2026",
    "dave": "Dave@TV2026",
}


def unique(prefix="item"):
    """A title or name no other test uses, so tests do not disturb each other."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def query(sql, *args):
    with get_conn() as conn:
        return conn.execute(sql, args).fetchall()


def make_user(role="viewer", password="Temp-pass-12345", active=True):
    """Insert a throwaway user straight into the test database."""
    username = "t_" + uuid.uuid4().hex[:8]
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, full_name, password_hash, role, is_active) "
            "VALUES (%s, %s, %s, %s, %s)",
            (username, "Temp " + username, generate_password_hash(password), role, active),
        )
    return username, password


def try_login(app, username, password, ip="127.0.0.1"):
    """Attempt a login. Returns (client, response) whatever the outcome."""
    client = app.test_client()
    environ = {"REMOTE_ADDR": ip}
    page = client.get("/login", environ_base=environ).get_data(as_text=True)
    token = re.search(r'csrf_token" value="([0-9a-f]+)"', page).group(1)
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        environ_base=environ,
    )
    return client, response


def login(app, username, password=None):
    """Log in and return the client. Fails the test if the login is refused."""
    client, response = try_login(app, username, password or PASSWORDS[username])
    assert response.status_code == 302, f"login as {username} gave {response.status_code}"
    return client


def csrf(client):
    """This session's CSRF token (fetched once, then remembered)."""
    if not hasattr(client, "csrf_value"):
        html = client.get("/documents").get_data(as_text=True)
        client.csrf_value = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)
    return client.csrf_value


def post(client, url, **form):
    """POST a form with a valid CSRF token."""
    form["csrf_token"] = csrf(client)
    return client.post(url, data=form)


def upload(client, title="Test document", category="Contract", name="note.txt",
           data=b"hello", **extra):
    form = {"csrf_token": csrf(client), "title": title, "category": category,
            "file": (io.BytesIO(data), name)}
    form.update(extra)
    return client.post("/documents/upload", data=form, content_type="multipart/form-data")


def make_doc(client, title=None, data=b"hello secret", name="note.txt", category="Contract"):
    """Upload a document and return its id."""
    response = upload(client, title=title or unique("doc"), category=category,
                      name=name, data=data)
    assert response.status_code == 302, f"upload gave {response.status_code}"
    return int(response.location.rstrip("/").split("/")[-1])


def give(owner_client, doc_id, username, permission):
    return post(owner_client, f"/documents/{doc_id}/grants",
                username=username, permission=permission)


def active_grant_id(doc_id, username):
    rows = query(
        "SELECT g.id FROM grants g JOIN users u ON u.id = g.user_id "
        "WHERE g.document_id = %s AND u.username = %s AND g.revoked_at IS NULL",
        doc_id, username)
    return rows[0]["id"] if rows else None


def text(response):
    return response.get_data(as_text=True)