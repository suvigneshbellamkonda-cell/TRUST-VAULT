"""Test setup. Every test run builds a PRIVATE copy of the database tables
(the schema "tv_test") and deletes it afterwards. The real tables are never
touched, because DB_SCHEMA makes every query use the copy."""
import os

# These two lines must come before anything imports the app.
os.environ["DB_SCHEMA"] = "tv_test"
os.environ.setdefault("SECRET_KEY", "test-only-secret-used-nowhere-else")

import psycopg  # noqa: E402
import pytest  # noqa: E402
from psycopg import sql  # noqa: E402

import db  # noqa: E402,F401  (importing db loads the .env file)
from helpers import login  # noqa: E402


@pytest.fixture(scope="session")
def app():
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.exit("DATABASE_URL is not set. Put it in .env first.", returncode=2)
    # Neon's "-pooler" address does not accept the search_path setting the tests
    # need. The same database is reachable without "-pooler".
    url = url.replace("-pooler", "")
    os.environ["DATABASE_URL"] = url
    schema = os.environ["DB_SCHEMA"]
    assert schema != "public"          # never build test tables in the real place

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))

    import seed_demo
    import setup_db
    setup_db.main()      # tables, triggers and the five demo users
    seed_demo.main()     # the four sample documents

    from app import app as flask_app
    yield flask_app

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture
def anon(app):
    return app.test_client()


@pytest.fixture
def alice(app):
    return login(app, "alice")


@pytest.fixture
def bob(app):
    return login(app, "bob")


@pytest.fixture
def carol(app):
    return login(app, "carol")


@pytest.fixture
def dave(app):
    return login(app, "dave")


@pytest.fixture
def admin(app):
    return login(app, "admin")


@pytest.fixture(autouse=True)
def domains_exist(monkeypatch):
    """The tests have no internet, so every e-mail domain counts as real unless a test says otherwise."""
    import mailer
    monkeypatch.setattr(mailer, "domain_exists", lambda email: True)