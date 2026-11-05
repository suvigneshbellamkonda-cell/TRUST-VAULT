"""Database connection helper.

Every query in the app goes through get_conn(), so there is one place
that knows how to reach the database.
"""
import os
import re

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

# Reads DATABASE_URL from the .env file on my laptop.
# On Render, it comes from the environment settings instead.
load_dotenv()


def get_conn():
    # Only the automated tests set DB_SCHEMA. It points every query at a
    # private copy of the tables, so the tests can never touch real data.
    # On Render and on my laptop it is not set, and nothing changes.
    extra = {}
    schema = os.environ.get("DB_SCHEMA")
    if schema:
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", schema):
            raise RuntimeError("DB_SCHEMA must be a plain lowercase name")
        extra["options"] = f"-c search_path={schema}"

    # dict_row means each row comes back as a dictionary,
    # so I can write row["username"] instead of row[1].
    return psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row, **extra)