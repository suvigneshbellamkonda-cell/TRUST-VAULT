"""Database connection helper.

Every query in the app goes through get_conn(), so there is one place
that knows how to reach the database.
"""
import os

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

# Reads DATABASE_URL from the .env file on my laptop.
# On Render, it comes from the environment settings instead.
load_dotenv()


def get_conn():
    # dict_row means each row comes back as a dictionary,
    # so I can write row["username"] instead of row[1].
    return psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row)