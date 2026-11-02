from flask import Flask

from db import get_conn

app = Flask(__name__)


@app.route("/")
def home():
    return "TrustVault is running"


@app.route("/health")
def health():
    # Lets the hosting platform check the app and database are alive.
    # Never shows the error itself: that could leak internal details.
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok"}
    except Exception:
        return {"status": "database unavailable"}, 503