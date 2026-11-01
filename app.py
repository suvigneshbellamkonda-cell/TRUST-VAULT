from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return "TrustVault is running"


@app.route("/health")
def health():
    # Lets the hosting platform check the app is alive. Reveals nothing internal.
    return {"status": "ok"}