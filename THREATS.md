# THREATS.md

| # | Threat | What an attacker would try | What I did | Test | Status |
|---|---|---|---|---|---|
| 1 | Debug mode on the live site | Trigger an error to open Flask's debugger and run code on the server | Live site runs under gunicorn; no debug=True anywhere | Day 5 | Planned |