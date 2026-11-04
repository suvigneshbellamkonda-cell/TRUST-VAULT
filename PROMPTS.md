# PROMPTS.md: how I used AI, and where it was wrong

Tool: Claude. Each entry is written on the day it happened, with a link to the fix commit.

## Reused context
I paste SECURITY_RULES.md at the start of every AI session.

## Entries

### 2026-11-02: Where to host the database
- **What I asked:** How to deploy the app and database for free.
- **What it produced:** A plan to host the Postgres database on Render alongside the app.
- **What was wrong, specifically:** Render's free databases expire after 30 days and are then deleted. That could happen before the evaluators or interviewers look at it, and I would lose all the demo data.
- **How I noticed:** Before writing the setup, the AI checked Render's documentation and found the expiry rule, and told me.
- **What I did instead:** Put the database on Neon (free plan, no expiry) and kept only the app on Render. Commit: https://github.com/suvigneshbellamkonda-cell/TRUST-VAULT/commit/764be3a

### 2026-11-04: Login cookie that outlived logout
- **What I asked:** Build login, logout and roles in Flask, where disabling a user takes effect immediately.
- **What it produced:** A first design that stored only the user id in Flask's signed cookie and checked the database on each request.
- **What was wrong, specifically:** Logout only clears the cookie in my own browser. A copy of the cookie saved earlier would keep working for 8 hours. Also, if an admin disabled a user and later re-enabled them, the old cookies would work again.
- **How I noticed:** The AI spotted it while reviewing its own design against the rule "taking access away works immediately".
- **What I did instead:** Added a session_version number to the users table. The cookie carries it, every request compares it with the database, and logout and disable both raise it. Commit: https://github.com/suvigneshbellamkonda-cell/TRUST-VAULT/commit/e93e48b