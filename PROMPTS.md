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
- **What I did instead:** Put the database on Neon (free plan, no expiry) and kept only the app on Render. Commit: LINK-TO-ADD-LATER