# TrustVault write-up

*Draft written with AI help. Rewrite the sections marked "in your own words" in your own voice before submitting.*

## What I built
A Flask and PostgreSQL web app for sharing documents with an audit trail. There are three kinds of people: one administrator, document owners and viewers. Owners and viewers join only by e-mailed invitation. Owners upload files and share them with viewers as read or edit; they can revoke access at any time. Every action, and every refused attempt, is written to an append-only audit record whose rows are chained by hashes, and the administrator can check the chain. Other parts: search and filters, a notification bell that opens the document concerned, starred documents, a bin that keeps deleted documents for 15 days, security alerts for unusual events, light and dark mode, "Forgot password" by e-mailed code, and a 100 MB upload limit with a real progress bar. 280 automated tests check the rules; the site is live on Render with PostgreSQL on Neon.

## What I did not build
Two-factor sign-in, virus scanning, e-mail change, an invitation limit per day, a separate "recent documents" page, password reset for the administrator (by design), and any way for the audit chain to detect removal of its newest rows (see THREATS.md). The e-mail invitations rely on a free Brevo account.

## The permission model (in your own words)
*Starting draft:* The administrator runs the system but cannot see anybody's documents: they invite owners, switch accounts on or off, and read the audit record, the documents log (details only), the bin and the alerts. An owner is whoever uploaded a document; only the owner can share it, change who has access, or delete it. A viewer can see only what an owner gave them: with read access they can open and download; with edit access they can also change the title, category or file. Everything is decided in one function, `authorize()`; if the answer is no, the person gets "not found", so they cannot even tell the document exists, and the refusal is recorded.

## How I used AI, and where it was wrong
I used Claude as a coding assistant throughout; the prompts are in PROMPTS.md. I decided the design (roles, invitation-only joining, what the admin may not do) and the assistant wrote and tested code. Things the assistant got wrong or that I had to correct:
- A multi-file upload ignored the title I typed and used file names, so searching for my title found nothing. I noticed it by testing; it was fixed and a test added.
- It first built two roles with an administrator registration page protected by a setup code; I changed the design (one administrator in the database, owners and viewers, invitations), so that work was removed.
- It wrote a test helper that broke when I added star buttons to the page; the tests caught it.
- It assumed a 100 MB upload is fine; I have not proved that on the free hosting plan's memory, so it is listed as a risk.
- Several times it gave me instructions I could not follow (where to paste, which file); I asked it to restate them as numbered steps.
*Add your own examples here.*

## What is unfinished
The things in "not built", the memory risk of very large uploads, the notification bell having no e-mail copy, and the fact that the audit chain cannot detect truncation. The e-mail path was checked by hand on the live site, but there is no automated test that talks to the real e-mail provider.