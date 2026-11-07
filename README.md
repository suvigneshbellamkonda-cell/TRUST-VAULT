# TrustVault

Secure document sharing with a real audit trail.
Live site: **https://trust-vault-kutu.onrender.com** (Render free plan: the first visit after a quiet period can take about a minute to wake up).

## Demo accounts (published on purpose, see THREATS.md)

| Role | Username | Password | What it can do |
|---|---|---|---|
| Administrator | `admin` | `Admin@TV2026` | Invite owners, switch accounts on or off, read the audit record, see the documents log (details only), restore from the bin, see security alerts |
| Owner | `alice` | `Alice@TV2026` | Upload, share with viewers, revoke, delete |
| Owner | `bob` | `Bob@TV2026` | Same as alice (use him to check alice's files stay private) |
| Viewer | `carol` | `Carol@TV2026` | Sees only what an owner shared |
| Viewer | `dave` | `Dave@TV2026` | Same, with edit access on one document |

Demo data: alice shares "Salary letter - Carol" (read) and "Site drawing rev B" (dave can edit, carol can read); bob has a private contract and shares "Audit paper 2026" (read) with dave.

## The three roles and what each may do

| Action | Administrator | Owner | Viewer |
|---|---|---|---|
| Upload documents | no | yes | no |
| Open / download own documents | no | yes | n/a |
| Open / download a shared document | only if shared (it cannot be: documents are shared only with viewers) | n/a | with read or edit access |
| Change title, category or file | no | own documents | with edit access |
| Share, change or revoke access | no | own documents, to viewers only | no |
| Delete a document | no | own documents (goes to the admin bin for 15 days) | no |
| Invite people | owners only | viewers only | no |
| Disable / enable accounts | yes (cannot reset passwords) | no | no |
| Read the audit record, documents log, bin, alerts | yes | no | no |

The administrator never has access to document contents. Every document check goes through one function, `authz.authorize()`; a refused request answers 404 (so a visitor cannot tell "no access" from "does not exist") and is written to the audit record.

## Run it yourself from a clean clone

Needs Python 3.12+ and a PostgreSQL database (for example a free one on Neon).

```
git clone https://github.com/suvigneshbellamkonda-cell/TRUST-VAULT.git
cd TRUST-VAULT
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Create a file named `.env` (never commit it) with:

```
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DBNAME?sslmode=require
SECRET_KEY=any-long-random-text
# optional, for real e-mail (invitations and "Forgot password"):
BREVO_API_KEY=your-brevo-api-key
MAIL_FROM=your-verified-sender@example.com
APP_URL=https://your-site.example.com
```

Then create the tables and demo data, and start the app:

```
python setup_db.py        # tables, triggers, the five demo accounts (safe to run again)
python seed_demo.py       # sample documents and shares (safe to run again)
python -m flask --app app run
```

On Render: build command `pip install -r requirements.txt`, start command `gunicorn app:app`, and the same variables under Environment (plus `RENDER=1` is set by Render itself). Run `python setup_db.py` once against the database after each deploy that changes `schema.sql`.

Without `BREVO_API_KEY` and `MAIL_FROM`, no e-mail is sent: an invitation then shows its one-time link on screen to the person who created it, and "Forgot password" cannot deliver codes.

### Replacing the administrator
There is exactly one administrator and no registration page. To replace the administrator, change that row in the database (for example `UPDATE users SET password_hash = ... WHERE username = 'admin'`). A database trigger raises `session_version` whenever a password hash changes, so the old administrator is signed out on every device.

## Tests

```
python -m pytest -q
```
The tests build a private schema (`tv_test`) and delete it afterwards; they never touch real data. 280 tests, including: every page and action for the administrator, an owner, a viewer and a visitor, one user cannot reach another's documents on any route, the audit chain detects tampering, invitations work once, OTP limits, the bin and its 15-day purge. (Against a remote database the full run is slow, about half an hour; against a local PostgreSQL it takes about 20 seconds.)

## Other documents
- `THREATS.md` - what could go wrong, what stops it, which test proves it, what is left over
- `API.md` - every endpoint and who may call it
- `WRITEUP.md` - what was built and not built, the permission model in my own words, AI use
- `PROMPTS.md` - the prompts used, with the commits they produced
- `SECURITY_RULES.md` - the rules the AI assistant was given

## Not built (honest list)
Two-factor sign-in; checking that a mailbox really exists before an invitation is sent (only the domain is checked); virus scanning of uploads; a limit on how many people can be invited per day; e-mail change; deleting or editing a person's account details; "Forgot password" for the administrator (by design); a recent-documents page of its own (recent documents are a small list on Overview). Uploads are stored in the database and read into memory, so a 100 MB upload may be slow or fail on the free hosting plan.