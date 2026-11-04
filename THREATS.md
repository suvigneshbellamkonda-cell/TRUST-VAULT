# THREATS.md

How I think TrustVault could be broken, what I did about each, and what I knowingly accepted.

Status: Mitigated (fixed and tested) / Planned (not built yet) / Accepted (known risk, with reason).

| # | Threat | What an attacker would try | What I did / plan | Status |
|---|---|---|---|---|
| 1 | Debug mode on live site | Cause an error to open Flask's debugger and run code | Live site runs under gunicorn; no debug=True anywhere | Mitigated |
| 2 | Database password leaks | Find it in the GitHub repo | Password lives only in .env (ignored by git) and in Render's settings | Mitigated |
| 3 | Reading a document by changing its id in the URL | Open /documents/2 when it belongs to someone else | One authorize() function checked on every document route; returns 404 if no grant | Planned (Day 3) |
| 4 | Fake role or owner sent in a request | Send role=admin in a form | Role and user id are read only from the server session and database. Admin user creation reads only four named fields and checks the role against a fixed list | Mitigated |
| 5 | Access still works after revoking | Reuse an old session or page | Grants are checked in the database on every request; nothing cached | Planned (Day 3) |
| 6 | Search reveals documents I have no access to | Search for words in someone else's file name | Search query only returns rows the user has a grant for | Planned (Day 4) |
| 7 | Malicious file upload | Upload an .html or .svg file with a script | Allow-list of types, size limit, content check, download as attachment with nosniff | Planned (Day 3) |
| 8 | Audit log tampering | Edit or delete log rows to hide access | Insert-only table, hash chain, admin verify button | Planned (Day 4) |
| 9 | Password guessing on login | Try many passwords | Lockout after 5 failures per username or 20 per IP in 15 minutes | Mitigated |
| 10 | SQL injection | Put SQL in a search box or form | Every query uses %s placeholders | Mitigated so far; tested Day 4 |
| 11 | Published demo passwords | Log in as admin with the README password | Needed so evaluators can log in. Demo data only; no real documents | Accepted |
| 12 | Free host sleeps after 15 minutes | First request is slow | Noted in README; not a security issue | Accepted |
| 13 | Stolen or copied login cookie | Save the cookie, log out, replay it | Cookie holds only a user id and a version number. Logout and disable raise the version, so old cookies stop working at once | Mitigated |
| 14 | Forged form submission (CSRF) | Trick a logged-in admin's browser into posting to /admin/users | Every POST needs a secret token, checked in one place before any route runs. Cookie is SameSite=Lax | Mitigated |
| 15 | Guessing which usernames exist | Compare login errors or response times | Same message for every failure. A fake password check runs for unknown names. Lockout counts unknown names too | Mitigated |
| 16 | Locking someone else out on purpose | Fail logins for a victim's username | Lockout lasts only 15 minutes and also applies per IP. Anyone can be locked this way | Accepted |
| 17 | Admin pages reachable by non-admins | Open /admin/users as a viewer or POST to it directly | Server checks the role on every admin route and answers 404 | Mitigated |