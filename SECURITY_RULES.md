# Security rules for TrustVault (pasted into every AI session)

1. Every route that touches a document calls authorize(user, doc_id, action).
2. No grant means 404 (not 403), plus a "denied" entry in the audit log.
3. Never trust role, owner or user id from the browser. Read them from the session and the database.
4. Check permissions in the database on every request. Never cache them or store them in the cookie.
5. Files are stored in the database and leave only through the download route, after authorize().
6. Downloads use Content-Disposition: attachment, X-Content-Type-Options: nosniff, Cache-Control: no-store.
7. The audit log is insert-only and hash-chained. No code updates or deletes audit rows.
8. All SQL is parameterised. Never build SQL from user input.
9. No debug mode in production. No stack traces shown to users.
10. Every document route has a test proving another user cannot reach it.