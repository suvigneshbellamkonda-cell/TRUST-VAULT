# TrustVault endpoints and who may call them

The app is made of server-rendered pages; every POST must carry the form's CSRF token. "Signed in" means a valid session; a wrong role gets **404** and an audit row (`access.denied`). A document the person cannot use also gets 404 (`doc.<action>` denied in the audit record).

## Open to anyone
| Method | Path | What it does |
|---|---|---|
| GET/POST | `/login` | Sign in (lock-out after 5 failures per username or 20 per address in 15 minutes) |
| GET/POST | `/forgot` | Ask for an e-mailed one-time code (same answer whether or not the address exists; 5 requests per address per 15 minutes, 3 codes per person per hour) |
| GET/POST | `/forgot/code` | Enter the code (10 minutes, 5 tries). Administrator excluded |
| GET/POST | `/forgot/new` | Set the new password after a correct code; ends all sessions |
| GET/POST | `/join/<token>` | Register from an invitation. Works once, expires after 48 hours; otherwise 404 |
| GET | `/joined` | "Registered successfully" page |
| GET | `/health` | Service and database check |

## Any signed-in person
| Method | Path | What it does |
|---|---|---|
| POST | `/logout` | Sign out (ends every copy of the cookie) |
| GET | `/` | Overview for the person's role |
| GET | `/settings`, POST `/settings/password` | Appearance; change password (current password required; signs out other devices) |
| GET | `/profile`, POST `/profile/edit` | Own details; change name, username and e-mail (current password required, recorded in the audit record) |
| GET | `/notifications`, GET `/notifications/<id>/go`, POST `/notifications/read-all`, POST `/notifications/clear` (`which=read` or `all`, own notifications only) | The bell. `go` works only for the person's own notification and only redirects inside the site |
| GET | `/documents` | Own documents (owner) or documents shared with the person (viewer); filters: title, category, owner, access, dates |
| GET | `/documents/starred` | Own starred documents (only ones the person may still read) |
| POST | `/documents/<id>/star` | Toggle star; needs read access |

## By document access (checked by `authz.authorize`)
| Method | Path | Needs |
|---|---|---|
| GET | `/documents/<id>` | read (owner, edit or read grant) |
| GET | `/documents/<id>/open` | read; shows pdf, png, jpg, txt inline with a locked-down policy, anything else downloads |
| GET | `/documents/<id>/download` | read; audited with the file fingerprint |
| POST | `/documents/<id>/edit` | edit (owner or edit grant): title, category, optional replacement file; owner is notified |
| POST | `/documents/<id>/delete` | owner only; goes to the bin |
| POST | `/documents/<id>/grants` | owner only; target must be an active viewer; notifies the viewer |
| POST | `/documents/<id>/grants/<gid>/revoke` | owner only; works at once; clears the viewer's notifications for it |

## Owners only
| Method | Path | What it does |
|---|---|---|
| GET/POST | `/documents/upload` | Upload up to 50 files, 100 MB in total, all-or-nothing; replies JSON to the progress-bar script |
| GET | `/documents/shared` | Everything the owner has shared, filter by viewer or access |
| GET | `/viewers`, POST `/viewers/invitations` | Invite viewers; see own invitations (filter by status) and viewers who joined |

## Administrator only
| Method | Path | What it does |
|---|---|---|
| GET | `/admin/users` | Accounts and invitations, with filters |
| POST | `/admin/invitations` | Invite an owner |
| POST | `/admin/users/<id>/toggle` | Disable or enable an account (cannot be used on oneself). There is no password reset |
| GET | `/admin/audit`, POST `/admin/audit/verify` | Audit record with filters; re-check the hash chain |
| GET | `/admin/documents` | Documents log: details only, never contents |
| GET | `/admin/bin`, POST `/admin/bin/restore` | Deleted documents (15 days); restore one (`one`), several (`ids`) or all (`all=1`) |
| GET | `/admin/alerts`, POST `/admin/alerts/seen` | Unusual events; mark all as seen |