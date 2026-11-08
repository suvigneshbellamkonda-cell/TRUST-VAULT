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

### 2026-11-07, about 01:10 IST: Password rule, progress bar, alerts and bin (authorisation and audit)
- **What I asked:** "1. Password with atleast 8 characters with one capital, one number, one spl character 2. remove the setup code. 3. Add progress bar ... 4. Alert button like danger symbol at top right ... only appear when someone types wrong password more than 2 times, deleted documents or any other unusual things in the admin. 5. a fixed notifications button, the one who gets the new documents will get a notification like in the instagram. 6. only left arrow symbol and back for moving into previous page. 7. starred and recent documents. 8. someone deleted the documents wantedly, those should come to admin's bin, stay for 15 days and admin can revoke the action, send back to the original where it came from." (my words, spelling lightly cleaned, shortened)
- **What it produced:** The password rule, an upload with a real percentage bar, the admin alert list, the notification table and bell, one Back link, stars, and a bin with restore and 15-day purge.
- **What I checked:** I read the SQL for the alert thresholds and ran the tests `test_wrong_passwords_deletions_and_refusals_raise_alerts...`, `test_restore_one_returns_the_document_to_its_owner_with_its_sharing` and `test_documents_in_the_bin_over_15_days_are_removed_for_good`. Restore and purge are written to the audit log (`doc.restore`, `doc.purge`).
- **Commit:** https://github.com/suvigneshbellamkonda-cell/TRUST-VAULT/commit/28c389b40555d5dc326abbc16852b97de9e6c04e

### 2026-11-07, before 13:35 IST: One admin account and signing out everywhere (authorisation)
- **What I asked:** "admin is only one, his username and password will be in there in the data base, when we need to change the admin we can reset it from the data base, once the admin password is changed it will logout the existing admin login in all devices." (my words, spelling lightly cleaned)
- **What it produced:** A database trigger (`users_bump_session`) that raises `session_version` whenever a password hash changes, and removal of admin registration and the setup code.
- **What I checked:** `test_changing_a_password_in_the_database_signs_that_user_out_everywhere`.
- **Commit:** https://github.com/suvigneshbellamkonda-cell/TRUST-VAULT/commit/764e669aff9aa2d2a5f48771031900d9554e1324

### 2026-11-07, about 13:35 IST: Roles and invitations (authorisation)
- **What I asked:** "there will be two types of users owners, viewers. overviews, users, audit record, documents log, settings should be sidewise left of the screen, and along with that bin should be there ... owners can be joined by filling their details ... each link will work for only one owner to join. admin will goto users and he will type fullname and email and press invitation then the owner will receive the mail from the company mail. admin cant reset the owners password he can disable and enable the owners accounts ... when pressed the notification it should direct me to the action happened. dark mode and light mode. change password in everyone's settings." (my words, spelling lightly cleaned)
- **What it produced:** Invitations with single-use join links, the roles admin, owner and viewer in the database, the left sidebar, notification links that open the page they are about, the theme switch, and change password.
- **What I checked:** `test_a_used_link_cannot_create_a_second_account`, `test_the_invited_address_cannot_be_changed_by_the_form`, `test_admin_cannot_reset_anyones_password` and `test_sharing_notifies_the_recipient_and_the_click_goes_to_the_document`. I decided the permission rules myself, and I asked the AI to show mock-up images first and approved them before it wrote code.
- **Commit:** https://github.com/suvigneshbellamkonda-cell/TRUST-VAULT/commit/7d12044fed7473e3f809eb0da22459b47a700019

### 2026-11-07, about 14:03 and 14:42 IST: Owner, viewer and sign-in rules (authorisation)
- **What I asked:** "owner will open the invitation link ... register full name, user name, email, password ... he can only send files he will not receive any files ... shared documents (the documents he shared) ... sign in page is common for all ... forgot password he will receive otp for mail ... upload files can be total 100mb limit no each one limit ... every owner, admin, viewer has notifications, settings." Then at 16:01: "viewer ... user have control of documents like read edit alter copy change only what he got from the owner", and at 16:14: "admin only can send invitations for the owners, owners only for the viewers." (my words, spelling lightly cleaned, shortened)
- **What it produced:** The viewer pages, editing with file replacement, owner-only invitations for viewers, the e-mailed code for a forgotten password, and the 100 MB total upload limit.
- **What I checked:** `test_nobody_else_can_invite`, `test_documents_can_be_shared_only_with_viewers`, `test_an_editor_can_replace_the_file_and_a_reader_cannot`, `test_forgot_password_with_a_code_sets_a_new_password` and `test_five_wrong_codes_block_the_right_one`.
- **Commit:** https://github.com/suvigneshbellamkonda-cell/TRUST-VAULT/commit/21692fc2d220358bb6e42049e8a455897fe15147