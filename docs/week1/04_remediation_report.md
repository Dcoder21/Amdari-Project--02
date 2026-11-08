# SentinelPay — Week 1 Remediation Report

**Engagement:** SentinelPay security assessment (Amdari programme, Week 1)
**Scope:** Application-layer, pipeline/supply-chain, and repository-level
findings against `payments-api` and `kyc-api`
**Status:** All 19 tracked findings fixed, tested, and submitted as PRs.
Merging into `main` is being done by the repository owner; nothing in this
report describes work still pending unless explicitly marked so.

---

## 1. Executive summary

Week 1 of the engagement produced a vulnerability inventory of 19 findings
across three layers: application code (11), pipeline/supply-chain (4), and
repository/credential hygiene (2, overlapping with a 3rd — runtime hardening
— that wasn't in the original index but was raised and fixed alongside it)
plus a dependency-CVE sweep. Eight of the eleven cloud-infrastructure
findings (`V-CLD-01/02/03/05/06/07/08`) are Week 2 Terraform scope and are
not addressed here; `V-CLD-04` (hardcoded secrets) was addressed because it
was partially observable directly in this repository.

Every finding below has a corresponding fix branch, automated regression
test(s) proving both that the exploit is closed and that legitimate
functionality still works, and an open pull request against `main` tying the
diff back to its tracking issue. All fixes were verified idempotent by
re-running each service's test suite 2–4 times per branch. No finding was
fixed by suppressing or weakening a test — every test added or modified
exercises the actual vulnerable code path.

**What remains open, by design:**
- All 19 PRs (#20–#38) are unmerged. The repository owner is merging them
  manually, in sequence, since each branch builds on the previous fix.
- Git history still contains the original fake/example secrets
  (`scripts/legacy_deploy.sh` and earlier commits). History rewriting
  (`git filter-repo` + force-push) was evaluated and explicitly **declined**
  — it would rewrite a shared fork's history for a destructive operation
  whose benefit (scrubbing clearly-fake training secrets) didn't justify the
  risk. The current secrets were already rotated/removed going forward; see
  §4.12.
- Week 2 (Terraform, `V-CLD-01/02/03/05/06/07/08`) and Week 3 (pipeline gates,
  purple-team simulation) are out of scope for this report.

---

## 2. Methodology

1. **Branch-per-finding.** Each fix lives on its own branch
   (`fix/<finding>` or `feat/<finding>`), branched forward from the previous
   fix so later branches never regress earlier ones.
2. **Red/blue pairing per finding.** Before changing code, the exploit was
   reproduced against the vulnerable path with a failing test. The fix was
   then applied until that test passed, without disabling or loosening any
   pre-existing test.
3. **Regression coverage.** Where a fix touched a shared code path (e.g.
   ownership checks added to `wallets.py` also used by the race-condition
   fix), downstream tests were re-run and, where their setup depended on the
   now-fixed bug, rewritten to use legitimate credentials instead.
4. **Idempotency verification.** Each branch's full test suite was run 2–4
   times in a row to catch state leakage (e.g. rate-limit counters, Redis
   keys) between runs.
5. **PR per finding.** Each PR title and body reference the GitHub issue
   number it closes, for traceability between the vulnerability inventory,
   the code diff, and the issue tracker.

---

## 3. Findings overview

| ID | Title | Severity (indicative) | Branch | PR | Status |
|----|-------|------------------------|--------|----|--------|
| V-APP-01 | SQL injection (transaction search, KYC lookup) | Critical | `fix/v-app-01-sqli` | [#21](../..) | Merged |
| V-APP-02 | Broken JWT validation (`none` alg, unverified signature) | Critical | `fix/v-app-02-jwt` | #20 | Merged |
| V-APP-03 | IDOR — missing ownership checks | Critical | `fix/v-app-03-idor` | #22 | Merged |
| V-APP-04 | SSRF (webhooks, BVN provider override) | High | `fix/v-app-04-ssrf` | #25 | Open |
| V-APP-05 | Wallet debit/credit race condition | High | `fix/v-app-05-wallet-race` | #24 | Merged |
| V-APP-06 | MD5, unsalted password hashing | High | `fix/v-app-06-password-hash` | #26 | Open |
| V-APP-07 | Mass assignment / self-assigned role at register | Critical | `fix/v-app-07-mass-assignment` | #23 | Merged |
| V-APP-08 | No rate limiting (login/register/OTP); weak OTP RNG | High | `fix/v-app-08-rate-limit` | #27 | Open |
| V-APP-09 | Verbose errors / debug mode leaking stack traces | Medium | `fix/v-app-09-error-handling` | #28 | Open |
| V-APP-10 | Insecure deserialisation (`pickle`) in admin session restore | Critical | `fix/v-app-10-pickle` | #29 | Open |
| V-APP-11 | No audit logging for money movement | Medium | `fix/v-app-11-audit-log` | #30 | Open |
| KYC-UPLOAD | Public-read ACL, key traversal, no upload validation | High | `fix/kyc-upload-hardening` | #31 | Open |
| V-CLD-04 | Hardcoded secrets in repo (partial — code-reachable portion) | Critical | `fix/v-cld-04-secrets` | #32 | Open |
| HARDEN-RUNTIME | Containers run as root, no healthchecks, compose defaults | Medium | `fix/runtime-hardening` | #33 | Open |
| DEPS | 89 known CVEs across pinned dependencies | High | `fix/dependency-upgrade` | #34 | Open |
| V-PIP-01 | Unsigned container images | High | `feat/v-pip-01-image-signing` | #35 | Open |
| V-PIP-02 | No SBOM generation | Medium | `feat/v-pip-02-sbom` | #36 | Open |
| V-PIP-03 | Pipeline authenticates with long-lived admin AWS keys | Critical | `feat/v-pip-03-oidc` | #37 | Open |
| V-PIP-04 | No branch protection on `main` | Medium | `feat/v-pip-04-branch-protection` | #38 | Open |

19/19 findings fixed and PR'd. 4/19 merged at time of writing; the remaining
15 are open, awaiting the owner's manual merge.

---

## 4. Findings in detail

### 4.1 V-APP-01 — SQL injection
**Where:** `services/payments-api/app/routes/transactions.py` (search),
`services/kyc-api/app/routes/verify.py` (lookup).
**Issue:** User-supplied search terms and lookup identifiers were
interpolated directly into SQL strings.
**Fix:** Converted every affected query to parameterised queries via
psycopg2 placeholders (`%s`), removing all string formatting/concatenation
of user input into SQL.
**Proof:** Regression test attempts a classic `' OR '1'='1` / stacked-query
payload against both endpoints and asserts no unauthorised rows return and
no 500 is raised from a malformed query; a second test confirms normal
search still returns the expected row.

### 4.2 V-APP-02 — Broken JWT validation
**Where:** `services/payments-api/app/auth.py` (replicated in
`services/kyc-api/app/auth.py`).
**Issue:** JWT signatures were not verified on decode, and the `none`
algorithm was implicitly accepted, allowing a forged token with an arbitrary
`user_id`/`role` claim to authenticate as anyone, including admin.
**Fix:** Decoding now pins `algorithms=["HS256"]` explicitly and verifies
the signature against the configured secret; a forged/unsigned token or one
using `alg: none` is rejected with 401.
**Proof:** Test forges a token with `alg: none` and a privileged claim set
and confirms it's rejected; a correctly-signed token for a real session
still authenticates.

### 4.3 V-APP-03 — IDOR / missing ownership checks
**Where:** `accounts.py`, `wallets.py`, `transactions.py` (payments-api),
`documents.py` (kyc-api).
**Issue:** Any authenticated user could read or mutate any other user's
account, wallet, transaction, or KYC document by ID — no comparison between
the resource owner and the requesting principal.
**Fix:** Added `resource.user_id != request.current_user_id and
request.current_user_role != "admin"` ownership gates (403 on mismatch) to
every by-ID read/write route across both services; `get_transaction` now
joins to `accounts` to resolve the owning user before the check.
**Proof:** Each affected endpoint has a test that creates two users, has
user B attempt to access user A's resource, and asserts 403; a same-user
and an admin-override test confirm legitimate access still works.

### 4.4 V-APP-04 — SSRF
**Where:** `webhooks.py` (register/test), `verify.py` (BVN provider
override).
**Issue:** User-supplied URLs (webhook target, BVN provider override) were
fetched server-side with no validation, allowing requests into the
internal network (metadata endpoints, internal services) via DNS or literal
private-IP targets, and via HTTP redirects.
**Fix:** New `ssrf_guard.is_safe_external_url()` (duplicated in both
services) resolves the hostname and rejects any address that is private,
loopback, link-local, reserved, multicast, or unspecified per the
`ipaddress` module; all outbound calls set `allow_redirects=False`. The BVN
lookup still defaults to a trusted configured URL when no override is
supplied.
**Proof:** Tests target `127.0.0.1`, `169.254.169.254`, and a DNS name that
resolves to a private address, asserting all are rejected before any
request is made; a legitimate public HTTPS URL still passes.

### 4.5 V-APP-05 — Wallet race condition
**Where:** `wallets.py` (`credit_wallet`, `debit_wallet`).
**Issue:** Read-then-write balance updates without row locking allowed
concurrent debits to race past a balance check (classic TOCTOU), enabling
overdraft.
**Fix:** Balance reads inside the transaction now use `SELECT ... FOR
UPDATE`, serialising concurrent credit/debit operations on the same
account.
**Proof:** Test fires concurrent debit requests against a fixed starting
balance sufficient for only one to succeed, and asserts the final balance
never goes negative and exactly the expected number of debits succeeded.

### 4.6 V-APP-06 — Weak password hashing
**Where:** `payments-api/app/auth.py`.
**Issue:** Passwords were hashed with unsalted MD5.
**Fix:** `hash_password()` now uses werkzeug's `generate_password_hash`
(scrypt by default in werkzeug 3.1); `verify_password()` detects legacy
32-hex-char MD5 hashes via constant-time comparison and transparently
rehashes to the modern format on successful legacy login, so no forced
password reset is needed.
**Proof:** Test confirms a freshly-hashed password is not a bare 32-char hex
string (algorithm-agnostic, since werkzeug's default scheme can change);
a second test logs in with a seeded legacy MD5 hash and confirms the stored
hash is upgraded afterward.

### 4.7 V-APP-07 — Mass assignment / self-assigned role
**Where:** `accounts.py` (`update_profile`), `auth.py` (`register`).
**Issue:** `update_profile` wrote any client-supplied field (including,
depending on input, privileged columns) straight into the `UPDATE`
statement; `register` accepted a client-supplied `role`, letting any
self-registering user become `admin`.
**Fix:** `update_profile` now allow-lists `UPDATABLE_PROFILE_FIELDS =
{"currency"}` and rejects any other field with 400; `register` hardcodes
`role = "merchant"` regardless of request body.
**Proof:** Test posts `{"role": "admin"}` at registration and confirms the
created user's role is `merchant`; a second test posts an unexpected field
to profile update and confirms 400 with no DB write.

### 4.8 V-APP-08 — No rate limiting; weak OTP
**Where:** `auth.py` (`register`, `login`, `request_otp`).
**Issue:** No limits on login attempts, registration, or OTP requests;
OTP codes were generated with `random.randint` (not cryptographically
secure) and were logged via `print()`.
**Fix:** Redis-backed rate limiting: increment-based for register/OTP,
failure-counted-with-reset-on-success for login (so legitimate repeated
logins aren't penalised). OTP generation switched to
`secrets.randbelow()`; all debug `print()` logging of OTP values removed.
**Proof:** Test exceeds each endpoint's limit and asserts 429; a login test
confirms the failure counter resets after a successful login so a
legitimate user isn't locked out by their own earlier typos.

### 4.9 V-APP-09 — Verbose errors / debug mode
**Where:** `main.py` (both services).
**Issue:** Unhandled exceptions returned full stack traces to the client;
Flask debug mode could be left on in non-development environments.
**Fix:** Global exception handler logs full detail server-side
(`app.logger.error(..., exc_info=True)`) and returns only a generic 500 to
the client; `app.run(debug=...)` is now gated on
`ENVIRONMENT == "development"`.
**Proof:** Test triggers an unhandled exception path and asserts the
response body contains no traceback, file path, or exception class name.

### 4.10 V-APP-10 — Insecure deserialisation
**Where:** `admin.py` (`restore_session`).
**Issue:** `pickle.loads()` on client-influenced data allows arbitrary code
execution via a crafted `__reduce__` gadget.
**Fix:** Replaced with `json.loads()` plus an explicit `isinstance(session,
dict)` check.
**Proof:** Test supplies a pickle payload with a `__reduce__` side effect
and confirms it is rejected/raises cleanly rather than executing; a
legitimate JSON session blob still restores.

### 4.11 V-APP-11 — No audit logging
**Where:** New `audit.py`; wired into `wallets.py` credit/debit,
`accounts.py` profile update, `auth.py` register.
**Issue:** No record of who moved money or changed sensitive account state.
**Fix:** New `audit_log` table (created defensively at app startup, not
only via migration) with a best-effort `log_event()` helper that never
raises into the request path on logging failure.
**Proof:** Test performs a credit/debit/profile-update and asserts a
corresponding row exists in `audit_log` with the correct actor, action, and
metadata.

### 4.12 KYC-UPLOAD — Public ACL, key traversal, no validation
**Where:** `kyc-api/app/routes/documents.py`.
**Issue:** Uploaded documents were stored with `ACL="public-read"`
(internet-readable KYC documents), no server-side encryption, no file-type
or size validation, and the client-influenced filename was used directly in
the S3 key (path traversal risk).
**Fix:** Removed the public ACL; added `ServerSideEncryption="AES256"`;
added an extension allow-list (`.jpg`, `.jpeg`, `.png`, `.pdf`) and a 10 MB
size cap; keys are now built from `secure_filename()` plus a `uuid4` prefix
under `users/{user_id}/...`, and `get_document` enforces the same ownership
prefix check as other V-APP-03 fixes.
**Proof:** Tests attempt an oversized file, a disallowed extension, and a
traversal-style filename (`../../etc/passwd`), asserting all are rejected;
a legitimate upload is retrievable only by its owner.

### 4.13 V-CLD-04 — Hardcoded secrets (repo-visible portion)
**Where:** `scripts/legacy_deploy.sh`, `.env.example`, `docker-compose.yml`,
`README.md`.
**Issue:** A deploy script committed a fake Slack webhook, a fake partner
API key, and a fake production DB password; `docker-compose.yml` had
literal `POSTGRES_PASSWORD`/AWS key values; `.env.example` showed
secret-shaped literal values instead of placeholders; the README printed a
literal DB password.
**Fix:** Deleted `scripts/legacy_deploy.sh` entirely; `docker-compose.yml`
now interpolates `${POSTGRES_PASSWORD}`, `${AWS_ACCESS_KEY_ID}`,
`${AWS_SECRET_ACCESS_KEY}` from the environment; `.env.example` rewritten
with placeholder values; README updated to point at `.env` instead of
printing a password.
**Scope note:** This closes the finding going forward. The same
fake/example values remain visible in git history on earlier commits.
History rewriting to remove them was considered and **declined** by the
repository owner — it is a destructive, shared-history operation, and the
exposed values are training/example secrets, not live credentials.

### 4.14 HARDEN-RUNTIME — Container and compose hardening
**Where:** Both `Dockerfile`s, `docker-compose.yml`.
**Issue:** Containers ran as root with no healthcheck; compose had no
restart policy and no privilege-escalation restrictions.
**Fix:** `python:3.11` → `python:3.11-slim`; added a non-root `app` user
(`groupadd`/`useradd --no-create-home`) and switched to it via `USER app`;
added `HEALTHCHECK`; compose gained `restart: unless-stopped`,
`security_opt: [no-new-privileges:true]` on all services, and
`cap_drop: [ALL]` on the two application services.
**Proof:** Confirmed via `docker compose exec ... whoami` returning `app`,
not `root`; confirmed `pip install -r requirements-dev.txt` for the test
suite still works by moving dev-dependency installation into the image
build step (before the `USER` switch), since installing as a non-root user
against root-owned site-packages at runtime fails silently.

### 4.15 DEPS — Vulnerable dependencies
**Where:** Both services' `requirements.txt`/`requirements-dev.txt`.
**Issue:** `pip-audit` reported 89 known CVEs across pinned versions,
concentrated in `flask==2.0.1`, `werkzeug==2.0.3`, `cryptography`, and
`requests`.
**Fix:** Upgraded to `flask==3.1.3`, `werkzeug==3.1.9`,
`psycopg2-binary==2.9.9`, `redis==5.3.1`, `pyjwt==2.15.1`,
`cryptography==50.0.2`, `requests==2.34.2`, `boto3==1.40.76`,
`gunicorn==24.1.1`; `moto` bumped `4.2.14` → `5.2.5` in kyc-api's dev
dependencies (with the corresponding `mock_s3()` → `mock_aws()` API
migration in its test suite). The Flask 3.x migration required replacing
the removed `app.json_encoder` hook with a `JSONProvider` subclass.
**Proof:** `pip-audit` run against both services' final requirements
reports zero known vulnerabilities; full test suites pass unchanged after
the upgrade.

### 4.16 V-PIP-01 — Unsigned container images
**Where:** `.github/workflows/ci.yml`, new `scripts/verify_image_signature.sh`.
**Issue:** Images were pushed to ECR with no signing — nothing to confirm a
deployed image came from this pipeline.
**Fix:** `build-and-push` now signs every pushed image keylessly with
`cosign`, using the job's GitHub Actions OIDC identity token (no signing
key to generate, store, or leak). A new `verify-signature` job and the
`deploy` job both verify the signature via `scripts/verify_image_signature.sh`
before anything downstream (including ECS deployment) trusts the image.
**Proof:** Static pipeline test confirms cosign install + sign steps and
`id-token: write` are present, the verify script exists and is executable,
and that the verify script itself fails closed (non-zero exit) when run
with no arguments.

### 4.17 V-PIP-02 — No SBOM generation
**Where:** `.github/workflows/ci.yml`.
**Issue:** No software bill of materials was produced for any built image.
**Fix:** `build-and-push` now generates a CycloneDX SBOM per image with
Syft, attaches it to the image digest via `cosign attach sbom`, signs the
attachment, and uploads it as a retrievable workflow artifact — not merely
produced and discarded.
**Proof:** Static pipeline test confirms Syft + CycloneDX generation,
`cosign attach sbom` + a signature over the attachment, and an
`upload-artifact` step for the SBOM, all outside commented-out text (to
avoid a false pass against a step that only *mentions* these tools).

### 4.18 V-PIP-03 — Pipeline has administrator AWS access
**Where:** `.github/workflows/ci.yml`.
**Issue:** `build-and-push` and `deploy` authenticated to AWS using a
long-lived access key pair from an IAM user with `AdministratorAccess`,
stored as repository secrets.
**Fix:** Both jobs now federate via GitHub's OIDC provider
(`aws-actions/configure-aws-credentials` with `role-to-assume`), requesting
`permissions: id-token: write`. No long-lived key pair is used or stored.
The deploy role's actual permission scope is Week 2 Terraform work — this
fix only removes the long-lived-key authentication method itself.
**Proof:** Static pipeline test confirms no `secrets.AWS_ACCESS_KEY_ID`/
`AWS_SECRET_ACCESS_KEY` reference remains, `role-to-assume:` is present, and
(via a YAML-aware check, not text matching) every job that assumes a role
also declares `id-token: write` on itself — since the combination silently
fails at runtime otherwise, not just cosmetically.

### 4.19 V-PIP-04 — No branch protection on `main`
**Where:** GitHub repository settings (not expressible in `ci.yml`).
**Issue:** `main` had no branch protection — any push, including a direct
force-push or deletion, could land without review or passing checks.
**Fix:** Configured via the GitHub API: required status checks (`test
(payments-api)`, `test (kyc-api)`), `enforce_admins: true`, force-push and
branch deletion blocked. **Deliberately not required:** PR approving
reviews — this fork has one collaborator, and GitHub does not allow a PR
author to approve their own PR, so requiring reviews would have locked the
owner out of merging their own fixes. This can be added back the moment a
second collaborator exists.
**Proof:** A live test (not a static file check) queries
`gh api repos/.../branches/main/protection` and asserts status checks are
required and force-push/deletion are blocked.

---

## 5. Testing summary

- `payments-api` test suite: 39 tests, all passing, re-run 2–4× per fix
  branch to confirm idempotency (no leaked Redis/rate-limit/DB state
  between runs).
- `kyc-api` test suite: 15 tests, all passing, same idempotency check.
- `tests/pipeline/`: 4 standalone test modules (`test_v_pip_01` through
  `test_v_pip_04`) statically verify the CI workflow's content for
  V-PIP-01/02/03, and `test_v_pip_04` queries live GitHub branch-protection
  state for V-PIP-04.
- No test was weakened, skipped, or deleted to make a fix pass; where a
  downstream test's setup depended on a since-fixed vulnerability (e.g. a
  race-condition test that originally exploited the V-APP-03 ownership gap
  to seed its fixture), it was rewritten against the seeded admin account
  instead of the exploit path.

---

## 6. Residual risk and recommendations

1. **Merge order matters.** PRs #21–#38 each build on the branch before it.
   Merging out of order (or merging #30 before #29, for example) will
   produce conflicts or reintroduce an already-fixed line. Merge in
   ascending PR number order.
2. **Branch protection has no required reviewer** by design (§4.19). If a
   second collaborator joins the repository, re-enable
   `required_pull_request_reviews` immediately — the current configuration
   is a deliberate, temporary trade-off for a solo maintainer, not a
   permanent policy.
3. **Git history still contains example secrets.** They are fake
   (training-only) values, but anyone cloning the repository's full history
   will still see them. No action taken by design (§4.13); revisit only if
   this repository is ever used as a template with real values substituted
   in at any point in its history.
4. **Week 2 scope is untouched.** `V-CLD-01/02/03/05/06/07/08` (public RDS,
   unencrypted/public S3, overbroad IAM, missing CloudTrail integrity,
   GuardDuty disabled, no flow logs) require the Terraform-managed
   infrastructure described in `docs/ARCHITECTURE_NOTES.md`'s target state
   and are not addressed by anything in this report.
5. **The pipeline's `test` job still uses `continue-on-error: true`**
   (§ci.yml header comment). This was intentionally left out of scope — it
   wasn't one of the four tracked V-PIP findings — but it means the
   pipeline can still report green with failing tests. Worth flagging for
   Week 3's pipeline-gate work.

---

## 7. Appendix — PR reference

| PR | Finding | Branch |
|----|---------|--------|
| #20 | V-APP-02 | `fix/v-app-02-jwt` |
| #21 | V-APP-01 | `fix/v-app-01-sqli` |
| #22 | V-APP-03 | `fix/v-app-03-idor` |
| #23 | V-APP-07 | `fix/v-app-07-mass-assignment` |
| #24 | V-APP-05 | `fix/v-app-05-wallet-race` |
| #25 | V-APP-04 | `fix/v-app-04-ssrf` |
| #26 | V-APP-06 | `fix/v-app-06-password-hash` |
| #27 | V-APP-08 | `fix/v-app-08-rate-limit` |
| #28 | V-APP-09 | `fix/v-app-09-error-handling` |
| #29 | V-APP-10 | `fix/v-app-10-pickle` |
| #30 | V-APP-11 | `fix/v-app-11-audit-log` |
| #31 | KYC-UPLOAD | `fix/kyc-upload-hardening` |
| #32 | V-CLD-04 | `fix/v-cld-04-secrets` |
| #33 | HARDEN-RUNTIME | `fix/runtime-hardening` |
| #34 | DEPS | `fix/dependency-upgrade` |
| #35 | V-PIP-01 | `feat/v-pip-01-image-signing` |
| #36 | V-PIP-02 | `feat/v-pip-02-sbom` |
| #37 | V-PIP-03 | `feat/v-pip-03-oidc` |
| #38 | V-PIP-04 | `feat/v-pip-04-branch-protection` |
