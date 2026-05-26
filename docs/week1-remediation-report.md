# Week 1 Remediation Report

## 1. Overview

Week 1 focused on establishing an application security baseline for the SentinelPay system, identifying high-risk vulnerabilities, and remediating the most critical authentication, authorisation, data access, and transaction integrity issues.

The work covered repository discovery, local environment setup, threat modelling, automated scanning, manual code review, remediation, and post-remediation validation. The main services reviewed were:

- `payments-api`
- `kyc-api`
- PostgreSQL database
- Redis cache
- Docker Compose local deployment

The remediation work prioritised issues that could directly affect user authentication, account access, payment integrity, KYC data exposure, and service-to-service trust.

---

## 2. Work Completed

| Area | Status |
|---|---|
| Repository discovery and local setup | Completed |
| Docker Compose environment validation | Completed |
| Threat modelling using STRIDE | Completed |
| Automated scanning with Semgrep, Bandit, and Gitleaks | Completed |
| Manual code review of authentication, authorisation, and wallet logic | Completed |
| SQL injection remediation | Completed |
| Broken JWT validation remediation | Completed |
| IDOR/account ownership remediation | Completed |
| Wallet race condition remediation | Completed |
| Argon2id password hashing implementation | Completed |
| JWT RS256 signing with key rotation support | Completed |
| Internal request signing | Completed |
| Structured audit logging | Completed |
| Post-remediation scans | Completed |

---

## 3. Key Risks Identified Before Remediation

The initial review identified several high-risk application security weaknesses:

| ID | Risk | Impact |
|---|---|---|
| V-01 | Broken JWT validation | Attackers could forge or tamper with tokens and impersonate users. |
| V-02 | SQL injection | Attackers could manipulate unsafe database queries and access or modify sensitive data. |
| V-03 | Weak password hashing using MD5 | Password hashes could be cracked quickly if exposed. |
| V-04 | IDOR/account ownership weakness | Users could access accounts or transactions belonging to other users. |
| V-05 | Wallet race condition | Concurrent debit requests could result in inconsistent balances. |
| V-06 | Mass assignment | Users could submit unexpected fields and modify protected account attributes. |
| V-07 | Missing audit logging | Security-sensitive activity lacked structured traceability. |
| V-08 | Hardcoded secrets | Exposed credentials or tokens could be abused if valid. |
| V-09 | Insecure deserialisation using pickle | Untrusted serialized data could lead to code execution risk. |
| V-10 | Flask debug mode enabled | Debug mode could expose sensitive information or unsafe debugger behaviour. |
| V-11 | Containers running without explicit non-root users | A compromised application process could gain unnecessary container privileges. |

---

## 4. Remediation Completed

### 4.1 JWT Authentication Hardening

The previous JWT implementation accepted unsafe token configurations and relied on weaker shared-secret handling. This was remediated by implementing RS256-based JWT signing.

Completed actions:

- Removed unsafe JWT validation behaviour.
- Enforced signature verification.
- Added issuer validation.
- Added token expiry validation.
- Migrated JWT signing from HS256 to RS256.
- Configured `payments-api` to sign tokens using a private key.
- Configured `payments-api` and `kyc-api` to verify tokens using public keys.
- Added `kid` support for key rotation.
- Stored public keys in a public key map file.
- Ensured the KYC API does not require the private signing key.

Security improvement:

The KYC API can now verify tokens without possessing the private signing key. If the KYC service is compromised, an attacker cannot use the public key to generate valid tokens.

---

### 4.2 Argon2id Password Hashing

The previous password hashing approach used MD5, which is unsuitable for password storage because it is fast, old, and vulnerable to cracking attacks.

Completed actions:

- Replaced MD5 password hashing with Argon2id.
- Added `argon2-cffi` to the payments API dependencies.
- Updated seeded user password hashes to Argon2id format.
- Rebuilt the local environment and confirmed login functionality.

Security improvement:

Passwords are now protected using a modern password hashing algorithm designed to resist brute-force and GPU-based cracking attacks.

---

### 4.3 SQL Injection Remediation

Unsafe SQL query construction was identified in KYC lookup and payment-related routes. These were remediated using parameterised queries.

Completed actions:

- Replaced unsafe string interpolation in SQL queries.
- Used parameterised SQL execution for BVN and NIN lookup.
- Used parameterised SQL for transaction search and account access.
- Retained functional API behaviour while removing direct user-controlled SQL construction.

Security improvement:

User input is now passed as query parameters rather than being concatenated into SQL statements. This reduces the risk of database manipulation and unauthorised data access.

---

### 4.4 IDOR and Account Ownership Controls

Account and transaction routes were reviewed for object-level authorisation weaknesses.

Completed actions:

- Enforced `user_id` ownership checks on account lookup.
- Restricted account listing to the authenticated user.
- Enforced ownership checks on transaction search and transaction lookup.
- Returned generic not-found responses for unauthorised account access attempts.

Security improvement:

Authenticated users can only access their own accounts and transactions. This reduces the risk of horizontal privilege escalation.

---

### 4.5 Wallet Transaction Integrity

Wallet credit and debit logic was improved to reduce financial integrity risk.

Completed actions:

- Added account ownership checks before wallet operations.
- Added positive amount validation.
- Added database transaction handling.
- Added row-level locking using `SELECT ... FOR UPDATE`.
- Added rollback behaviour on failed wallet operations.
- Generated transaction references for successful wallet operations.

Security improvement:

Wallet balances are now updated more safely under concurrent access, reducing the likelihood of race-condition abuse or inconsistent balances.

---

### 4.6 Mass Assignment Mitigation

The account profile update endpoint previously accepted user-supplied fields in a way that could lead to unsafe modification of protected account attributes.

Completed actions:

- Removed arbitrary field update behaviour.
- Verified account ownership before profile update handling.
- Rejected profile updates where no safe user-editable fields are defined.
- Added audit logging for rejected profile update attempts.

Security improvement:

Users can no longer submit arbitrary account fields such as balance, status, currency, or user ID for update through the profile endpoint.

---

### 4.7 Internal Request Signing

Request signing was added to protect internal service-to-service communication.

Completed actions:

- Added `INTERNAL_SIGNING_SECRET` to both API services in the local Docker Compose environment.
- Created request signing helpers for both APIs.
- Implemented HMAC-SHA256 request signatures.
- Included HTTP method, request path, timestamp, and body hash in the signature calculation.
- Added timestamp tolerance to reduce replay risk.
- Protected the internal KYC BVN endpoint with request signature validation.

Security improvement:

The internal KYC route now requires both a valid JWT and a valid internal request signature. This provides an additional layer of trust between services and helps detect tampered internal requests.

---

### 4.8 Structured Audit Logging

Structured JSON audit logging was added for important security and financial actions.

Completed actions:

- Created reusable `audit.py` helper in both APIs.
- Added audit events for login success and failure.
- Added audit events for account lookup and account listing.
- Added audit events for wallet credit and debit operations.
- Added audit events for failed wallet operations, including invalid amounts and insufficient funds.
- Added audit events for transaction search and lookup.
- Added audit events for KYC lookup and BVN verification.

Example audit event types include:

- `auth.login.success`
- `auth.login.failed`
- `account.lookup.success`
- `account.lookup.denied`
- `wallet.credit.success`
- `wallet.debit.success`
- `wallet.debit.failed`
- `transaction.search.success`
- `kyc.lookup.success`
- `kyc.bvn.failed`

Security improvement:

Sensitive operations now produce structured logs that can be ingested into a SIEM or log monitoring platform for investigation, alerting, and compliance evidence.

---

## 5. Post-Remediation Scan Summary

Post-remediation scans were run using Semgrep, Bandit, and Gitleaks.

### 5.1 Bandit Summary

Bandit reported 9 remaining issues:

| Severity | Count | Main Findings |
|---|---:|---|
| High | 2 | Flask debug mode enabled in both APIs |
| Medium | 3 | Bind-all-interfaces and unsafe pickle deserialisation |
| Low | 4 | Pickle import and assert statements in test files |

Key observation:

The previous MD5 password hashing finding is no longer present in the post-remediation Bandit scan, confirming that the Argon2id migration addressed that issue.

---

### 5.2 Semgrep Summary

Semgrep reported 11 remaining findings. The main categories were:

| Category | Finding |
|---|---|
| Secrets | Stripe-like key detected in legacy/evidence files |
| Container security | Missing non-root `USER` in Dockerfiles |
| Flask configuration | Debug mode enabled |
| Network exposure | Flask app bound to `0.0.0.0` |
| Deserialisation | Unsafe `pickle.loads()` usage |

Key observation:

The previous high-risk SQL injection and unsafe JWT validation findings are no longer present in the post-remediation Semgrep output. This indicates that the main Week 1 code-level remediations were effective.

---

### 5.3 Gitleaks Summary

Gitleaks reported 6 findings. These relate mainly to:

- Slack webhook-style values
- Stripe-style API key values
- Findings inside previous scan output files
- Findings inside `scripts/legacy_deploy.sh`

Key observation:

Some findings appear in stored scan evidence under `docs/scans/`, meaning the scan reports themselves contain examples of detected secrets. These should be handled carefully because security scan evidence can accidentally preserve sensitive values.

---

## 6. Remaining Risks

The following issues remain open after Week 1 and should be addressed in the next remediation cycle.

| Risk | Location | Priority | Recommended Action |
|---|---|---|---|
| Flask debug mode enabled | `payments-api/app/main.py`, `kyc-api/app/main.py` | High | Make debug mode environment-controlled and disabled by default. |
| Bind to all interfaces | `payments-api/app/main.py`, `kyc-api/app/main.py` | Medium | Use production WSGI server and avoid direct Flask development server for deployment. |
| Unsafe pickle deserialisation | `payments-api/app/routes/admin.py` | High | Replace pickle with JSON or remove unsafe session restore functionality. |
| Hardcoded/fake secrets | `scripts/legacy_deploy.sh`, scan evidence | High | Remove secrets from code and historical scan evidence; use secret placeholders or secret manager references. |
| Missing non-root Docker users | API Dockerfiles | Medium | Add non-root users in both Dockerfiles. |
| SSRF risk in BVN provider URL | `kyc-api/app/routes/verify.py` | High | Remove user-controlled provider URL or enforce strict allowlisting. |
| No rate limiting | Login, OTP, wallet routes | Medium | Add rate limiting using Flask-Limiter or gateway/WAF controls. |
| Dev secret in Compose | `INTERNAL_SIGNING_SECRET` | Medium | Move to Docker secrets, `.env`, or cloud secret management. |
| Scan evidence contains secret-like values | `docs/scans/` | Medium | Redact sensitive values before committing reports. |

---

## 7. Evidence Produced

The following artefacts support the Week 1 work:

- `docs/Repo-Discovery.md`
- `docs/threat-model-scanning.md`
- `docs/manual-code-review.md`
- `docs/scans/semgrep-after-week1.txt`
- `docs/scans/bandit-after-week1.txt`
- `docs/scans/gitleaks-after-week1.json`
- Git commits for authentication remediation
- Git commits for SQL injection and IDOR remediation
- Git commits for wallet transaction safety
- Git commits for Argon2id password hashing
- Git commits for JWT RS256 key rotation support
- Git commits for request signing
- Git commits for structured audit logging

---

## 8. Overall Outcome

Week 1 successfully reduced the most critical application-layer risks in the SentinelPay system.

The main security improvements were:

- Stronger password storage using Argon2id
- Safer JWT authentication using RS256 and `kid`-based key rotation support
- Safer SQL execution through parameterised queries
- Object-level authorisation for account and transaction access
- Safer wallet update handling using ownership checks and row-level locking
- Internal request signing for protected service-to-service routes
- Structured JSON audit logging for security-sensitive actions

The post-remediation scans show that several major risks were addressed, including weak password hashing, unsafe JWT validation, and SQL injection patterns. However, the scans also confirm that some issues remain, particularly debug mode, pickle deserialisation, secret hygiene, SSRF risk, and container hardening.

---

## 9. Conclusion

The Week 1 remediation work established a stronger security baseline for SentinelPay. The highest-risk authentication, authorisation, SQL injection, and wallet integrity issues were remediated, and additional defence-in-depth controls were added through RS256 JWT signing, internal request signing, and structured audit logging.

The system is not yet production-ready, but it is significantly improved from its initial vulnerable baseline. The next sprint should focus on secret management, production-safe Flask configuration, SSRF prevention, unsafe deserialisation removal, container hardening, and CI/CD security gates.