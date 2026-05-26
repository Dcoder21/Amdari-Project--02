# Threat Model and Scanning

## 1. Objective

The objective of Day 2 is to produce a STRIDE-based threat model for the SentinelPay application, identify trust boundaries, document a threat register, and run initial automated security scans using Semgrep, Bandit, and Gitleaks.

## 2. Scope

This assessment covers the local SentinelPay application stack:

- payments-api
- kyc-api
- PostgreSQL
- Redis
- Docker Compose configuration
- Application source code
- Repository secrets and configuration files

The focus is on application-layer threats, trust boundaries, and early vulnerability discovery before remediation begins.

## 3. System Assets

| Asset | Description | Security Concern |
|---|---|---|
| User accounts | Merchant/admin user identities | Account takeover, privilege abuse |
| JWT tokens | Authentication/session tokens | Token forgery, impersonation |
| Account records | Merchant account details | IDOR, unauthorised access |
| Transactions | Payment and wallet transaction records | Data exposure, tampering |
| Wallet balances | Financial balances | Race conditions, unauthorised debit/credit |
| KYC records | BVN/NIN and identity verification data | Sensitive data exposure |
| KYC documents | Uploaded identity documents | Unauthorised access, insecure storage |
| Webhook URLs | Merchant callback destinations | SSRF |
| Database credentials | App-to-database access | Secret leakage |
| AWS-style keys/config values | Cloud-related credentials/config | Secret sprawl, cloud abuse |

## 4. Main Services

| Service | Port | Role |
|---|---:|---|
| payments-api | 8001 | Handles authentication, accounts, transactions, wallets, webhooks, and admin functions |
| kyc-api | 8002 | Handles KYC verification and document-related operations |
| PostgreSQL | 5432 | Stores application data |
| Redis | 6379 | Supports cache/session/idempotency functionality |

## 5. Data Flows

### DF-01: User Authentication

Client sends login/register request to payments-api. The API checks user data in PostgreSQL and returns a JWT token after successful login.

### DF-02: Account and Transaction Access

Authenticated client sends requests to payments-api. The API queries PostgreSQL for account and transaction data and returns the response.

### DF-03: Wallet Debit/Credit

Authenticated client sends wallet debit or credit requests to payments-api. The API reads and updates balances in PostgreSQL.

### DF-04: KYC Verification

Client sends BVN/NIN verification request to kyc-api. The API processes identity-related data and stores or retrieves KYC records.

### DF-05: KYC Document Handling

Client uploads or retrieves identity documents through kyc-api. Document-related data is handled by the API and linked to KYC records.

### DF-06: Webhook Testing

Client submits webhook callback URLs to payments-api. The API makes outbound requests to the supplied URL.

## 6. Trust Boundaries

| Boundary ID | Trust Boundary | Description |
|---|---|---|
| TB-01 | External client to payments-api | Untrusted users send requests into the payments API |
| TB-02 | External client to kyc-api | Untrusted users send KYC-related requests |
| TB-03 | API services to PostgreSQL | Application services access the database |
| TB-04 | API services to Redis | Application services interact with cache/session data |
| TB-05 | payments-api to external webhook URL | Application sends outbound requests to user-controlled URLs |
| TB-06 | kyc-api to document storage/KYC records | Sensitive identity data crosses into storage |
| TB-07 | Developer/repository to runtime environment | Code and configuration move from repository into running containers |

## 7. STRIDE Threat Register

| ID | STRIDE Category | Trust Boundary / Area | Threat Scenario | Impact | Likelihood | Initial Risk | Suggested Control |
|---|---|---|---|---|---|---|---|
| T-01 | Spoofing | TB-01: External client to payments-api | An attacker forges or manipulates JWT tokens to impersonate another user or administrator. | Unauthorised access to accounts, transactions, wallet operations, or admin functions. | High | Critical | Use strong JWT validation, reject `alg:none`, use asymmetric signing, rotate keys, and validate claims properly. |
| T-02 | Spoofing | TB-02: External client to kyc-api | An attacker reuses or forges a token to access KYC verification or document endpoints. | Exposure of sensitive identity data such as BVN/NIN records or documents. | High | Critical | Enforce consistent token validation across both APIs and verify user/service permissions per request. |
| T-03 | Tampering | payments-api wallet endpoints | An authenticated user manipulates wallet debit or credit requests to alter balances. | Financial loss, incorrect balances, fraud, and loss of transaction integrity. | High | Critical | Enforce ownership checks, validate transaction amounts, use database transactions and row-level locking. |
| T-04 | Tampering | payments-api profile update | A user submits unexpected fields in a profile update request, such as role or privilege-related fields. | Unauthorised privilege or account data modification. | Medium | High | Use allow-listed fields only and reject unknown/sensitive fields. |
| T-05 | Tampering | Repository to runtime environment | A developer or compromised account modifies insecure code or pipeline configuration without review. | Vulnerable code reaches runtime, weakening the production environment. | Medium | High | Require branch protection, peer review, required checks, and signed/verified build artefacts. |
| T-06 | Repudiation | Wallet and transaction operations | A user performs a sensitive action such as debit, credit, or profile update, but the system does not create reliable audit logs. | Difficult incident investigation, weak fraud analysis, and poor compliance evidence. | High | High | Add structured audit logging for authentication, account access, wallet movement, KYC access, and admin actions. |
| T-07 | Repudiation | Admin operations | An administrator restores a session or views users without sufficient audit trail. | Admin misuse may be difficult to prove or investigate. | Medium | High | Log admin actions with actor, target, timestamp, source IP, request ID, and outcome. |
| T-08 | Information Disclosure | Account and transaction endpoints | An authenticated user changes an account ID or transaction reference to view another user’s data. | Exposure of financial account and transaction information. | High | Critical | Enforce object-level authorisation and ownership checks on every account and transaction lookup. |
| T-09 | Information Disclosure | kyc-api document endpoints | A user fetches KYC documents using predictable or unauthorised document keys. | Exposure of identity documents and regulated personal data. | High | Critical | Enforce ownership checks, use non-guessable object keys, avoid direct public access, and log access. |
| T-10 | Information Disclosure | Error handling | The API returns verbose stack traces or internal error details. | Attackers learn internal paths, libraries, queries, and implementation details. | Medium | Medium | Replace verbose errors with generic responses and log details server-side only. |
| T-11 | Information Disclosure | Repository/configuration | Secrets, credentials, or AWS-style keys are stored in source code, config, Docker Compose, or git history. | Cloud/database compromise and unauthorised access to sensitive systems. | High | Critical | Remove secrets from code, rotate exposed credentials, use Secrets Manager, and enforce Gitleaks scanning. |
| T-12 | Denial of Service | Authentication and OTP endpoints | An attacker repeatedly calls login, registration, or OTP endpoints. | Account lockout, brute-force attempts, service degradation, and SMS/email cost abuse. | High | High | Add rate limiting, lockout controls, bot protection, and monitoring. |
| T-13 | Denial of Service | Webhook testing endpoint | An attacker submits slow or unreachable webhook URLs, causing worker exhaustion. | API slowdown, thread exhaustion, or outbound request abuse. | Medium | High | Add timeouts, destination validation, allow/block lists, and async processing where appropriate. |
| T-14 | Denial of Service | Transaction search and KYC lookup | An attacker submits expensive search queries or repeated lookup requests. | Database performance degradation and API instability. | Medium | High | Add query limits, pagination, rate limiting, indexes, and input validation. |
| T-15 | Elevation of Privilege | Admin endpoints | A normal user manipulates tokens, session restore, or role fields to access admin-only functions. | Full user data exposure and administrative abuse. | High | Critical | Enforce role-based access checks, secure session handling, remove unsafe deserialisation, and test admin boundaries. |
| T-16 | Elevation of Privilege | Pipeline/deployment identity | A compromised GitHub Actions identity has excessive AWS privileges. | Source compromise becomes cloud compromise. | Medium | Critical | Use GitHub OIDC, least-privilege IAM roles, scoped permissions, and environment approvals. |

## 8. Threat Model Summary

The highest-risk areas identified during threat modelling are authentication/session handling, object-level authorisation, wallet integrity, KYC document access, secret exposure, and deployment pipeline permissions.

The most serious threats are those that could allow an attacker to impersonate another user, access another merchant’s financial or KYC data, alter wallet balances, or compromise cloud resources through leaked credentials or over-privileged deployment roles.

The next step is to validate these threat assumptions using automated scanning and manual code review. Semgrep and Bandit will be used to identify insecure Python patterns, while Gitleaks will be used to identify hardcoded secrets in the repository and git history.

## 9. Automated Scanning Plan

The following tools were selected for initial vulnerability discovery:

| Tool | Purpose | Target |
|---|---|---|
| Semgrep | Static analysis for insecure coding patterns and application security issues | Application source code |
| Bandit | Python-specific security scanning | Python services |
| Gitleaks | Secret scanning for hardcoded credentials and tokens | Repository files and git history |

Scanner outputs are saved under:

```text
docs/scans/
```

## 10. Automated Scan Results Summary

Automated scanning was performed using Semgrep, Bandit, and Gitleaks. The scan outputs were saved under `docs/scans/`.

| Tool | Purpose | Output |
|---|---|---|
| Semgrep | Static analysis for insecure code/config patterns | `docs/scans/semgrep.txt`, `docs/scans/semgrep.json` |
| Bandit | Python-specific security scanning | `docs/scans/bandit.txt`, `docs/scans/bandit.json` |
| Gitleaks | Secret scanning | `docs/scans/gitleaks.json` |

The raw scanner output contained duplicate alerts across tools. Findings were therefore reviewed and deduplicated into the vulnerability inventory below.

## 11. Severity-Ranked Vulnerability Inventory

| ID | Severity | Finding | Evidence | Impact | Recommended Fix |
|---|---|---|---|---|---|
| V-01 | Critical | Broken JWT validation | Semgrep flagged `alg:none` and disabled signature verification in `services/payments-api/app/auth.py` and `services/kyc-api/app/auth.py`. | Attackers may forge tokens and impersonate users or administrators. | Reject `alg:none`, enable signature verification, use strong signing keys, and validate issuer, expiry, audience, and role claims. |
| V-02 | Critical | SQL injection in transaction/KYC lookup | Semgrep and Bandit flagged string-based SQL construction in transaction search and KYC lookup routes. | Attackers may read or manipulate sensitive transaction or KYC data. | Replace string interpolation with parameterised queries. |
| V-03 | Critical | Hardcoded secrets in repository | Gitleaks identified a Slack webhook URL and Stripe-style live API key in `scripts/legacy_deploy.sh`. | Exposed secrets could allow unauthorised third-party API use or data leakage. | Remove secrets from code, rotate exposed credentials, purge secrets from git history, and enforce secret scanning in CI. |
| V-04 | High | Weak password hashing using MD5 | Semgrep and Bandit flagged MD5 password hashing in `services/payments-api/app/auth.py`. | Password hashes can be cracked quickly if the database is exposed. | Replace MD5 with Argon2id or bcrypt with unique salts and safe parameters. |
| V-05 | High | Insecure deserialisation using pickle | Semgrep and Bandit flagged `pickle.loads()` in `services/payments-api/app/routes/admin.py`. | A malicious session blob could lead to arbitrary code execution. | Remove pickle usage and use safe formats such as JSON with strict schema validation. |
| V-06 | High | Flask debug mode enabled | Semgrep and Bandit flagged `debug=True` in both API services. | Debug mode may expose stack traces or interactive debugger behaviour in unsafe environments. | Disable debug mode by default and control it through environment-specific configuration. |
| V-07 | High | Mass assignment risk in account profile update | Semgrep flagged dynamic SQL update construction in `services/payments-api/app/routes/accounts.py`. | Users may modify fields they should not control, such as role or sensitive account attributes. | Use an allow-list of editable fields and reject unknown or sensitive fields. |
| V-08 | Medium | Containers run without explicit non-root user | Semgrep flagged missing `USER` directives in both API Dockerfiles. | If an attacker compromises the app, they may gain root privileges inside the container. | Add a non-root user in each Dockerfile and run the application as that user. |
| V-09 | Medium | Docker Compose services lack `no-new-privileges` | Semgrep flagged missing `security_opt: no-new-privileges:true` for services. | A compromised process may attempt privilege escalation inside the container. | Add `security_opt: ["no-new-privileges:true"]` where compatible. |
| V-10 | Medium | Writable container root filesystems | Semgrep flagged writable filesystems for Docker Compose services. | Attackers may write tools/payloads inside a compromised container. | Use `read_only: true` where possible and mount only required writable paths. |
| V-11 | Medium | Binding services to all interfaces | Bandit flagged `host="0.0.0.0"` in both Flask apps. | Services may be exposed more broadly than intended if deployed incorrectly. | In production, run behind ALB/API Gateway and restrict network exposure. |
| V-12 | Low | Non-cryptographic random used for OTP | Bandit flagged `random.randint()` for OTP generation. | OTPs may be more predictable than intended. | Use Python `secrets` module for security-sensitive random values. |
| V-13 | Low | Assert statements in tests | Bandit flagged `assert` usage in test files. | Low practical risk because this appears in tests, not production runtime. | Accept as low/noise or use test framework assertions intentionally. |


## 12. Triage Notes

Several scanner findings are duplicates of the same root cause. For example, SQL injection was reported by both Semgrep and Bandit, and Semgrep produced multiple alerts for the same vulnerable query patterns. These were consolidated into a single vulnerability category rather than counted separately.

The most urgent issues are broken JWT validation, SQL injection, hardcoded secrets, weak password hashing, insecure deserialisation, and missing object-level authorisation. These directly affect authentication, sensitive data protection, and financial transaction integrity.

Some findings, such as Docker Compose hardening and binding to `0.0.0.0`, are important but lower priority for immediate application remediation because the current environment is local development. However, they must be addressed before any production-style deployment.

The `assert_used` findings in test files are considered low-risk/noise because they occur in test code rather than production application logic.


## 13. STRIDE Category and Vunerabilities Inventory

| Finding                     | STRIDE category                                |
| --------------------------- | ---------------------------------------------- |
| Broken JWT validation       | Spoofing, Elevation of Privilege               |
| SQL injection               | Tampering, Information Disclosure              |
| Hardcoded secrets           | Spoofing, Elevation of Privilege               |
| MD5 password hashing        | Information Disclosure, Spoofing               |
| Pickle deserialisation      | Tampering, Elevation of Privilege              |
| Flask debug mode            | Information Disclosure, Elevation of Privilege |
| Mass assignment             | Tampering, Elevation of Privilege              |
| Missing container hardening | Elevation of Privilege                         |
| Weak OTP randomness         | Spoofing                                       |


## 14. Key Risks Identified

The highest-risk areas identified:

| Priority | Risk Area | Reason |
|---|---|---|
| 1 | Broken JWT validation | May allow attackers to forge tokens and impersonate users or administrators |
| 2 | SQL injection | May allow attackers to read or manipulate transaction and KYC records |
| 3 | Hardcoded secrets | May expose third-party services or cloud-like credentials to abuse |
| 4 | Weak password hashing | MD5 hashes can be cracked quickly if the database is exposed |
| 5 | Insecure deserialisation | Unsafe `pickle.loads()` usage may lead to code execution |
| 6 | Missing object-level authorisation | Users may access records belonging to other users |
| 7 | Flask debug mode | Debug mode may expose sensitive internal details |
| 8 | Weak runtime/container hardening | Containers lack some defence-in-depth controls |

## 15. Remediation Priority

The remediation phase should begin with vulnerabilities that directly affect identity, data access, and financial integrity.

Recommended remediation order:

1. Fix broken JWT validation.
2. Fix SQL injection in transaction and KYC lookup routes.
3. Remove hardcoded secrets and rotate exposed values.
4. Replace MD5 password hashing with Argon2id or bcrypt.
5. Remove unsafe pickle deserialisation.
6. Enforce object-level authorisation on account, transaction, wallet, and KYC access.
7. Disable Flask debug mode and use environment-based configuration.
8. Improve audit logging for sensitive operations.
9. Harden Dockerfiles and Docker Compose settings.
10. Add scanner checks into CI/CD so these issues cannot silently return.
