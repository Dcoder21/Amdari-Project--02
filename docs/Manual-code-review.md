# Manual Code Review

## 1. Objective

The objective of Day 3 is to manually review the SentinelPay application code, focusing on authentication, authorisation, and money movement paths. The review validates scanner findings from Day 2 and identifies business logic flaws that automated scanners may not reliably detect.

## 2. Review Scope

The manual review covers:

- payments-api authentication and JWT handling
- kyc-api authentication and JWT handling
- account lookup and profile update logic
- transaction search and transaction retrieval
- wallet credit and debit operations
- admin endpoints
- KYC verification and lookup routes

## 3. Review Method

Each sensitive route was reviewed using the following questions:

1. Is the endpoint protected by authentication?
2. Is the JWT properly verified?
3. Does the endpoint check object ownership?
4. Can the user modify fields they should not control?
5. Are database queries parameterised?
6. Are sensitive actions logged?
7. Can the operation be abused through concurrency or replay?
8. Does the error handling leak internal details?

## 4. Files Reviewed

| File | Reason for Review |
|---|---|
| services/payments-api/app/auth.py | Password hashing, JWT issuing, JWT verification, authentication decorator |
| services/payments-api/app/routes/accounts.py | Account lookup, account listing, profile update, object-level authorisation |
| services/payments-api/app/routes/transactions.py | Transaction search and transaction retrieval |
| services/payments-api/app/routes/wallets.py | Wallet credit/debit logic and money movement |
| services/payments-api/app/routes/admin.py | Admin access control and session restore |
| services/kyc-api/app/auth.py | KYC API token validation |
| services/kyc-api/app/routes/verify.py | BVN/NIN lookup, SSRF risk, KYC SQL injection |

## 5. Authentication Review

### Finding A-01: Weak Password Hashing

The payments API uses MD5 to hash passwords. MD5 is not suitable for password storage because it is fast and can be cracked quickly if hashes are exposed.

Impact:
An attacker who obtains the database could crack common passwords quickly.

Recommended fix:
Replace MD5 with Argon2id or bcrypt using a unique salt and secure parameters.

### Finding A-02: Broken JWT Validation

Both the payments API and KYC API decode JWTs with signature verification disabled. The code also allows the `none` algorithm. This means an attacker may be able to forge a token and impersonate another user or administrator.

Impact:
Authentication can be bypassed, and role claims such as `admin` can be forged.

Recommended fix:
Reject `alg:none`, enable signature verification, use strong signing keys or RS256, and validate expiry, issuer, audience, and role claims.

### Finding A-03: Missing JWT Expiry and Claim Validation

Issued tokens do not appear to include expiry, issuer, or audience claims.

Impact:
Tokens may remain valid indefinitely and cannot be strongly scoped to the intended service.

Recommended fix:
Add `exp`, `iat`, `iss`, and `aud` claims and validate them during token decoding.

## 6. Authorisation Review

### Finding AU-01: Missing Object-Level Authorisation on Account Lookup

The account lookup route fetches account details by account ID but does not verify that the account belongs to the authenticated user.

Impact:
An authenticated user may access another user’s account by guessing or enumerating account IDs.

Recommended fix:
Modify the query to include both `id` and `user_id`, or perform an explicit ownership check before returning the account.

Example safe logic:

`WHERE id = %s AND user_id = %s`

### Finding AU-02: Admin Role Trusts Unverified JWT Claim

The admin route checks whether `request.current_user_role` equals `admin`. However, the role value comes from the JWT, and JWT verification is broken.

Impact:
A forged token with `role=admin` could access admin-only functions.

Recommended fix:
Fix JWT verification and consider checking admin status against the database instead of trusting only the token claim.

### Finding AU-03: Mass Assignment in Profile Update

The profile update route builds an update statement from all fields submitted by the user. This may allow users to modify sensitive fields such as `user_id`, `status`, or `balance`.

Impact:
A user may change account ownership, account status, or financial data.

Recommended fix:
Use an allow-list of editable fields and reject any unexpected or sensitive fields.

## 7. Money Movement Review

### Finding M-01: Wallet Debit/Credit Missing Ownership Check

The wallet debit and credit routes operate on `account_id`, but the code does not clearly verify that the authenticated user owns the target account.

Impact:
An authenticated user may attempt to debit or credit accounts they do not own.

Recommended fix:
Before performing wallet operations, verify that the target account belongs to `request.current_user_id`, unless the caller has a legitimate privileged service role.

### Finding M-02: Wallet Debit Race Condition

The debit operation reads the current balance, checks whether funds are sufficient, computes the new balance in application memory, and then writes the new balance back. There is no row-level lock or atomic database update.

Impact:
Two concurrent debit requests may both pass the balance check using the same original balance, causing incorrect balances or double-spend behaviour.

Recommended fix:
Use a database transaction with row-level locking, such as `SELECT ... FOR UPDATE`, or perform an atomic conditional update.

### Finding M-03: Missing Idempotency Protection

Wallet operations do not appear to enforce idempotency keys.

Impact:
A repeated request may create duplicate wallet movements or duplicate transaction records.

Recommended fix:
Require idempotency keys for money movement operations and store processed keys to prevent duplicate execution.

### Finding M-04: Missing Structured Audit Logging

Sensitive money movement operations do not produce structured audit logs showing actor, account, amount, timestamp, source IP, request ID, and result.

Impact:
Fraud investigation and incident response would be weak because the system lacks reliable evidence of who performed each financial operation.

Recommended fix:
Add structured audit logs for wallet debit, credit, failed attempts, account access, and admin operations.

## 8. Scanner Finding Validation

| Scanner Finding | Manual Review Result | Status |
|---|---|---|
| Broken JWT validation | Confirmed in both payments-api and kyc-api auth helpers. Signature verification is disabled and `alg:none` is allowed. | Confirmed |
| MD5 password hashing | Confirmed in payments-api authentication helper. | Confirmed |
| SQL injection | Confirmed in transaction search and KYC lookup routes where user input is interpolated into SQL strings. | Confirmed |
| Hardcoded secrets | Confirmed by Gitleaks in legacy deployment script. | Confirmed |
| Insecure deserialisation | Confirmed in admin session restore endpoint using `pickle.loads()`. | Confirmed |
| Flask debug mode | Confirmed in both API main files using `debug=True`. | Confirmed |
| Mass assignment | Confirmed in account profile update logic using arbitrary request body fields. | Confirmed |
| Missing container hardening | Confirmed in Dockerfile/Docker Compose scan output. | Confirmed |

## 9. Logic Flaws Identified During Manual Review

| ID | Logic Flaw | Why Scanner May Miss It | Risk |
|---|---|---|---|
| L-01 | Missing ownership checks on account and wallet routes | Requires understanding user/account relationships | Users may access or manipulate other users’ accounts |
| L-02 | Admin access depends on unverified JWT role claim | Requires tracing auth flow into admin route | Normal users may self-promote to admin |
| L-03 | Wallet debit is not atomic | Requires understanding concurrent request behaviour | Double-spend or incorrect balance updates |
| L-04 | No idempotency control for money movement | Requires business logic understanding | Duplicate debits/credits may be processed |
| L-05 | Missing audit logs for sensitive actions | Requires operational/security context | Weak fraud investigation and compliance evidence |

## 10. Day 3 Outcome

Day 3 manual code review confirmed the highest-risk scanner findings and identified additional business logic weaknesses that automated tools may not reliably detect.

The most critical confirmed issues are broken JWT validation, missing object-level authorisation, SQL injection, unsafe admin session deserialisation, weak password hashing, wallet race conditions, and missing audit logging.

The next phase should begin remediation, starting with authentication and authorisation issues before moving to SQL injection, money movement safety, password hashing, deserialisation, and audit logging.