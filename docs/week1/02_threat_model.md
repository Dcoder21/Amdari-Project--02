# D-01 — SentinelPay STRIDE Threat Model (draft 1)

## 1. System and trust boundaries

```
 [Internet / merchant client]            [Researcher / attacker]
            |  TB1: internet -> edge
            v
   [ALB + WAF]   (planned; local compose has none)
            |  TB2: edge -> app
     +------+--------------+
     v                     v
 [payments-api :8001]  [kyc-api :8002]     <- TB3: service <-> service (no
     |      |               |   |              auth exists today)
     |      +---+   +-------+   |
     |  TB4: app -> data        |  TB5: app -> AWS APIs
     v          v   v          v
 [PostgreSQL] [Redis]       [S3 KYC bucket]  [IMDS/ECS metadata 169.254.x]
     ^
     | TB6: CI/CD -> cloud       TB7: developer -> repo
 [GitHub Actions]               [laptop / git history]
```

Trust boundaries: TB1 internet/edge, TB2 edge/app, TB3 service/service,
TB4 app/data stores, TB5 app/AWS control plane (including metadata service),
TB6 pipeline/cloud, TB7 developer/source.

## 2. Assets

PII (BVN, NIN, KYC documents), account balances and transaction ledger,
credentials (JWT signing secret, DB, AWS), admin capability, audit trail,
availability of payments.

## 3. Adversary profiles

| ID | Adversary | Capability assumed |
|---|---|---|
| A1 | Anonymous internet user | Can reach public endpoints, register freely |
| A2 | Authenticated merchant | Valid token for own account; can enumerate IDs |
| A3 | Malicious merchant | A2 plus willingness to forge tokens, craft payloads, race requests |
| A4 | Compromised insider / maintainer account | Push access to repo; GitHub Actions credentials |
| A5 | Attacker with code execution in a task (post-RCE) | Task role credentials, network position inside VPC |
| A6 | Researcher / opportunist | Public disclosures, scanning, git history |

## 4. Threat register

Links point to inventory numbers (`00_vulnerability_inventory.md`) and
planned mitigation. Status is `open` until a fix commit references it.

| ID | Boundary | STRIDE | Threat | Adv. | Inv # | Sev | Mitigation (planned) | Status |
|---|---|---|---|---|---|---|---|---|
| T-01 | TB1 | S | Forged JWT impersonates any user, incl. admin | A1 | 1 | Crit | Verify signature, RS256, pinned alg, exp/iss/aud, key in Secrets Manager | open |
| T-02 | TB1 | S | Self-registration as admin | A1 | 12 | Crit | Server-side role assignment; ignore client `role` | open |
| T-03 | TB1 | S | Credential stuffing / OTP brute force | A1 | 13, 25 | Med | Rate limit + lockout, `secrets`-based OTP stored hashed with TTL | open |
| T-04 | TB1 | T | SQL injection in transaction search and KYC lookup | A2 | 2, 3 | Crit | Parameterised queries; scope by owner | open |
| T-05 | TB1 | T | Column-name SQL injection and mass assignment in profile update | A2 | 11 | High | Allow-list of mutable fields; fixed SQL | open |
| T-06 | TB1 | T | Double-spend via concurrent debit | A3 | 9 | High | `SELECT ... FOR UPDATE` or atomic conditional UPDATE; idempotency key | open |
| T-07 | TB1 | R | Money movement with no trace of actor | A3 | 16 | Med | Structured audit log with actor, request ID, idempotency key | open |
| T-08 | TB1 | I | Cross-tenant read of accounts, transactions, KYC docs and records | A2 | 4, 6, 21, 23 | Crit | Central ownership helper; per-object checks | open |
| T-09 | TB1 | I | Verbose errors and Werkzeug debugger | A1 | 14, 26 | Med | Generic error handler, `debug=False`, gunicorn | open |
| T-10 | TB1 | I | Email enumeration via register | A1 | 13 | Low | Uniform response | open |
| T-11 | TB1 | D | Unbounded requests, no body-size limit, no rate limits | A1 | 13, 32 | Med | WAF rate rule, Flask `MAX_CONTENT_LENGTH` | open |
| T-12 | TB1 | E | Pickle RCE through admin session restore | A3 | 15 | High | Remove pickle; signed JSON or server-side session | open |
| T-13 | TB1 | E | Any user debits or credits any account | A2 | 19, 20 | Crit | Ownership check on wallets and profile | open |
| T-14 | TB2 | T | Request smuggling and known CVEs in framework layer | A3 | 31 | High | Upgrade gunicorn, Flask, urllib3; SCA gate | open |
| T-15 | TB2 | S | Direct access to compute bypassing WAF | A1 | n/a | High | Tasks in private subnets; ALB only ingress (Week 2) | planned |
| T-16 | TB3 | S | No authentication between services; either could call the other | A5 | n/a | High | Short-lived signed service tokens, separate identities | open |
| T-17 | TB3 | I | One shared DB credential; kyc-api compromise reads ledger | A5 | 29 | High | Per-service DB roles with least privilege | open |
| T-18 | TB4 | I | Postgres and Redis reachable with default or no auth | A5 | 29 | High | Private only, SG-by-reference, Redis AUTH + TLS | open |
| T-19 | TB4 | T | Redis (sessions/idempotency) tampering | A5 | n/a | Med | AUTH token, TLS, key namespace | planned |
| T-20 | TB5 | E | SSRF to metadata endpoints returns task-role credentials | A3 | 7, 8, 24 | High | Scheme/host allow-list, block link-local/private ranges, IMDSv2 / disable redirects | open |
| T-21 | TB5 | I | KYC objects public-read, key traversal, no ownership | A1,A2 | 22 | Crit | Private bucket, server-generated keys under user prefix, SSE-KMS | open |
| T-22 | TB5 | E | Over-broad task role after RCE or SSRF | A5 | n/a | High | Per-service scoped roles (V-CLD-05) | planned |
| T-23 | TB5 | R | CloudTrail tampering by admins | A5 | n/a | High | Object Lock, log validation (V-CLD-06) | planned |
| T-24 | TB6 | E | Pipeline principal has AdministratorAccess | A4 | n/a | Crit | OIDC with scoped role (V-PIP-03) | planned |
| T-25 | TB6 | T | Unsigned/unscanned images deployed | A4 | n/a | High | Cosign keyless, SBOM, admission verify (V-PIP-01/02) | planned |
| T-26 | TB6 | T | Direct push to main, no review | A4 | n/a | High | Branch protection (V-PIP-04) | planned |
| T-27 | TB7 | I | Secrets in source and git history | A6 | 17 | Crit | Remove, rotate, Secrets Manager, Gitleaks gate with custom rules | open |
| T-28 | TB7 | T | Malicious or vulnerable dependency | A4,A6 | 31 | High | Pinned + hashed requirements, SCA, SBOM | open |
| T-29 | all | D | No detection or alerting; attack unnoticed | A1-A5 | n/a | High | GuardDuty, Security Hub, alarms (Week 2) | planned |

Every STRIDE category appears at TB1; TB2 to TB7 each carry at least one
threat, but not yet one per STRIDE category per boundary as the D-01
distinction bar requires. Gaps to fill in draft 2: TB2 (R, D), TB3 (T, R, D),
TB4 (R, D), TB5 (S, T, D), TB6 (S, R, I, D), TB7 (S, R, D, E).

## 5. Assumptions and residual risk

- Local compose has no TLS; production assumes TLS terminated at ALB. In-VPC
  traffic to tasks is plain HTTP unless we add mTLS (residual risk to record
  as an ADR).
- Redis role is unclear: no code uses it yet. Treated as a future sessions
  and idempotency store.
- `ci.yml` not available; pipeline threats are based on the brief only.

## 6. Next

Draft 2: complete the STRIDE-per-boundary matrix, add a per-endpoint table
(all 17 routes), render the diagram graphically, and link each threat to a
fix commit once remediation begins.
