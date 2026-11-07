# Week 1 — Scanner Reconciliation and Index Cross-check

Raw reports (kept local, git-ignored because they embed the secret strings):
`evidence/week1/scans/`. Tools: Semgrep 1.184.0 (p/python, p/flask, p/secrets,
p/dockerfile), Bandit 1.9.4, Gitleaks 8.30.1, pip-audit 2.10.1, Trivy 0.76.2.
Scans were run against a clean copy of tracked files so that reports were not
scanning themselves.

## 1. Coverage by finding (inventory numbers from `00_vulnerability_inventory.md`)

| Inventory # | Finding | Semgrep | Bandit | Gitleaks | Trivy / pip-audit | Manual only? |
|---|---|---|---|---|---|---|
| 1 | JWT signature not verified / `none` | yes (both services) | no | no | no | |
| 2 | SQLi transactions search | no | yes (B608) | no | no | |
| 3 | SQLi kyc lookup | yes (x4) | yes (B608 x2) | no | no | |
| 4, 5, 6 | IDOR / BOLA | no | no | no | no | **yes** |
| 7, 8 | SSRF | no | no | no | no | **yes** |
| 9 | Debit race | no | no | no | no | **yes** |
| 10 | MD5 passwords | yes | yes (B324) | no | no | |
| 11 | Mass assignment + column-name SQLi | no | line flagged as B608, mass assignment not named | no | no | partly |
| 12 | Self-assigned role | no | no | no | no | **yes** |
| 13 | No rate limiting | no | no | no | no | **yes** |
| 14 | Verbose errors | debug flag only | debug flag only | no | no | partly |
| 15 | Pickle RCE | no | yes (B301) | no | no | |
| 16 | No audit log | no | no | no | no | **yes** |
| 17 | Hardcoded secrets | Stripe only | no | Slack + Stripe only | Slack + Stripe only | AWS keys, DB passwords, JWT secret missed |
| 19-24 | Wallet BOLA, KYC ACL/traversal, stored SSRF | no | no | no | no | **yes** |
| 25 | OTP weakness | no | `random` only (B311) | no | no | partly |
| 26 | `debug=True`, 0.0.0.0 | yes | yes | no | no | |
| 30 | Container runs as root, no healthcheck | yes (missing-user) | no | no | yes (DS-0002, DS-0026) | |
| 31 | Vulnerable dependencies | no | no | no | **yes** | |

Scanner-detectable: roughly 10 of 34 inventory items. Business-logic and
authorisation flaws, which are the ones that caused the incident, are
invisible to all five tools.

## 2. Secret scanner gap

Gitleaks and Trivy flagged only the Slack webhook and Stripe-style key.
They did **not** flag:
- `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/...` (AWS documentation example
  pair; Gitleaks allowlists it by design)
- `sentinel123`, `Sent!nelPr0d_2024_Master` (DB passwords, no recognisable
  prefix)
- `JWT_SECRET` (low-entropy string)

Pipeline implication (Week 3): ship a custom `.gitleaks.toml` with rules for
`PROD_DB_PASSWORD=`, `JWT_SECRET=`, `*_PASSWORD:` and non-allowlisted AWS
keys, and treat the example AWS pair as a finding in this repo.

## 3. Dependency findings (pip-audit; same set in both services)

51 vulnerabilities across 7 packages: pyjwt 1.7.1 (15), urllib3 1.26.20 (12),
requests 2.25.1 (8), flask 2.0.1, redis 4.3.4, gunicorn 20.1.0, idna 2.10
(4 each). Trivy reports 2 critical and 18 high. Fix versions are in the
pip-audit JSON. Upgrading PyJWT to 2.x is a breaking change for `jwt.decode`
and ties into the V-APP-02 fix.

## 4. Cross-check against `docs/VULN_INDEX.md`

Read after the inventory was written. Index entries I had already found: all
of V-APP-01 to 11 and the kyc-api variants listed there.

Findings in my inventory that the index does not list:
- wallet credit/debit have no ownership check (#19)
- `update_profile` writes to any account (#20)
- `get_transaction` has no ownership check (#21)
- `public-read` ACL and filename traversal on upload (#22)
- `lookup_kyc` has no authorisation (#23)
- stored SSRF via webhook registration (#24)
- OTP logged and never verified (#25)
- shared DB credential across services (#29)
- vulnerable dependencies (#31)

Index items I under-rated or misplaced: none found. The index points to
`register`'s `role` under V-APP-07 only implicitly via a code comment.

Not verifiable yet: V-PIP-01 to 04 (no `ci.yml` in the repo).
