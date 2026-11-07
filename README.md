# SentinelPay — Pan-African Payments Platform

> ⚠️ **This is a deliberately vulnerable training codebase. Do not deploy to a real environment.**
>
> This repository ships with documented security vulnerabilities for the VaultBridge SentinelPay Capstone Engagement. Every flaw exists on purpose. Your job is to find them, fix them, and prove your fixes work — across the application, the cloud deployment you will build, and the CI/CD pipeline you will design.

---

## What is SentinelPay?

SentinelPay Technologies Ltd. is a fictional Nigerian-founded fintech operating a pan-African payments platform. The company processes card and bank-transfer payments for ~1,400 merchants across Nigeria, Ghana, Kenya, and Rwanda. After two years of fast feature delivery and zero dedicated security investment, an external researcher disclosed an IDOR vulnerability in production. The internal review that followed surfaced the rest of this repository.

You are the security engineering team SentinelPay just hired.

## What you're inheriting

```
sentinelpay/
├── services/
│   ├── payments-api/        # Flask service: accounts, wallets, transactions, webhooks
│   └── kyc-api/             # Flask service: identity verification, document upload
├── seed/                    # SQL fixtures for local development
├── scripts/                 # Developer convenience scripts
├── docs/                    # Architectural notes left by the previous team
├── docker-compose.yml       # Local development orchestration
├── .github/workflows/       # The current (inadequate) CI pipeline
└── README.md
```

There are **two services**, sharing **one PostgreSQL database** and **one Redis cache**:

| Service        | Stack             | Port  | Responsibility                                            |
| -------------- | ----------------- | ----- | --------------------------------------------------------- |
| `payments-api` | Python 3.11 + Flask | 8001  | Authentication, accounts, wallets, transactions, webhooks |
| `kyc-api`      | Python 3.11 + Flask | 8002  | Identity verification, document upload, BVN/NIN lookup    |

## Local development

You only need Docker and Docker Compose.

```bash
# Bring up the full stack
docker compose up --build

# Seed the database with realistic fixtures
docker compose exec payments-api python -m app.seed

# The services are now available at:
#   payments-api: http://localhost:8001
#   kyc-api:      http://localhost:8002
#   postgres:     localhost:5432  (user: sentinel, pass: see your .env's POSTGRES_PASSWORD)
#   redis:        localhost:6379
```

A Postman collection lives in `docs/SentinelPay.postman_collection.json` with example requests against every endpoint.

## Your engagement scope

You have 21 days. The full engagement brief is in the capstone case study document you received with this repository. Briefly:

- **Week 1 — AppSec.** Threat-model the application, find every vulnerability (there are 11 in the app code, 4 more in the build and pipeline configuration), remediate them, and produce a remediation report.
- **Week 2 — CloudSec.** **Design and build the entire AWS deployment yourselves, in Terraform.** No infrastructure code is shipped in this repo. You decide the architecture; the case study tells you the principles it must satisfy.
- **Week 3 — DevSecOps + Purple Team.** Replace the existing CI workflow with a multi-stage security pipeline, then run the documented attack simulation against your deployment.

## What is NOT in this repository

The following are **deliberately absent**. You will build them yourselves:

- ❌ Terraform code for any AWS infrastructure
- ❌ A working CI/CD security pipeline (the existing one is intentionally inadequate — see `.github/workflows/ci.yml`)
- ❌ Container image signing or SBOM generation
- ❌ OPA policies
- ❌ Detection or response runbooks
- ❌ A threat model

Producing each of these is part of your graded deliverable set (D-01 through D-10).

## What IS in this repository (and is broken)

A working application. It runs. It accepts requests. It moves money between wallet balances. It just does all of that very, very insecurely.

Your first commit should not be a fix. Your first commit should be the threat model and the vulnerability inventory.

## Rules of engagement

1. **Do not delete the vulnerabilities silently.** Every fix must be a discrete commit referencing the V-APP / V-CLD / V-PIP identifier from the vulnerability index in the case study.
2. **Do not rewrite the application from scratch.** The point is to triage, prioritise, and patch a real-world inherited codebase, not to greenfield.
3. **Do not push to `main` directly.** Open a pull request for everything. Peer review is graded.
4. **Document every assumption.** If the inherited code does something ambiguous, write down what you decided and why before you change it.
5. **Use the issue tracker.** One issue per finding. Link the fix PR to the issue. This is what your remediation report will be built from.

## Getting unstuck

- Programme Lead: Nuel Ojeabulu
- Standups: 09:30 WAT daily
- Pod reviews: end of Day 7, Day 14, Day 21
- Slack: `#sentinelpay-capstone`

Good luck. Make it boring to attack.
