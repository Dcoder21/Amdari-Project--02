# Repo Discovery

## Onboarding and Discovery

### Objective

The objective of Day 1 was to review the SentinelPay repository, understand the main application components, confirm the local development environment, and make sure the application services were running successfully before moving into threat modelling and vulnerability assessment.

### Repository Overview

The SentinelPay project is a deliberately vulnerable fintech API system. It contains two main Flask-based backend API services supported by PostgreSQL and Redis.

| Component | Port | Purpose |
|---|---:|---|
| payments-api | 8001 | Handles authentication, accounts, wallets, transactions, webhooks, and admin-related functions |
| kyc-api | 8002 | Handles KYC-related functions such as BVN/NIN verification and document handling |
| PostgreSQL | 5432 | Stores users, accounts, transactions, wallet, and KYC-related data |
| Redis | 6379 | Supports caching, session, and idempotency-related functionality |

The system is API-based rather than a browser-based frontend application. The two main application-facing services are `payments-api` and `kyc-api`. PostgreSQL and Redis are backend dependencies and should not be treated as public-facing application services in a production environment.

### Local Environment Setup

The local environment was started using Docker Compose.

```bash
docker compose up -d --build
```

The expected running containers were:

```text
sentinelpay-postgres
sentinelpay-redis
sentinelpay-payments
sentinelpay-kyc
```

After setup and troubleshooting, all four containers were confirmed to be running successfully.

### Health Check Validation

The health endpoints for both API services were tested successfully through the browser and terminal using `curl`.

```bash
curl http://localhost:8001/health
curl http://localhost:8002/health
```

Successful access to these endpoints confirmed that both backend API services were reachable locally.

### Setup Issues Encountered

During setup, the API containers initially failed to start even though PostgreSQL and Redis were running correctly. The issue was traced through Docker logs.

#### Issue 1: Flask and Werkzeug Compatibility

The `payments-api` and `kyc-api` containers initially failed with an import error related to `url_quote` from Werkzeug.

```text
ImportError: cannot import name 'url_quote' from 'werkzeug.urls'
```

The root cause was that the project used an older Flask version, but Werkzeug was not pinned in the requirements files. Docker installed a newer Werkzeug version that was incompatible with the Flask version used by the application.

Resolution:

- Added `Werkzeug==2.0.3` to `services/payments-api/requirements.txt`
- Added `Werkzeug==2.0.3` to `services/kyc-api/requirements.txt`

#### Issue 2: psycopg2 Compatibility

After resolving the Werkzeug issue, both API services failed at the PostgreSQL driver import stage.

```text
SystemError: initialization of _psycopg raised unreported exception
```

The root cause was an incompatible `psycopg2-binary` version for the Python runtime used inside the containers.

Resolution:

- Updated `psycopg2-binary` in both API requirements files to a compatible version.
- Rebuilt the containers after updating the dependency files.

### Basic Architecture Understanding

At a high level, the local architecture is:

```text
Client / API Tester
      |
      v
payments-api :8001
      |
      |---- PostgreSQL
      |---- Redis

Client / API Tester
      |
      v
kyc-api :8002
      |
      |---- PostgreSQL
      |---- Redis
```

The payments API handles core financial and account-related operations, while the KYC API handles identity verification and document-related operations. Both services depend on PostgreSQL and Redis.

In a production-grade deployment, the API services should sit behind a controlled entry point such as an Application Load Balancer or API Gateway with WAF protection. PostgreSQL and Redis should be isolated in private subnets and should not be directly accessible from the internet.

### Initial Observations

- The project is a deliberately vulnerable fintech API system.
- The application is made up of separate payments and KYC API services.
- The system does not include a traditional browser-based frontend.
- The local environment did not run cleanly from a fresh setup without dependency fixes.
- PostgreSQL and Redis are exposed locally for development purposes, but this would not be acceptable in a production architecture.
- Both API services are now running and accessible locally through their health endpoints.
- The environment is ready for Day 2 threat modelling and vulnerability assessment.

### Day 1 Outcome

Day 1 was completed successfully. The repository was reviewed, the main services were identified, the local Docker Compose environment was debugged, dependency issues were resolved, and both API health endpoints were validated.

The project is now ready to move into Day 2, which focuses on threat modelling, trust boundaries, data flows, threat actors, and early vulnerability assessment.
