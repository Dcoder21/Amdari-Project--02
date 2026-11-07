# Week 1 — Environment Setup Log

## Docker registry workaround

Docker Desktop's VM context (`desktop-linux`) could not resolve its own proxy
(`http.docker.internal:3128`), so every pull through it failed. The native
`default` context (unix socket, no VM/proxy hop) pulls normally. All compose
and build commands in this engagement are run with:

```bash
export DOCKER_CONTEXT=default
```

## Local port conflicts

This machine already runs Postgres (5432) and Redis (6379) natively.
`docker-compose.override.yml` (git-ignored, machine-local) stops the
`postgres` and `redis` services from publishing to the host at all — the
app containers still reach them over the compose network by service name,
so nothing about the application changes. Fixing the fact that production
Terraform must never publish these is tracked under V-CLD-01 (Week 2); the
override here is a local dev-only workaround, not a fix.

## Reproducibility fixes (not security fixes)

The inherited codebase would not run end-to-end as committed. Three
pins/compat shims were required before any vulnerability could even be
exercised; none of them touch authentication, authorisation or SQL logic:

| Fix | File | Why |
|---|---|---|
| Pin `werkzeug==2.0.3` | both `requirements.txt` | `flask==2.0.1` is pinned but `werkzeug` isn't; an unpinned install resolves a modern `werkzeug` that removed `url_quote`, which `flask.cli` imports at startup. Both services crashed on boot. |
| Bump `psycopg2-binary` to `2.9.9` | both `requirements.txt` | `2.9.1`'s compiled wheel has a known ABI bug against Python 3.11 (`SystemError: initialization of _psycopg raised unreported exception`). |
| Decode `jwt.encode()`'s return value to `str` in `issue_token` | `payments-api/app/auth.py` | PyJWT 1.7.1's `encode()` returns `bytes`; Flask's `jsonify` can't serialise `bytes`, so every login 500'd. `decode_token`'s broken signature verification (V-APP-02) is untouched. |
| Register a `Decimal`-aware JSON encoder | `payments-api/app/main.py` | `NUMERIC` columns come back from psycopg2 as `Decimal`; Flask 2.0's default encoder can't serialise it, so every route returning a balance 500'd regardless of IDOR. Encoder only changes serialisation, not any route's authorisation logic. |

Each is commented in place with "Environment-compatibility note (not a
security fix)" so it isn't mistaken for a V-APP fix in the diff history.

## Exploit evidence (Week 1, Day 1)

Having gotten the stack running, each V-APP finding (and variants in
`kyc-api`) was proven live, first by hand with `curl`, then encoded as a
pytest exploit test that passes against the current, unpatched code:

- `services/payments-api/tests/test_vulnerabilities.py` — 12 tests, 1
  documented skip (V-APP-11; no audit logger exists yet to assert against).
- `services/kyc-api/tests/test_vulnerabilities.py` — 6 tests, using
  `moto`'s mocked S3 in place of a real bucket (no AWS account exists for
  this engagement yet).

Both suites were run three times each against a freshly reset DB
(`docker compose down -v && up -d --build`) to confirm they're idempotent
and not dependent on run order or leftover state from a previous pass.

Run them with:

```bash
export DOCKER_CONTEXT=default
docker compose exec payments-api pip install -r requirements-dev.txt
docker compose exec kyc-api pip install -r requirements-dev.txt
docker compose exec payments-api pytest tests/ -v
docker compose exec kyc-api pytest tests/ -v
```

One correction made during this pass: the inventory's original claim that
the KYC upload filename allows `../` traversal across S3 **keys** was wrong
— S3 keys are flat strings, not filesystem paths, so a `../` does not escape
the `users/<id>/` prefix the way it would on a real filesystem. The test and
`00_vulnerability_inventory.md` were corrected; the real, demonstrated
impact is unsanitised, unbounded nested keys and silent same-key overwrite
with no collision check.

## Still outstanding

- `.github/workflows/ci.yml` does not exist in the fork (confirmed absent
  upstream too). V-PIP-01–03 branches exist but can't be evidenced
  before/after until this is obtained or reconstructed.
- V-APP-11 (audit logging) has no automated exploit test — see the skip
  reason in `payments-api/tests/test_vulnerabilities.py`.
