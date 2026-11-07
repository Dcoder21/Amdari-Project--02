"""Exploit tests — one per V-APP finding in payments-api.

These are written against the INHERITED, unpatched code and are expected to
PASS right now (because the exploit succeeds). Each will be inverted (or
replaced by a regression test proving the exploit now fails) in the commit
that closes the corresponding GitHub issue.

Run inside the payments-api container, where DATABASE_URL resolves the
`postgres` service by name:

    docker compose exec payments-api pytest tests/test_vulnerabilities.py -v

Requires requirements-dev.txt (pytest) installed in the image/container.
"""
import base64
import os
import pickle
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from app.main import create_app
from app.auth import hash_password, verify_password, needs_rehash
from app.db import get_connection as get_db_connection
from tests.conftest import get_test_private_key_pem


def _generate_attacker_rsa_key() -> bytes:
    """A key the attacker generated themselves — structurally valid RS256,
    just not the one payments-api actually trusts."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

SEEDED_ACCOUNT_ID = 3          # merchant1@example.com — read/debit/credit tests
OWNERSHIP_TRANSFER_TARGET_ID = 4  # merchant2@example.com — kept separate so the
                                  # mass-assignment test's permanent ownership
                                  # change doesn't break other tests' assumptions


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def register_and_login(client, role=None):
    """Register a fresh user and return (user_id, token)."""
    email = f"{uuid.uuid4().hex}@example.com"
    password = "Test#Pass123"
    payload = {"email": email, "password": password, "full_name": "Test User"}
    if role is not None:
        payload["role"] = role
    reg = client.post("/v1/auth/register", json=payload)
    assert reg.status_code == 201, reg.get_json()
    user_id = reg.get_json()["id"]

    login = client.post("/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.get_json()
    return user_id, login.get_json()["token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def login_seeded_owner(client):
    """Return a token that can act on SEEDED_ACCOUNT_ID as if it were the
    real owner (merchant1@example.com). The seeded merchant users' plaintext
    passwords aren't known, so this logs in as the seeded admin account
    (admin@sentinelpay.io / password123, see seed/init.sql) instead — admin
    bypasses the ownership check by design (see app/routes/accounts.py).
    Now that V-APP-07 is fixed, self-assigned role='admin' at registration
    no longer works, so this is a real admin login, not a workaround."""
    login = client.post(
        "/v1/auth/login",
        json={"email": "admin@sentinelpay.io", "password": "password123"},
    )
    assert login.status_code == 200, login.get_json()
    return login.get_json()["token"]


# --------------------------------------------------------------------------
# V-APP-01 — FIXED: transaction search now binds q/account_id as query
# parameters instead of interpolating them into the SQL string. See
# services/payments-api/app/routes/transactions.py.
# --------------------------------------------------------------------------
def test_v_app_01_fix_injection_payload_no_longer_leaks_rows(client):
    """The same payload that used to leak every row via an always-true OR
    clause must now be treated as a literal (non-matching) search string."""
    _, token = register_and_login(client)

    baseline = client.get(
        "/v1/transactions/search",
        query_string={"q": "definitely-not-a-real-reference-xyz"},
        headers=auth_header(token),
    )
    assert baseline.status_code == 200
    assert baseline.get_json() == []

    injected = client.get(
        "/v1/transactions/search",
        query_string={"q": "x' OR '1'='1') --"},
        headers=auth_header(token),
    )
    assert injected.status_code == 200
    assert injected.get_json() == [], (
        "expected the injection payload to be treated as a literal string "
        "with no matching rows, not as SQL"
    )


def test_v_app_01_fix_account_id_rejects_non_integer_injection(client):
    """account_id used to be concatenated too; a non-integer payload must now
    be rejected outright instead of reaching the query."""
    _, token = register_and_login(client)

    resp = client.get(
        "/v1/transactions/search",
        query_string={"q": "", "account_id": "1 OR 1=1"},
        headers=auth_header(token),
    )
    assert resp.status_code == 400


def test_v_app_01_fix_legitimate_search_still_works(client):
    """Confirms the fix didn't just break search: a substring that genuinely
    matches a seeded transaction's reference/counterparty/description still
    comes back."""
    _, token = register_and_login(client)

    resp = client.get(
        "/v1/transactions/search",
        query_string={"q": "a"},
        headers=auth_header(token),
    )
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


# --------------------------------------------------------------------------
# V-APP-02 — FIXED: RS256, signature always verified, algorithm pinned.
# These are now regression tests: each exploit that used to pass must now
# be rejected with 401. See services/payments-api/app/auth.py.
# --------------------------------------------------------------------------
def test_v_app_02_fix_forged_hs256_token_is_rejected(client):
    """A token signed with an attacker-chosen HS256 secret — the original
    exploit — must now be rejected, since decode_token only accepts RS256."""
    forged = jwt.encode(
        {"user_id": 1, "role": "admin"},
        "attacker-does-not-know-anything-useful",
        algorithm="HS256",
    )
    resp = client.get("/v1/admin/users", headers=auth_header(forged))
    assert resp.status_code == 401


def test_v_app_02_fix_none_algorithm_token_is_rejected(client):
    """alg:none tokens must now be rejected."""
    unsigned = jwt.encode({"user_id": 1, "role": "admin"}, key=None, algorithm="none")
    resp = client.get("/v1/admin/users", headers=auth_header(unsigned))
    assert resp.status_code == 401


def test_v_app_02_fix_token_signed_with_wrong_rsa_key_is_rejected(client):
    """Even a well-formed RS256 token, correctly structured, fails if it
    wasn't signed with the real private key."""
    attacker_private_key = _generate_attacker_rsa_key()
    forged = jwt.encode(
        {
            "user_id": 1,
            "role": "admin",
            "iss": "sentinelpay-payments-api",
            "aud": "sentinelpay-services",
            "iat": datetime.now(tz=timezone.utc),
            "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=15),
        },
        attacker_private_key,
        algorithm="RS256",
    )
    resp = client.get("/v1/admin/users", headers=auth_header(forged))
    assert resp.status_code == 401


def test_v_app_02_fix_expired_token_is_rejected(client):
    from app.auth import ISSUER, AUDIENCE

    expired = jwt.encode(
        {
            "user_id": 1,
            "role": "admin",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": datetime.now(tz=timezone.utc) - timedelta(minutes=30),
            "exp": datetime.now(tz=timezone.utc) - timedelta(minutes=15),
        },
        get_test_private_key_pem(),
        algorithm="RS256",
    )
    resp = client.get("/v1/admin/users", headers=auth_header(expired))
    assert resp.status_code == 401


def test_v_app_02_fix_wrong_audience_is_rejected(client):
    from app.auth import ISSUER

    wrong_audience = jwt.encode(
        {
            "user_id": 1,
            "role": "admin",
            "iss": ISSUER,
            "aud": "some-other-service",
            "iat": datetime.now(tz=timezone.utc),
            "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=15),
        },
        get_test_private_key_pem(),
        algorithm="RS256",
    )
    resp = client.get("/v1/admin/users", headers=auth_header(wrong_audience))
    assert resp.status_code == 401


def test_v_app_02_fix_legitimate_login_flow_still_works(client):
    """The fix doesn't just reject forgeries — real users can still log in
    and use their token end-to-end."""
    _, token = register_and_login(client)
    resp = client.get("/v1/accounts/", headers=auth_header(token))
    assert resp.status_code == 200


# --------------------------------------------------------------------------
# V-APP-03 — FIXED: ownership (or admin role) is now enforced on accounts,
# wallets and transactions. See app/routes/{accounts,wallets,transactions}.py.
# --------------------------------------------------------------------------
def test_v_app_03_fix_unrelated_user_cannot_read_account(client):
    """An authenticated user with no relationship to account 3 must now be
    rejected with 403, not handed its balance and account number."""
    attacker_id, attacker_token = register_and_login(client)

    resp = client.get(f"/v1/accounts/{SEEDED_ACCOUNT_ID}", headers=auth_header(attacker_token))
    assert resp.status_code == 403


def test_v_app_03_fix_owner_can_still_read_own_account(client):
    """Confirms the fix didn't just lock everyone out: the real owner can
    still read their own account."""
    owner_token = login_seeded_owner(client)

    resp = client.get(f"/v1/accounts/{SEEDED_ACCOUNT_ID}", headers=auth_header(owner_token))
    assert resp.status_code == 200
    assert resp.get_json()["id"] == SEEDED_ACCOUNT_ID


def test_v_app_03_fix_unrelated_user_cannot_debit_account(client):
    """An unrelated user must no longer be able to DEBIT money from an
    account they do not own."""
    _, attacker_token = register_and_login(client)

    debit = client.post(
        f"/v1/wallets/{SEEDED_ACCOUNT_ID}/debit",
        json={"amount": "1.00", "counterparty": "attacker-controlled", "description": "unauthorised debit"},
        headers=auth_header(attacker_token),
    )
    assert debit.status_code == 403


def test_v_app_03_fix_unrelated_user_cannot_credit_account(client):
    """An unrelated user must no longer be able to CREDIT an account they
    do not own either — credit had the identical missing-ownership bug."""
    _, attacker_token = register_and_login(client)

    credit = client.post(
        f"/v1/wallets/{SEEDED_ACCOUNT_ID}/credit",
        json={"amount": "1.00"},
        headers=auth_header(attacker_token),
    )
    assert credit.status_code == 403


def test_v_app_03_fix_owner_can_still_debit_and_credit_own_account(client):
    """Confirms the fix didn't break legitimate wallet operations for the
    real owner."""
    owner_token = login_seeded_owner(client)

    credit = client.post(
        f"/v1/wallets/{SEEDED_ACCOUNT_ID}/credit",
        json={"amount": "100.00"},
        headers=auth_header(owner_token),
    )
    assert credit.status_code == 200, credit.get_json()

    debit = client.post(
        f"/v1/wallets/{SEEDED_ACCOUNT_ID}/debit",
        json={"amount": "1.00", "counterparty": "test", "description": "owner debit"},
        headers=auth_header(owner_token),
    )
    assert debit.status_code == 200, debit.get_json()


def test_v_app_03_fix_unrelated_user_cannot_read_transaction_by_reference(client):
    """A transaction reference belonging to an account the caller doesn't
    own must now be rejected with 403, not handed the full transaction."""
    _, attacker_token = register_and_login(client)

    resp = client.get("/v1/transactions/TXN-2026-001", headers=auth_header(attacker_token))
    assert resp.status_code == 403


def test_v_app_03_fix_owner_can_still_read_own_transaction(client):
    owner_token = login_seeded_owner(client)

    resp = client.get("/v1/transactions/TXN-2026-001", headers=auth_header(owner_token))
    assert resp.status_code == 200
    assert resp.get_json()["reference"] == "TXN-2026-001"


# --------------------------------------------------------------------------
# V-APP-05 — FIXED: debit/credit now take a row lock (SELECT ... FOR UPDATE)
# so concurrent operations against the same account serialise instead of
# racing. See app/routes/wallets.py.
# --------------------------------------------------------------------------
def test_v_app_05_fix_concurrent_debits_no_longer_overdraw_the_account(client):
    """Fire N concurrent debits, each individually affordable only once. The
    row lock must now serialise them: at most 2 can succeed against a
    balance that only covers 2, and the account must never go negative."""
    app = create_app()
    app.config["TESTING"] = True

    seed_client = app.test_client()
    actor_token = login_seeded_owner(seed_client)
    topped_up = Decimal("1000.00")
    seed_client.post(
        f"/v1/wallets/{SEEDED_ACCOUNT_ID}/credit",
        json={"amount": str(topped_up)},
        headers=auth_header(actor_token),
    )
    balance_before = Decimal(
        seed_client.get(f"/v1/accounts/{SEEDED_ACCOUNT_ID}", headers=auth_header(actor_token)).get_json()["balance"]
    )

    concurrency = 8
    debit_amount = (balance_before / 2).quantize(Decimal("0.01"))  # only 2 can be legitimately afforded

    def fire_debit(_):
        c = app.test_client()
        resp = c.post(
            f"/v1/wallets/{SEEDED_ACCOUNT_ID}/debit",
            json={"amount": str(debit_amount), "counterparty": "race-test"},
            headers=auth_header(actor_token),
        )
        return resp.status_code

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(fire_debit, range(concurrency)))

    successes = sum(1 for s in results if s == 200)
    insufficient_funds = sum(1 for s in results if s == 400)
    balance_after = Decimal(
        seed_client.get(f"/v1/accounts/{SEEDED_ACCOUNT_ID}", headers=auth_header(actor_token)).get_json()["balance"]
    )

    assert successes == 2, f"expected exactly 2 of {concurrency} debits to succeed, got {successes}"
    assert insufficient_funds == concurrency - 2
    assert balance_after >= 0
    assert balance_after == balance_before - (2 * debit_amount)


# --------------------------------------------------------------------------
# V-APP-04 — FIXED: webhook registration and test-fire now validate the
# target URL against private/loopback/link-local/reserved destinations
# before storing or fetching it. See app/routes/webhooks.py and
# app/ssrf_guard.py. No pre-existing exploit test existed for this service
# (only kyc-api's BVN-provider variant was covered in Week 1), so this is
# new regression-only coverage added alongside the fix.
# --------------------------------------------------------------------------
def test_v_app_04_fix_webhook_test_blocks_cloud_metadata_address(client):
    _, token = register_and_login(client)
    resp = client.post(
        "/v1/webhooks/test",
        json={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        headers=auth_header(token),
    )
    assert resp.status_code == 400


def test_v_app_04_fix_webhook_registration_rejects_internal_callback_url(client):
    _, token = register_and_login(client)
    resp = client.post(
        "/v1/webhooks/",
        json={"callback_url": "http://127.0.0.1:8001/v1/admin/users"},
        headers=auth_header(token),
    )
    assert resp.status_code == 400


def test_v_app_04_fix_webhook_registration_accepts_public_callback_url(client):
    """Confirms the fix didn't just break legitimate webhook registration."""
    _, token = register_and_login(client)
    resp = client.post(
        "/v1/webhooks/",
        json={"callback_url": "https://8.8.8.8/webhooks/incoming"},
        headers=auth_header(token),
    )
    assert resp.status_code == 201, resp.get_json()


# --------------------------------------------------------------------------
# V-APP-06 — FIXED: salted PBKDF2-SHA256 instead of unsalted MD5, with
# transparent upgrade of any still-legacy hash on next successful login.
# See app/auth.py and app/routes/auth.py.
# --------------------------------------------------------------------------
def test_v_app_06_fix_new_hashes_are_salted_pbkdf2_not_md5():
    import hashlib

    h = hash_password("Test#Pass123")
    assert h != hashlib.md5(b"Test#Pass123").hexdigest()
    assert h.startswith("pbkdf2:")
    # Salted: the same password hashes differently each time.
    assert hash_password("same-password") != hash_password("same-password")


def test_v_app_06_fix_verify_password_still_accepts_legacy_md5_hash():
    """Accounts created before this fix (and the seed data) have a bare MD5
    hash on disk; verify_password must still accept it so existing users
    aren't locked out."""
    import hashlib

    legacy_hash = hashlib.md5(b"Test#Pass123").hexdigest()
    assert verify_password("Test#Pass123", legacy_hash) is True
    assert verify_password("wrong-password", legacy_hash) is False
    assert needs_rehash(legacy_hash) is True


def test_v_app_06_fix_login_transparently_upgrades_legacy_hash(client):
    """A real login against the seeded admin account (still MD5 in
    seed/init.sql) must succeed, and silently rewrite the stored hash to the
    new format so a direct DB read no longer shows a crackable MD5 digest."""
    login = client.post(
        "/v1/auth/login",
        json={"email": "admin@sentinelpay.io", "password": "password123"},
    )
    assert login.status_code == 200, login.get_json()

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT password_hash FROM users WHERE email = %s", ("admin@sentinelpay.io",))
        stored_hash = cur.fetchone()["password_hash"]
    finally:
        cur.close()
        conn.close()

    assert not needs_rehash(stored_hash), "expected the legacy MD5 hash to have been upgraded on login"
    assert verify_password("password123", stored_hash) is True


# --------------------------------------------------------------------------
# V-APP-07 — FIXED: role is no longer client-supplied at registration, and
# update_profile now enforces ownership plus a fixed column allow-list.
# See app/routes/auth.py and app/routes/accounts.py.
# --------------------------------------------------------------------------
def test_v_app_07_fix_register_ignores_client_supplied_role(client):
    """A registration payload requesting role='admin' must now silently
    become 'merchant' — and that account must not be authorised as admin."""
    reg = client.post(
        "/v1/auth/register",
        json={
            "email": f"{uuid.uuid4().hex}@example.com",
            "password": "Test#Pass123",
            "full_name": "Test User",
            "role": "admin",
        },
    )
    assert reg.status_code == 201, reg.get_json()
    assert reg.get_json()["role"] == "merchant"

    login = client.post(
        "/v1/auth/login",
        json={"email": reg.get_json()["email"], "password": "Test#Pass123"},
    )
    token = login.get_json()["token"]
    resp = client.get("/v1/admin/users", headers=auth_header(token))
    assert resp.status_code == 403, "self-requested 'admin' role must not be authorised"


def test_v_app_07_fix_mass_assignment_no_longer_transfers_ownership(client):
    """update_profile must reject unknown/dangerous fields like user_id,
    instead of writing whatever the client sends."""
    attacker_id, attacker_token = register_and_login(client)

    resp = client.put(
        f"/v1/accounts/{OWNERSHIP_TRANSFER_TARGET_ID}/profile",
        json={"user_id": attacker_id},
        headers=auth_header(attacker_token),
    )
    assert resp.status_code == 400


def test_v_app_07_fix_update_profile_requires_ownership(client):
    """Even for an allow-listed field, an unrelated caller must not be able
    to update someone else's account."""
    _, attacker_token = register_and_login(client)

    resp = client.put(
        f"/v1/accounts/{OWNERSHIP_TRANSFER_TARGET_ID}/profile",
        json={"currency": "USD"},
        headers=auth_header(attacker_token),
    )
    assert resp.status_code == 403


def test_v_app_07_fix_owner_can_still_update_allowed_profile_field(client):
    """Confirms the fix didn't just break legitimate profile updates: the
    real owner (via admin, since the seeded merchant password is unknown)
    can still update the allow-listed 'currency' field."""
    admin_token = login_seeded_owner(client)

    resp = client.put(
        f"/v1/accounts/{SEEDED_ACCOUNT_ID}/profile",
        json={"currency": "USD"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["currency"] == "USD"

    # restore, so other tests relying on SEEDED_ACCOUNT_ID's original
    # currency aren't affected by this test's side effect
    client.put(
        f"/v1/accounts/{SEEDED_ACCOUNT_ID}/profile",
        json={"currency": "NGN"},
        headers=auth_header(admin_token),
    )


# --------------------------------------------------------------------------
# V-APP-08 — FIXED: login (per email), register (per IP) and OTP (per
# phone) are now rate limited via Redis. See app/rate_limit.py and
# app/routes/auth.py.
# --------------------------------------------------------------------------
def test_v_app_08_fix_login_is_rate_limited_per_email(client):
    """Brute forcing a single account's password must now be cut off well
    before 25 attempts."""
    email = f"probe-{uuid.uuid4().hex}@example.com"
    client.post("/v1/auth/register", json={"email": email, "password": "Correct#Pass1"})

    statuses = []
    for _ in range(25):
        resp = client.post("/v1/auth/login", json={"email": email, "password": "wrong-guess"})
        statuses.append(resp.status_code)

    assert 429 in statuses, "expected the brute-force attempt to be rate limited"
    assert statuses.count(401) <= 5, "expected only the first few attempts to be evaluated before the limit kicked in"


def test_v_app_08_fix_login_still_works_for_a_different_account(client):
    """Confirms the per-email key doesn't accidentally lock out unrelated
    accounts sharing the same source IP."""
    _, token = register_and_login(client)
    assert token


def test_v_app_08_fix_register_is_rate_limited_per_ip(client):
    """A flood of registrations from a single source IP must now be cut off.
    Uses a distinct fake source IP (via environ_overrides) so this doesn't
    interact with every other test's use of register_and_login on the
    default test-client IP."""
    fake_ip = "203.0.113.77"
    statuses = []
    for _ in range(60):
        resp = client.post(
            "/v1/auth/register",
            json={"email": f"{uuid.uuid4().hex}@example.com", "password": "Test#Pass123"},
            environ_overrides={"REMOTE_ADDR": fake_ip},
        )
        statuses.append(resp.status_code)

    assert 429 in statuses, "expected the registration flood to be rate limited"


def test_v_app_08_fix_otp_request_is_rate_limited_per_phone():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    phone = f"+234{uuid.uuid4().int % 10**10:010d}"

    statuses = []
    for _ in range(10):
        resp = client.post("/v1/auth/otp", json={"phone": phone})
        statuses.append(resp.status_code)

    assert 429 in statuses, "expected repeated OTP requests for the same phone to be rate limited"


def test_v_app_08_fix_otp_code_is_not_logged(capfd):
    """The old code printed the generated OTP to stdout; nothing should be
    printed at all now."""
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    resp = client.post("/v1/auth/otp", json={"phone": f"+234{uuid.uuid4().int % 10**10:010d}"})
    assert resp.status_code == 200

    captured = capfd.readouterr()
    assert "OTP" not in captured.out


# --------------------------------------------------------------------------
# V-APP-09 — verbose error responses
# --------------------------------------------------------------------------
def test_v_app_09_verbose_error_leaks_stack_trace(client):
    _, token = register_and_login(client)
    resp = client.post(
        f"/v1/wallets/{SEEDED_ACCOUNT_ID}/credit",
        json={"amount": "not-a-number"},
        headers=auth_header(token),
    )
    assert resp.status_code == 500
    body = resp.get_json()
    assert "trace" in body and "Traceback" in body["trace"]


# --------------------------------------------------------------------------
# V-APP-10 — insecure deserialisation (pickle RCE)
# --------------------------------------------------------------------------
def test_v_app_10_pickle_deserialisation_executes_arbitrary_code(client, tmp_path):
    _, token = register_and_login(client)
    marker = f"/tmp/pwned_v_app_10_{uuid.uuid4().hex}"
    assert not os.path.exists(marker)

    class Gadget:
        def __reduce__(self):
            return (os.system, (f"touch {marker}",))

    blob = base64.b64encode(pickle.dumps(Gadget())).decode()
    resp = client.post(
        "/v1/admin/session/restore",
        json={"session": blob},
        headers=auth_header(token),
    )

    try:
        assert os.path.exists(marker), (
            f"expected pickle.loads() to execute os.system() as a side effect; "
            f"restore_session returned {resp.status_code} {resp.get_json()}"
        )
    finally:
        if os.path.exists(marker):
            os.remove(marker)


# --------------------------------------------------------------------------
# V-APP-11 — missing audit logging
# --------------------------------------------------------------------------
@pytest.mark.skip(
    reason=(
        "V-APP-11: there is no structured audit logger to assert against yet. "
        "Validated manually today by confirming `docker compose logs payments-api` "
        "contains no structured entry for a debit. This test will be un-skipped and "
        "rewritten against pytest's caplog once the fix PR introduces the audit "
        "logger, asserting a log record with actor/action/object/outcome fields."
    )
)
def test_v_app_11_wallet_debit_emits_no_audit_log():
    pass
