"""Exploit tests — one per V-APP finding (and variants) in kyc-api.

V-APP-01, 03, 04 and the KYC-upload findings below are still written
against the inherited, unpatched code and are expected to PASS (the
exploit succeeds) until their own fix branches land. V-APP-02 has already
been fixed (see app/auth.py) — its section below is a regression suite,
and `mint_token()` (standing in for a token payments-api would have
issued) is what every other test in this file uses to get past
`require_auth` now that forging one no longer works.

S3 calls are mocked with moto (requirements-dev.txt) since there is no AWS
account for this engagement right now; the real bucket will be exercised
again once Week 2's Terraform-managed S3 bucket exists.

Run inside the kyc-api container:

    docker compose exec kyc-api pytest tests/test_vulnerabilities.py -v
"""
import io
import os
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from moto import mock_aws

from app.main import create_app
from app.auth import ISSUER, AUDIENCE
from tests.conftest import get_test_private_key_pem

KYC_BUCKET = os.environ.get("KYC_BUCKET", "sentinelpay-kyc-documents")
AWS_REGION = os.environ.get("AWS_REGION", "af-south-1")


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def s3_bucket():
    """A moto-mocked S3 with the KYC bucket pre-created, standing in for the
    real bucket until Week 2's Terraform provisions one.

    Fix for DEPS: moto 5.x replaced the per-service mock_s3() decorator with
    a single mock_aws() covering every AWS service it mocks."""
    with mock_aws():
        import boto3

        s3 = boto3.client(
            "s3",
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        s3.create_bucket(Bucket=KYC_BUCKET, CreateBucketConfiguration={"LocationConstraint": AWS_REGION})
        yield s3


def mint_token(user_id=1, role="merchant"):
    """A legitimately-signed token, standing in for one payments-api would
    have issued after a real login — kyc-api never issues tokens itself."""
    now = datetime.now(tz=timezone.utc)
    payload = {
        "user_id": user_id,
        "role": role,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    return jwt.encode(payload, get_test_private_key_pem(), algorithm="RS256")


def _generate_attacker_rsa_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# V-APP-02 (shared) — FIXED: see payments-api/app/auth.py for the writeup.
# kyc-api holds only the public key, so it can verify but never forge one.
# --------------------------------------------------------------------------
def test_v_app_02_fix_forged_hs256_token_is_rejected(client):
    forged = jwt.encode(
        {"user_id": 999, "role": "admin"},
        "attacker-does-not-know-anything-useful",
        algorithm="HS256",
    )
    resp = client.get("/v1/verify/lookup", query_string={"nin": "00000000000"}, headers=auth_header(forged))
    assert resp.status_code == 401


def test_v_app_02_fix_token_signed_with_wrong_rsa_key_is_rejected(client):
    attacker_private_key = _generate_attacker_rsa_key()
    now = datetime.now(tz=timezone.utc)
    forged = jwt.encode(
        {
            "user_id": 999,
            "role": "admin",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        attacker_private_key,
        algorithm="RS256",
    )
    resp = client.get("/v1/verify/lookup", query_string={"nin": "00000000000"}, headers=auth_header(forged))
    assert resp.status_code == 401


def test_v_app_02_fix_legitimately_minted_token_is_accepted(client):
    """Confirms the fix didn't just break everything: a token signed with
    the real (test) private key — i.e. one payments-api would issue — still
    authenticates."""
    token = mint_token(user_id=1)
    resp = client.get("/v1/verify/lookup", query_string={"nin": "00000000000"}, headers=auth_header(token))
    assert resp.status_code == 200


# --------------------------------------------------------------------------
# V-APP-01 (variant) — FIXED: lookup_kyc now binds bvn/nin as query
# parameters instead of interpolating them into the SQL string. See
# services/kyc-api/app/routes/verify.py.
# --------------------------------------------------------------------------
def test_v_app_01_fix_injection_payload_no_longer_leaks_rows(client):
    token = mint_token()

    baseline = client.get("/v1/verify/lookup", query_string={"bvn": "00000000000"}, headers=auth_header(token))
    assert baseline.status_code == 200
    assert baseline.get_json() == []

    injected = client.get(
        "/v1/verify/lookup",
        query_string={"bvn": "00000000000' OR '1'='1"},
        headers=auth_header(token),
    )
    assert injected.status_code == 200
    assert injected.get_json() == [], (
        "expected the injection payload to be treated as a literal BVN with "
        "no matching rows, not as SQL"
    )


# --------------------------------------------------------------------------
# V-APP-04 (variant) — FIXED: the provider URL is now validated against
# private/loopback/link-local/reserved destinations before being fetched.
# See app/routes/verify.py and app/ssrf_guard.py.
# --------------------------------------------------------------------------
def test_v_app_04_fix_internal_provider_url_is_blocked(client):
    """The same internal payments-api target that used to be reachable via
    the 'provider' override must now be rejected with 400, not fetched."""
    resp = client.post(
        "/v1/verify/bvn",
        json={"bvn": "12345678901", "provider": "http://payments-api:8001/v1/auth/otp"},
        headers=auth_header(mint_token()),
    )
    assert resp.status_code == 400


def test_v_app_04_fix_guard_rejects_private_and_internal_ranges():
    """Unit coverage of the guard itself, independent of DNS/network
    availability in CI: loopback, link-local (incl. cloud metadata),
    RFC1918 private ranges, and non-http(s) schemes must all be rejected."""
    from app.ssrf_guard import is_safe_external_url

    assert is_safe_external_url("http://127.0.0.1/") is False
    assert is_safe_external_url("http://169.254.169.254/latest/meta-data/") is False
    assert is_safe_external_url("http://10.0.0.5/") is False
    assert is_safe_external_url("http://192.168.1.1/") is False
    assert is_safe_external_url("ftp://8.8.8.8/") is False
    assert is_safe_external_url("not-a-url") is False


def test_v_app_04_fix_guard_accepts_public_address():
    """A genuinely public IP literal must still be allowed — confirms the
    fix didn't just block everything."""
    from app.ssrf_guard import is_safe_external_url

    assert is_safe_external_url("https://8.8.8.8/bvn") is True


# --------------------------------------------------------------------------
# V-APP-03 (variant) — FIXED: ownership (via the users/<id>/ key prefix, or
# admin role) is now enforced. See app/routes/documents.py.
# --------------------------------------------------------------------------
def test_v_app_03_fix_unrelated_user_cannot_read_document(client, s3_bucket):
    victim_token = mint_token(user_id=101)
    attacker_token = mint_token(user_id=202)

    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"victim passport bytes"), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(victim_token),
    )
    assert upload.status_code == 201, upload.get_json()
    key = upload.get_json()["key"]
    assert key.startswith("users/101/")

    # The attacker knows the predictable users/<id>/<filename> key but must
    # now be rejected — they don't own it.
    fetch = client.get(f"/v1/documents/{key}", headers=auth_header(attacker_token))
    assert fetch.status_code == 403


def test_v_app_03_fix_owner_can_still_read_own_document(client, s3_bucket):
    """Confirms the fix didn't just lock everyone out: the uploader can
    still read their own document."""
    owner_token = mint_token(user_id=303)

    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"my own passport bytes"), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(owner_token),
    )
    key = upload.get_json()["key"]

    fetch = client.get(f"/v1/documents/{key}", headers=auth_header(owner_token))
    assert fetch.status_code == 200
    assert fetch.data == b"my own passport bytes"


# --------------------------------------------------------------------------
# KYC-UPLOAD — FIXED: no public-read ACL, server-side encryption set
# explicitly, filenames sanitised and uniquified, extension/size validated.
# See app/routes/documents.py.
# --------------------------------------------------------------------------
def test_kyc_upload_fix_no_longer_sets_public_read_acl(client, s3_bucket):
    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"some id document"), "id.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(mint_token(user_id=303)),
    )
    assert upload.status_code == 201
    key = upload.get_json()["key"]

    acl = s3_bucket.get_object_acl(Bucket=KYC_BUCKET, Key=key)
    all_users_grant = [
        g for g in acl["Grants"]
        if g["Grantee"].get("URI", "").endswith("/groups/global/AllUsers")
    ]
    assert not all_users_grant, "expected no AllUsers grant on a newly uploaded document"


def test_kyc_upload_fix_sets_server_side_encryption(client, s3_bucket):
    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"some id document"), "id.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(mint_token(user_id=303)),
    )
    key = upload.get_json()["key"]

    head = s3_bucket.head_object(Bucket=KYC_BUCKET, Key=key)
    assert head.get("ServerSideEncryption") == "AES256"


def test_kyc_upload_fix_rejects_disallowed_extension(client, s3_bucket):
    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"<script>alert(1)</script>"), "exploit.html")},
        content_type="multipart/form-data",
        headers=auth_header(mint_token(user_id=606)),
    )
    assert upload.status_code == 400


def test_kyc_upload_fix_rejects_oversized_file(client, s3_bucket):
    oversized = b"0" * (10 * 1024 * 1024 + 1)
    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(oversized), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(mint_token(user_id=707)),
    )
    assert upload.status_code == 400


def test_kyc_upload_fix_repeated_same_filename_no_longer_collides(client, s3_bucket):
    """Two uploads with the identical filename must now get distinct keys —
    no silent same-key overwrite."""
    token = mint_token(user_id=505)

    first = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"first version of the document"), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(token),
    )
    assert first.status_code == 201
    first_key = first.get_json()["key"]

    second = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"second, unrelated upload"), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(token),
    )
    assert second.status_code == 201
    second_key = second.get_json()["key"]

    assert first_key != second_key
    assert s3_bucket.get_object(Bucket=KYC_BUCKET, Key=first_key)["Body"].read() == b"first version of the document"
    assert s3_bucket.get_object(Bucket=KYC_BUCKET, Key=second_key)["Body"].read() == b"second, unrelated upload"


def test_kyc_upload_fix_path_traversal_filename_is_sanitised(client, s3_bucket):
    """A filename containing '../' must no longer be passed through
    verbatim into the S3 key."""
    token = mint_token(user_id=505)

    resp = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"doc"), "../../etc/weird.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(token),
    )
    assert resp.status_code == 201, resp.get_json()
    key = resp.get_json()["key"]
    assert ".." not in key
    assert key.startswith("users/505/")
