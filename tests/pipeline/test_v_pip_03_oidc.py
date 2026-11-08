"""V-PIP-03 — pipeline role has administrator access (long-lived keys).

Static check against .github/workflows/ci.yml. Run from the repo root:

    python3 -m pytest tests/pipeline/test_v_pip_03_oidc.py -v

or directly:

    python3 tests/pipeline/test_v_pip_03_oidc.py

Fails against the inherited ci.yml (static secrets.AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY in both the build-and-push and deploy jobs); passes
once both jobs federate into AWS via OIDC (role-to-assume) instead.

This can't verify the IAM role's actual permission scope (that's Week 2
Terraform, provisioned outside this repo) — only that the pipeline no
longer authenticates with a long-lived key pair at all, which is what
this file can actually show or hide.
"""
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _non_comment_text() -> str:
    lines = []
    for line in CI_YML.read_text().splitlines():
        stripped = line.split("#", 1)[0]
        lines.append(stripped)
    return "\n".join(lines)


def test_no_long_lived_aws_access_keys_are_used():
    text = _non_comment_text()
    assert "secrets.AWS_ACCESS_KEY_ID" not in text, (
        "expected no job to authenticate with a static AWS access key from secrets"
    )
    assert "secrets.AWS_SECRET_ACCESS_KEY" not in text, (
        "expected no job to authenticate with a static AWS secret key from secrets"
    )


def test_aws_credentials_are_configured_via_oidc_role_assumption():
    text = _non_comment_text()
    assert "role-to-assume:" in text, "expected configure-aws-credentials to federate via role-to-assume"


def test_every_job_assuming_an_aws_role_requests_an_oidc_token():
    """role-to-assume without id-token: write on the same job silently
    fails at runtime — this is the actual thing that lets federation work,
    not just cosmetic YAML."""
    import yaml

    workflow = yaml.safe_load(CI_YML.read_text())
    jobs = workflow["jobs"]
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        uses_role_assume = any(
            step.get("uses", "").startswith("aws-actions/configure-aws-credentials")
            and "role-to-assume" in step.get("with", {})
            for step in steps
        )
        if uses_role_assume:
            permissions = job.get("permissions", {})
            assert permissions.get("id-token") == "write", (
                f"job '{job_name}' assumes an AWS role via OIDC but doesn't request "
                f"id-token: write, which federation requires"
            )


if __name__ == "__main__":
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS: {name}")
            except AssertionError as e:
                print(f"FAIL: {name}: {e}")
                failures += 1
            except ModuleNotFoundError as e:
                print(f"SKIP: {name}: {e}")
    sys.exit(1 if failures else 0)
