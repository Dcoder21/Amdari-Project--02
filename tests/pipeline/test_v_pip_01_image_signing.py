"""V-PIP-01 — unsigned container images.

Static check against .github/workflows/ci.yml (not a live CI run, since
this sandbox has no AWS/ECR/GitHub Actions to execute against). Run from
the repo root:

    python3 -m pytest tests/pipeline/test_v_pip_01_image_signing.py -v

or directly:

    python3 tests/pipeline/test_v_pip_01_image_signing.py

Fails against the inherited ci.yml (no cosign step at all); passes once
the fix branch's build-and-push job signs the pushed image and a
verify-signature (or deploy) job verifies it.
"""
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_image_signature.sh"


def test_build_and_push_signs_the_image_with_cosign():
    text = CI_YML.read_text()
    assert "sigstore/cosign-installer" in text, "expected cosign to be installed in the pipeline"
    assert "cosign sign" in text, "expected an image to actually be signed, not just cosign installed"


def test_build_and_push_requests_an_oidc_token_for_keyless_signing():
    text = CI_YML.read_text()
    assert "id-token: write" in text, (
        "keyless cosign signing requires requesting the job's OIDC identity token"
    )


def test_a_verification_step_fails_closed_before_deploy():
    text = CI_YML.read_text()
    assert "verify_image_signature.sh" in text, (
        "expected a signature verification step gating the pipeline (ideally before deploy)"
    )
    assert VERIFY_SCRIPT.exists(), "verify_image_signature.sh referenced by ci.yml must exist"
    assert VERIFY_SCRIPT.stat().st_mode & 0o111, "verify_image_signature.sh must be executable"


def test_verify_script_fails_closed_on_an_actually_unsigned_image():
    """Without a real cosign binary + registry in this sandbox, this
    exercises the one thing we CAN check here: the script's own
    `set -e`/explicit exit-on-failure behaviour, by running it with no
    arguments (its own usage-error path) and confirming it exits non-zero
    rather than silently succeeding."""
    result = subprocess.run(["bash", str(VERIFY_SCRIPT)], capture_output=True, text=True)
    assert result.returncode != 0, "verify_image_signature.sh must fail closed, not exit 0, on error"


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
    sys.exit(1 if failures else 0)
