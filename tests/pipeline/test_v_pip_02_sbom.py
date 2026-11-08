"""V-PIP-02 — no SBOM generation.

Static check against .github/workflows/ci.yml. Run from the repo root:

    python3 -m pytest tests/pipeline/test_v_pip_02_sbom.py -v

or directly:

    python3 tests/pipeline/test_v_pip_02_sbom.py

Fails against the inherited ci.yml (no SBOM step at all); passes once the
fix branch's build-and-push job generates, attaches, signs and uploads a
CycloneDX SBOM for the built image.
"""
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _non_comment_text() -> str:
    """Strips full-line and trailing '#' comments so a step merely
    mentioning a tool's name in passing (e.g. documenting that it's
    missing) doesn't satisfy these checks."""
    lines = []
    for line in CI_YML.read_text().splitlines():
        stripped = line.split("#", 1)[0]
        lines.append(stripped)
    return "\n".join(lines)


def test_an_sbom_is_generated_in_cyclonedx_format():
    text = _non_comment_text()
    assert "syft" in text.lower(), "expected an SBOM generator (Syft) to actually run in the pipeline"
    assert "cyclonedx" in text.lower(), "expected the SBOM to be generated in CycloneDX format"


def test_the_sbom_is_attached_to_the_image_and_signed():
    text = _non_comment_text()
    assert "cosign attach sbom" in text, "expected the SBOM to be attached to the image digest, not just produced"
    assert "cosign sign --yes --attachment sbom" in text, (
        "expected the SBOM attachment itself to be signed, same as the image"
    )


def test_the_sbom_is_not_only_discarded_at_build_time():
    text = _non_comment_text()
    assert "upload-artifact" in text and "sbom" in text.lower(), (
        "expected the SBOM to also be uploaded as a retrievable workflow artifact, "
        "not only attached to a registry entry that could itself be pruned"
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
    sys.exit(1 if failures else 0)
