"""V-PIP-04 — no branch protection on main.

Unlike the other three V-PIP tests, this isn't a static check against a
file in this repo — branch protection is a GitHub repository setting, not
something expressible in ci.yml. This test queries the live setting via
the GitHub API (through the `gh` CLI, which must already be authenticated
in this environment) and so requires network access and a configured
remote, unlike tests/pipeline/test_v_pip_0{1,2,3}.

Run from the repo root:

    python3 -m pytest tests/pipeline/test_v_pip_04_branch_protection.py -v

or directly:

    python3 tests/pipeline/test_v_pip_04_branch_protection.py

Fails before branch protection is configured on main (GitHub returns 404
for "Branch not protected"); passes once required status checks and a
force-push/deletion block are in place.

Note: a required-PR-review check is deliberately NOT included here. This
fork has a single collaborator, and GitHub does not let a PR author
approve their own PR — requiring reviews would have locked the owner out
of merging their own work. Status checks + no direct force-push/deletion
still block an untested or history-rewriting change from reaching main;
required reviews can be added back the moment a second collaborator
exists to actually provide them.
"""
import json
import subprocess
import sys

REPO = "sadorect/Amdari-Project--02"


def _get_protection() -> dict:
    result = subprocess.run(
        ["gh", "api", f"repos/{REPO}/branches/main/protection"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"main is not protected at all (gh api returned: {result.stdout.strip() or result.stderr.strip()})"
        )
    return json.loads(result.stdout)


def test_main_branch_is_protected():
    _get_protection()


def test_status_checks_are_required():
    protection = _get_protection()
    checks = protection.get("required_status_checks")
    assert checks is not None, "expected required_status_checks to be configured"
    assert len(checks.get("contexts", [])) > 0 or len(checks.get("checks", [])) > 0, (
        "expected at least one required status check context"
    )


def test_force_pushes_are_blocked():
    protection = _get_protection()
    assert protection.get("allow_force_pushes", {}).get("enabled") is False


def test_branch_deletion_is_blocked():
    protection = _get_protection()
    assert protection.get("allow_deletions", {}).get("enabled") is False


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
