#!/usr/bin/env python3
"""Host wrapper for a protected, pinned tracker-first worker job."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finalize-only", action="store_true")
    args = parser.parse_args()
    if os.environ.get("CI_DEBUG_TRACE", "").lower() in ("1", "t", "true"):
        raise ValueError("debug trace is not allowed")
    if os.environ.get("CI_COMMIT_REF_PROTECTED") != "true":
        raise ValueError("protected worker ref required")
    binary = Path(os.environ["FULLSEND_TRACKER_BINARY"])
    expected_binary = os.environ["FULLSEND_TRACKER_BINARY_SHA256"]
    if not binary.is_file() or not re.fullmatch("[a-f0-9]{64}", expected_binary):
        raise ValueError("pinned Fullsend binary required")
    with binary.open("rb") as stream:
        actual_binary = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual_binary != expected_binary:
        raise ValueError("Fullsend binary integrity mismatch")
    raw = base64.b64decode(os.environ["TRACKER_REQUEST_B64"], validate=True)
    if len(raw) > 12288:
        raise ValueError("request exceeds bound")
    # Preserve the exact canonical bytes used by trackerflow.Request.Digest().
    if hashlib.sha256(raw).hexdigest() != os.environ["TRACKER_REQUEST_DIGEST"]:
        raise ValueError("request digest mismatch")
    request = json.loads(raw)
    operation = request["operation_id"]
    if operation != os.environ["TRACKER_OPERATION_ID"] or not re.fullmatch(
        "[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", operation
    ):
        raise ValueError("operation mismatch")
    root = Path(os.environ["CI_PROJECT_DIR"]) / ".tracker-work" / operation
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    request_file = root / "request.json"
    request_file.write_bytes(raw)
    request_file.chmod(0o600)
    source = root / "source"
    output = root / "output"
    command = [
        str(binary),
        "tracker-worker",
        "--request-file",
        str(request_file),
        "--target-repo",
        str(source),
        "--output-dir",
        str(output),
        "--owner",
        "job-" + os.environ["CI_JOB_ID"],
    ]
    # Check trusted admission before even fetching the submitted repository.
    subprocess.run(command + ["--check"], check=True)
    if args.finalize_only:
        state = subprocess.run(
            [str(binary), "journal", "read", "--id", operation],
            check=True,
            capture_output=True,
            text=True,
        )
        if json.loads(state.stdout)["data"]["state"] != "running":
            return 0
    if not args.finalize_only:
        # The Go worker verifies canonical origin, branch, exact SHA and clean
        # state again before inference and before accepting evidence.
        repository = request["repository"]
        branch = request["branch"]
        if not repository.startswith("https://") or "@" in repository or branch.startswith("-"):
            raise ValueError("credential-free source and branch required")
        subprocess.run(
            [
                "git",
                "clone",
                "--no-checkout",
                "--single-branch",
                "--branch",
                branch,
                "--",
                repository,
                str(source),
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(source), "checkout", "--detach", request["source_sha"]], check=True
        )
    if args.finalize_only:
        command.append("--finalize-only")
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, ValueError, OSError, subprocess.SubprocessError):
        # Remote exception text and credential-bearing clone diagnostics do not
        # become a saga receipt. Pending work is left for reconciliation.
        raise SystemExit("tracker worker setup failed; reconcile the admitted operation") from None
