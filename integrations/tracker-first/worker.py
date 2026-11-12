#!/usr/bin/env python3
"""Host wrapper for a protected, pinned tracker-first worker job."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def inference_environment(root):
    """Use the normal GitLab Vertex WIF contract without exposing values in logs."""
    environment = os.environ.copy()
    paths = []
    try:
        # The pinned Pi google-vertex provider reads GOOGLE_CLOUD_LOCATION;
        # other Vertex runtime paths read CLOUD_ML_REGION. Use the reviewed
        # GitLab region for both instead of silently selecting another region.
        region = environment.get("FULLSEND_GCP_REGION", "")
        if region:
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", region):
                raise ValueError("invalid configured inference region")
            environment["CLOUD_ML_REGION"] = region
            environment["GOOGLE_CLOUD_LOCATION"] = region
        provider = environment.get("FULLSEND_GCP_WIF_PROVIDER", "")
        if provider:
            token = environment.get("FULLSEND_ID_TOKEN", "")
            project = environment.get("FULLSEND_GCP_PROJECT_ID", "")
            if (
                not token
                or not project
                or not re.fullmatch(
                    r"projects/[0-9]+/locations/global/workloadIdentityPools/[A-Za-z0-9_-]+/providers/[A-Za-z0-9_-]+",
                    provider,
                )
            ):
                raise ValueError("complete GitLab Vertex identity required")
            credentials = {
                "type": "external_account",
                "audience": "//iam.googleapis.com/" + provider,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "token_url": "https://sts.googleapis.com/v1/token",
                "credential_source": {"file": "/sandbox/workspace/.gcp-oidc-token"},
            }
            account = environment.get("FULLSEND_GCP_SERVICE_ACCOUNT", "")
            if account:
                if not re.fullmatch(
                    r"[a-z][a-z0-9.-]*@[a-z0-9.-]+[.]iam[.]gserviceaccount[.]com", account
                ):
                    raise ValueError("invalid configured inference account")
                credentials["service_account_impersonation_url"] = (
                    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
                    + account
                    + ":generateAccessToken"
                )
            for name, contents in (("oidc", token), ("credentials", json.dumps(credentials))):
                with tempfile.NamedTemporaryFile(
                    mode="w", prefix=name + "-", dir=root, delete=False
                ) as stream:
                    paths.append(Path(stream.name))
                    stream.write(contents)
            environment["GCP_OIDC_TOKEN_FILE"] = str(paths[0])
            environment["GOOGLE_APPLICATION_CREDENTIALS"] = str(paths[1])
            environment["GOOGLE_CLOUD_PROJECT"] = project
            environment["ANTHROPIC_VERTEX_PROJECT_ID"] = project
        yield environment
    finally:
        for path in paths:
            path.unlink(missing_ok=True)


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
    encoded = os.environ["TRACKER_REQUEST_B64"]
    if len(encoded) > 16384:
        raise ValueError("encoded request exceeds bound")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > 12288:
        raise ValueError("request exceeds bound")
    # Preserve the exact canonical bytes used by trackerflow.Request.Digest().
    if hashlib.sha256(raw).hexdigest() != os.environ["TRACKER_REQUEST_DIGEST"]:
        raise ValueError("request digest mismatch")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("structured request required")
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
    if args.finalize_only:
        state = subprocess.run(
            [str(binary), "journal", "read", "--id", operation],
            check=True,
            capture_output=True,
            text=True,
        )
        if json.loads(state.stdout)["data"]["state"] != "running":
            return 0
    # Check trusted admission before even fetching the submitted repository.
    subprocess.run(command + ["--check"], check=True)
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
    if args.finalize_only:
        return subprocess.run(command, check=False).returncode
    with inference_environment(root) as environment:
        return subprocess.run(command, env=environment, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, ValueError, OSError, subprocess.SubprocessError):
        # Remote exception text and credential-bearing clone diagnostics do not
        # become a saga receipt. Pending work is left for reconciliation.
        raise SystemExit("tracker worker setup failed; reconcile the admitted operation") from None
