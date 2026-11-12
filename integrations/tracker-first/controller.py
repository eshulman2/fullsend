#!/usr/bin/env python3
"""Advance one bounded saga cycle from protected GitLab installation state."""

import hashlib
import os
import re
import subprocess
from pathlib import Path


def main():
    if os.environ.get("CI_DEBUG_TRACE", "").lower() in ("1", "t", "true"):
        raise ValueError("debug trace refused")
    if os.environ.get("CI_COMMIT_REF_PROTECTED") != "true":
        raise ValueError("protected controller ref required")
    binary = Path(os.environ["FULLSEND_TRACKER_INTAKE_BINARY"])
    expected = os.environ["FULLSEND_TRACKER_INTAKE_SHA256"]
    if not binary.is_file() or not re.fullmatch("[a-f0-9]{64}", expected):
        raise ValueError("pinned intake binary required")
    with binary.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise ValueError("intake binary integrity mismatch")
    return subprocess.run(
        [
            str(binary),
            "--manifest",
            os.environ["FULLSEND_TRACKER_MANIFEST"],
            "--owner",
            "pipeline-" + os.environ["CI_PIPELINE_ID"],
        ],
        check=False,
    ).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit(
            "tracker controller setup failed; inspect protected configuration"
        ) from None
