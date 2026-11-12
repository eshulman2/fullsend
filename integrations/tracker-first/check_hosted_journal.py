#!/usr/bin/env python3
"""Exercise real control-repository CAS/fencing; retains clearly labeled test records."""

import argparse
import hashlib
import json
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fullsend", required=True, help="reviewed fork binary")
    parser.add_argument("--iterations", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 20:
        raise ValueError("iterations must be 1..20")
    prefix = "conformance-" + uuid.uuid4().hex

    def call(*options, payload=None, must_succeed=True):
        response = subprocess.run(
            [args.fullsend, "journal", *options],
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if must_succeed and response.returncode:
            raise ValueError("hosted journal operation failed; retained state requires inspection")
        return response

    for index in range(args.iterations):
        operation = prefix + "-" + str(index)
        payload = {"kind": "hosted-conformance-test", "actual_external_effect": False}
        binding = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        call("admit", "--id", operation, "--binding", binding, payload=payload)

        def claim(owner, operation=operation):
            response = call(
                "claim", "--id", operation, "--owner", owner, "--ttl", "30m", must_succeed=False
            )
            return owner, response

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, ("contender-a", "contender-b")))
        winners = [(owner, response) for owner, response in results if response.returncode == 0]
        if len(winners) != 1:
            raise ValueError("CAS conformance failed: expected exactly one admitted owner")
        owner, response = winners[0]
        lease = json.loads(response.stdout)
        generation = str(lease["generation"])
        common = ("--id", operation, "--owner", owner, "--generation", generation)
        call("spend", *common, "--counter", "attempts", "--limit", "1")
        call(
            "intent",
            *common,
            "--effect-id",
            "synthetic",
            "--kind",
            "conformance",
            "--binding",
            binding,
        )
        call("effect", *common, "--effect-id", "synthetic", "--status", "in_flight")
        call("effect", *common, "--effect-id", "synthetic", "--status", "ambiguous")
        call("release", *common)
        newer = json.loads(
            call("claim", "--id", operation, "--owner", "replacement", "--ttl", "30m").stdout
        )
        if newer["generation"] <= lease["generation"]:
            raise ValueError("ownership generation did not advance")
        stale = call("spend", *common, "--counter", "attempts", "--limit", "2", must_succeed=False)
        if stale.returncode == 0:
            raise ValueError("stale owner was admitted")
        record = json.loads(call("read", "--id", operation).stdout)
        if (
            record["counters"]["attempts"] != 1
            or record["effects"]["synthetic"]["status"] != "ambiguous"
        ):
            raise ValueError("durable bounds or pending effect were lost")
        call(
            "release",
            "--id",
            operation,
            "--owner",
            "replacement",
            "--generation",
            str(newer["generation"]),
        )
    print(
        json.dumps(
            {
                "status": "passed",
                "iterations": args.iterations,
                "record_prefix": prefix,
                "model_calls": 0,
                "jira_writes": 0,
                "retained_test_records": args.iterations,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit(
            "hosted journal check failed; inspect retained conformance records"
        ) from None
