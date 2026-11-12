---
title: fullsend tracker-worker
---

# fullsend tracker-worker

Execute one journal-admitted branch attempt through ordinary `fullsend run`.
The [tracker-first adapter](../guides/user/tracker-first-intake.md) creates the
investigation ticket and admits the attempt before scheduling this worker.
This command requires a protected job in the configured GitLab control project.
It does not synthesize a human event or bypass a harness actor predicate.

```sh
fullsend tracker-worker --request-file /private/request.json \
  --target-repo /private/source --output-dir /private/attempt-output \
  --owner job-unique-id
```

`--check` verifies protected profiles, pins and current journal admission before
fetching source. Ordinary execution additionally checks actual origin, explicit
remote branch, source SHA and a clean checkout, then claims the separately
admitted attempt. A named checkout must match the requested branch. A verified
detached checkout is allowed. Existing running/finished attempts require
reconciliation and are not another permission to repeat inference.

## Worker profile

Supply protected `FULLSEND_TRACKER_WORKER_PROFILE` JSON with these fields:

| Field | Required binding |
| --- | --- |
| `agent` | Ordinary single-target agent name |
| `fullsend_dir` | Absolute trusted configuration directory |
| `runner_revision` | Actual binary's stamped 40-character source revision |
| `image` | Sandbox image pinned with `@sha256:` |
| `model`, `effort` | Explicit Pi model and effort |
| `files` | Relative trusted resource paths mapped to SHA256 digests |
| `assessment_file` | Basename of the retained host receipt |
| `validator_file` | Executable local evidence validator, present in `files` |

At minimum, pin `config.yaml`, `lock.yaml`, `harness/<agent>.yaml` and the host
validator. Pin all local scripts/resources consumed by that profile. Normal
resource locks and Pi extension integrity checks still apply. Linked or changed
resources are refused. The canonical worker-profile hash must equal the request
and controller profile's `profile_digest`.

Protected `FULLSEND_TRACKERFLOW_PROFILE`, `FULLSEND_JOURNAL_PROFILE` and their
registered credentials provide the other current policy and storage bindings.
The attempt must also exist in the current parent case and manifest. No profile
is installed or enabled by this fork automatically.

## Evidence and publication

The worker invokes ordinary Fullsend with its normal post-script disabled.
This prevents a publishing post-script from acting before final source and saga
validation. A pinned host validator runs after those checks, with only PATH and
locale in its environment. Its arguments are canonical request JSON, the source
directory and the private attempt-output directory. It must validate the
canonical assessment history and return one JSON object on stdout:

```json
{"request_digest":"<SHA256>","outcome":"uncertain","receipt_ref":"<retained-validated-evidence>"}
```

Receipt references can include a canonical `#sha256=<64 lowercase hex digits>`
fragment binding a retained artifact to its content. Whitespace, control
characters and markup are refused.

Supported outcomes are `affected`, `not_affected`, `uncertain` and `failed`.
A model response or successful pipeline alone is insufficient. The validator is
for local evidence validation, not external publication, and receives no inherited
Jira, forge or inference credentials. Final binding/source checks precede journal
acceptance. Publication remains a separately admitted adapter action.

`--finalize-only` validates retained evidence from a running attempt without
inference. The provided GitLab `after_script` uses this as best-effort cleanup;
periodic controller reconciliation remains necessary after runner loss. The
worker never merges code, promotes coding or closes an issue.

The [deployment template](../../integrations/tracker-first/gitlab-ci.yml) and
[host wrapper](../../integrations/tracker-first/worker.py) are examples to install
in a reviewed control configuration. They require protected credentials, pinned
binaries and a prepared runtime; they are not an enabled production deployment.


When the protected flow profile enables `jira.issue_controls`, the host needs its
configured Jira credentials. Metadata-only checks run before source fetching,
inference and accepting evidence. Missing credentials or changed public
classification, labels, status or assignee fail closed. Jira credentials stay on
the host. Finalization retains these same live eligibility gates.
