---
title: fullsend journal
---

# fullsend journal

Read and conditionally update the saga journal in the GitLab control repository.
This fork implements [ADR 0165](../ADRs/0165-recover-work-through-repository-owned-operation-journals.md).
It performs no inference. The JSON output is durable state only after the remote
checkpoint is accepted; a failed or ambiguous call is not permission to repeat
an external action.

## Protected host profile

Set `FULLSEND_JOURNAL_PROFILE` in trusted host installation state. Its strict JSON
fields are `forge` (`gitlab`), `base_url` (HTTPS site origin), `owner` (namespace),
`repo`, `branch`, `path` (relative JSON file), and `role`. Source checkouts, tracker
properties and model output cannot supply this profile. The journal branch must
already exist and be protected. The profile selects its exact scope; there are
no command flags to redirect writes elsewhere.

Register `role` as a custom identity through the existing protected
`FULLSEND_GITLAB_ROLE_REGISTRY`, with `write_repository` capability and its own
secret reference. The built-in Analyst, Poller and Coder roles are refused for
this journal command. Journal credentials stay on trusted hosts. The client
rechecks scope, current profile, authenticating credential and branch protection
on access. Neither ambient `GITLAB_TOKEN` nor a local database is a fallback.

## Operations

```sh
fullsend journal initialize
printf '%s' '{"phase":"admitted"}' | fullsend journal admit \
  --id case-001 --binding "reviewed-input-digest"
fullsend journal claim --id case-001 --owner controller-001 --ttl 5m
fullsend journal read --id case-001
```

`initialize` creates the journal on the pre-provisioned branch and refuses an
occupied path. Missing or corrupt existing state requires operator recovery;
ordinary commands never initialize or reset it.

Mutations require `--id`, `--owner` and the `--generation` returned by `claim`:

| Operation | Other flags / standard input |
| --- | --- |
| `admit` | `--binding`; bounded JSON data on stdin |
| `claim` | `--owner`, optional `--ttl` (default 5m, maximum 24h) |
| `renew` | Optional `--ttl` |
| `release` | Releases the current lease |
| `update` | Bounded replacement domain data on stdin; retains budgets/effects |
| `rebind` | `--binding` plus new reviewed domain data on stdin; preserves consumed bounds and effects |
| `intent` | `--effect-id`, `--kind`, `--binding` |
| `effect` | `--effect-id`, `--status`; confirmed receipt JSON on stdin |
| `spend` | `--counter`, `--limit`; consumption survives later attempts |
| `read` | No mutation flags or stdin |

The effect states are `intended`, `in_flight`, `ambiguous` and `confirmed`.
Transition checks and immutable receipts prevent a stale owner or repeated
in-flight admission from authorizing another external write. The CLI retries a
mutation at most three times only when the conditional write was definitively
rejected. It reloads state and rechecks all predicates on each attempt, with short
cancellation-aware backoff. It reads stdin once. Initialization and reads are not
replayed. Exhausted conflicts still require caller recovery; do not force-push or
merge competing JSON claims. These retries do not invoke an agent or repeat an
external action.

GitLab can report a branch-reference race as HTTP 400 with the exact message
`9:reference update: reference does not point to expected object.` The versioned
file adapter classifies this rejected reference update as a revision conflict,
so the same bounded fresh-transaction retry applies. Recognition of this
additional response is exact; similar messages or other HTTP statuses do not
gain retry authority from this rule.

A lost acknowledgement or failed checkpoint verification returns
`journal checkpoint outcome uncertain` and is never automatically retried. Mixed
conflict/unknown errors, invalid readback, and changes to the target record stay
uncertain. Ownership, binding, integrity and budget failures do not retry either.
The backend keeps all authority in one bounded document, using GitLab's file
revision precondition for the complete transition. After an acknowledged Engine
write, it validates the readback document and its exact intended record; unrelated
records may advance. Direct backend callers retain whole-document verification.

A checksum detects accidental corruption; it does not authenticate an actor.
Protected storage and current host authorization remain required. No delivery
or publication guarantee is described as exactly once.

### Bind child mutations to current parent admission

Promotion controllers can pass all three flags on journal commands:

```text
--require-record CASE_ID --require-binding MANIFEST_DIGEST --require-data-digest PARENT_DATA_SHA256
```

The data digest is SHA256 of the exact parent record's `data` bytes, as observed
by a trusted context exporter. Every mutation checks all parent requirements on
its fresh loaded snapshot, including idempotent no-op paths, and again in the
whole-document conditional write. A changed parent rejects the mutation. A
concurrent revision conflict can trigger the bounded transaction retry above;
a newly stale parent then fails its fresh check. This does not retry a model call
or external publication.
Reads remain available for recovery even after a parent changes. Requirements
cannot refer to the mutated record itself. They supplement the child operation's
own ownership generation and do not replace source, Jira or human-approval gates.
