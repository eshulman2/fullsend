---
title: Tracker-first branch intake
---

# Tracker-first branch intake

This fork includes `cmd/tracker-intake`, a domain adapter for ADR 0167. It creates
one Jira investigation per reviewed source target, then schedules ordinary
single-target Fullsend runs in the GitLab control project. It does not add a
multi-target interface to `fullsend run`, infer affected status from an alert,
merge code or close issues.

## Prepare the host

Supply administrator-controlled `FULLSEND_JOURNAL_PROFILE` and the registered
journal writer credentials. Initialize the protected journal branch explicitly
with `fullsend journal initialize`; a missing journal never silently resets.
Journal contents are JSON in the control repository, independent of source forge.

Supply `FULLSEND_TRACKERFLOW_PROFILE` as protected installation state. Do not
read it from a source checkout, Jira issue or model output. Its fields are:

| Field | Meaning |
| --- | --- |
| `policy_digest`, `profile_digest` | Exact policy identity and canonical worker-profile digest |
| `agent` | Allowed ordinary single-target agent |
| `allowed_target_ids` | Exact stable target IDs printed by the manifest check |
| `jira.base_url`, optional `jira.api_url` | Jira site and scoped API gateway |
| `jira.project`, `issue_type_id`, `assignee_account_id` | Allowed ticket destination |
| `jira.actor_account_id` | Expected authenticated Jira writer account |
| `control.base_url`, `owner`, `repo` | GitLab execution project |
| `control.worker_ref` | Protected ref containing the reviewed worker wrapper |
| `control.dispatch_role` | Registered role with `dispatch_pipeline` capability |
| `control.lookup_since` | RFC3339 lookup boundary no later than the first dispatch |

Use the normal `FULLSEND_JIRA_TOKEN` and optional `FULLSEND_JIRA_EMAIL`, or the
normal Jira OAuth client credentials. Tokens never belong in the manifest.
The adapter rechecks protected configuration, role credentials, worker-ref
protection and the authenticated Jira account before admission and effects.
Workers additionally require the [protected worker profile](../../cli/tracker-worker.md)
and its source/runtime bindings. No human command actor is manufactured.

The GitLab worker wrapper accepts typed inputs `operation_id`, `request_digest`
and `request_b64`. Its pipeline name must be exactly
`trackerflow-$operation_id-$request_digest`, using the input values. It validates
the separately admitted journal operation before invoking ordinary `fullsend run`.
A pipeline name correlates scheduling only; it is never an assessment receipt.

## Review and run a manifest

The bounded JSON manifest has `schema_version: 1`, `case_id`, `revision`,
`public: true`, `advisory`, `policy_digest`, `profile_digest`, `agent`, a `jira`
destination, `limits`, and an explicit `targets` array. Each target supplies
`repository` as a credential-free HTTPS origin, `branch`, pinned `source_sha`,
`component`, `product`, `release`, `stream` and `owner`. Use `blocked_reason` to
account for a known unresolved mapping without pretending it was assessed.
Optional `intake` contains the existing exact ten-field CVE intake; its repository
is the source slug, not the HTTPS origin. Only provide intake supported by the
reviewed worker profile. Without it, the ticket is an investigation rather than
an admitted CVE workflow input.

`limits` requires `max_targets` (at most 100), `max_concurrent` and
`max_attempts` (at most 20). Attempts and effects remain in the journal across
plan changes; changing an input does not replenish consumed bounds. The initial
journal implementation also enforces its document size and record-count limits;
operators must retain/compact history deliberately before those limits are hit.

Validate the reviewed manifest and obtain identities without credentials or API
calls:

```sh
go run ./cmd/tracker-intake --manifest /trusted/manifest.json --check
```

After provisioning the protected profiles and worker wrapper, advance one bounded
cycle with a unique controller identity:

```sh
go run ./cmd/tracker-intake --manifest /trusted/manifest.json \
  --owner controller-invocation-001
```

Schedule this command periodically from the control repository. A run advances
or reconciles durable state; it is not a daemon and does not wait for workers.
Workers claim separate attempt records, allowing different branches to run
concurrently without taking the parent case lease. Their startup and assessment
receipts bind the exact request digest. Source origin, branch and revision must
be checked by the trusted worker before and after inference.

## Recovery and interpretation

Ticket identity combines the case and stable target mapping, excluding the
source SHA. Each ticket starts with applicability unknown. The original create
includes a stable label and typed provenance; reuse verifies project, type,
immutable issue ID and target scope. Multiple candidates block progress. An
ambiguous create remains held even when eventual search is empty.

Dispatch records intent before submission. Recovery can resume a dispatch still
marked intended. Once a request is in flight, an empty scheduler lookup cannot
authorize another submission. Submitted and superseded runs consume concurrency
until their termination is established. A superseded attempt still marked
intended can be cancelled locally before submission. Its cancellation receipt
is distinct from scheduling acceptance, and consumed attempt bounds are retained. Scheduling receipts, validated assessment
receipts and publication receipts remain distinct.

The worker retains validated evidence in its journal record before publication.
The controller publishes it as a marked Jira comment bound to the target,
source revision, attempt and assessment receipt. This is a separate journaled
effect, with intent, acceptance and verified comment identity. Ambiguous comment
creation stays held when a subsequent lookup is empty; publication recovery
never needs to rerun inference. A backend without assessment publication leaves
that target explicitly pending rather than claiming successful publication.

Every required branch stays in the report. Confirmed affected/not-affected
assessments count as assessed only after their Jira comment is confirmed;
uncertain results remain pending human assessment after publication.
Failed runs retry within retained bounds, then remain exhausted on the same
tracker. A successful CI pipeline without a validated receipt is not an affected
or not-affected finding. Case completion never follows from ticket creation or
a successful subset of branches.

Automated tests use synthetic Jira and scheduler transports plus the real journal
engine. Those tests do not establish live source applicability, hosted Pi results
or production GitLab recovery conformance.


### Current Jira eligibility

A protected tracker profile may enable `jira.issue_controls` with bounded
`required_labels` and `blocked_labels` lists. Enabled controls require explicit
`security: null`, the configured project and issue type, a current `new` or
`indeterminate` status category, and the exact configured assignee. Required labels
match exactly; blocked labels match without case sensitivity. Missing
classification, unknown status, reassignment or lookup failure prevents work.
Editable issue properties and labels never grant execution authority.

The adapter reads routing/classification metadata before substantive issue content
or assessment comments. Investigations receive the required labels. The controller
rechecks eligibility before dispatch and publication; workers check before source
fetch/inference and accepting evidence. Revocation leaves work unresolved, never
not affected. Install the controls explicitly: policy digests do not execute gates.
Legacy profiles omitting `issue_controls` keep their existing behavior.

A manifest can supply `advisory_id` as a canonical CVE separately from its
human-readable `advisory`. Original ten-field `fullsend.cve.intake` properties
then use that identifier as `cve`; constructed-fixture labels remain descriptions.
