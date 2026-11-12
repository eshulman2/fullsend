# tracker-context

`tracker-context --manifest FILE --target-id ID --target-repo CHECKOUT` exports
fresh host domain context for a separate planning or human-approved remediation
phase. It reads protected trackerflow/journal configuration and performs no
external writes, model calls, coding promotion or publication.

Build with `go build -o tracker-context ./cmd/tracker-context`. Use the same
protected `FULLSEND_TRACKERFLOW_PROFILE`, registered GitLab dispatch role,
`FULLSEND_JOURNAL_*` installation and scoped host Jira credentials as the intake
controller. Promotion requires configured non-nil Jira issue controls; legacy
profiles without public eligibility enforcement are rejected.

The reviewed manifest's target must contain `domain_context` with normalized
`intake` (matching manifest `advisory_id`), `remediation_capabilities`, and
`target_connection` mapping evidence. These are protected mapping/policy inputs;
editable Jira text and model output cannot supply them. The exporter overrides
all authoritative case/target/request/source/Jira/digest fields.

Admission checks:

- Current protected profile, target allowlist, registered credential, service
  actor and protected worker ref via `ProfileAuthority`.
- Current parent manifest, required target and latest current attempt; accepted
  canonical assessment from the matching assessed worker record. A newer pending
  or failed attempt invalidates using an older result. CI termination and model
  assessment remain separate facts.
- Confirmed journal assessment-publication effect and exact retained receipt,
  fresh Jira issue classification/provenance and verified assessment comment.
- Exact actual checkout origin, remote tracking ref, HEAD, named branch and clean
  state via `trackerworker.VerifySource`.
- Final parent/worker rereads reject changes during observation. This is not
  atomic effect authority: the caller still needs a current lease/CAS before
  execution or external publication. Local tracking refs prove exact local pins;
  the trusted mapping/compiler must separately fetch/check current remote heads.

Output is the domain context object plus authoritative `case_id`, `target_id`,
`request_digest`, `manifest_digest`, `policy_digest`, `profile_digest`, `issue_key`,
`repository_sha`, `target`, `target_connection`, `intake_digest`, `target_digest`,
`parent_generation`, `parent_data_digest`, `accepted_native_request` and `accepted_native_assessment`.
Domain digests match the original Python sorted compact ASCII JSON convention.
Generic worker repositories use credential-free HTTPS; the original domain
contract's `target.repository` and connection use exact GitHub `owner/repo`.
Current remediation export explicitly supports GitHub source repositories.

`parent_generation` and SHA256 of raw parent Data (`parent_data_digest`) are volatile observations, not a new assessment/plan identity.
The human-approval adapter excludes only these fields from stable approval identity
and must rely on the coordinator's fresh ownership checks. Every actual mapping,
source, request, manifest, policy, profile or plan change invalidates approval.

Exported native assessment evidence is not a ready original schema-v2 plan. A
separate planning agent and deterministic plan validator must produce that
contract before authenticated human approval can authorize one scoped coding
run. An affected tracker, successful pipeline or API token grants no coding,
merge or Jira closure permission.

Before phase/effect writes, the coordinator passes the fresh observation as
`journal --require-record CASE --require-binding MANIFEST_DIGEST
--require-data-digest PARENT_DATA_DIGEST`. These predicates must be checked on
the same whole-document CAS as the write; a separate preceding read does not
prevent stale-parent admission.

A published host execution failure may also be exported for fresh read-only
triage: the latest parent attempt and worker must agree on the exact diagnostic
`outcome: failed`, `receipt_ref: worker-failure:<operation>`, with worker state
`failed`. All publication, current-parent, Jira and source checks still apply.
Output uses `evidence_kind: failed_host_diagnostic` and
`accepted_native_diagnostic`; it never supplies `accepted_native_assessment` for
this case. Normal validated model evidence uses `evidence_kind:
canonical_assessment`. A failed diagnostic establishes no applicability finding
or ready plan. Coding still requires a new independently validated affected,
ready, in-scope plan and fresh authenticated human approval.
