# Tracker-first saga integration

This fork implements ADRs 0165–0167 without depending on upstream acceptance.
Fullsend remains a single-target runner. The separate adapter creates branch
investigations, checkpoints progress in a GitLab control repository, and
reconciles scheduling and validated assessment receipts.

Build from the reviewed fork commit, stamping the real source revision:

```sh
fullsend_revision=$(git rev-parse HEAD)
go build -ldflags "-X github.com/fullsend-ai/fullsend/internal/cli.commitSHA=$fullsend_revision" \
  -o /private/bin/fullsend ./cmd/fullsend
go build -o /private/bin/tracker-intake ./cmd/tracker-intake
```

A development binary without the expected revision stamp is refused by the
protected worker profile. Pin the resulting binary SHA256 in the control job.
The host image needs the normal Fullsend/OpenShell runtime, Python 3 and Git;
select it by immutable digest. No Pi image patch is needed: the pinned Pi CLI
already refuses duplicate registrations, and Fullsend adds strict native-name
selection and vetted-source checks. Native-tool children are explicitly refused.

Install the [GitLab template](gitlab-ci.yml) and [worker wrapper](worker.py) in a
reviewed protected control ref. Treat it as a separate configuration from an
existing managed Fullsend pipeline. The template's three typed inputs are
scheduling data, not authorization. The worker validates their journal admission
before fetching source. Do not install a configuration that can let input values
replace protected profiles or role credentials.

Provision a separate protected journal branch and explicit JSON initialization,
then supply the administrator-controlled host profiles and registered-role
credentials. See the [journal command](../../docs/cli/journal.md),
[worker command](../../docs/cli/tracker-worker.md) and
[adapter guide](../../docs/guides/user/tracker-first-intake.md) for exact fields.
Keep real site addresses, project identifiers and credential values out of this
repository. Existing Jira and model authentication requirements still apply. The worker job
requests the normal `FULLSEND_ID_TOKEN` audience. For Vertex it prepares private
file-based credentials from the configured `FULLSEND_GCP_WIF_PROVIDER`,
`FULLSEND_GCP_PROJECT_ID` and optional `FULLSEND_GCP_SERVICE_ACCOUNT`.
The reviewed `FULLSEND_GCP_REGION`, when supplied, sets both
`GOOGLE_CLOUD_LOCATION` and `CLOUD_ML_REGION` so Pi and other Vertex readers
use the same location; no region is invented when it is absent. The harness
must retain its ordinary Vertex provider and host-file mounts. No credential
values are written into journal records or committed configuration.

Each worker profile must provide a pinned local evidence validator. The ordinary
publishing post-script is disabled. Validate the canonical assessment output,
not a model-authored verdict file, and return the bound structured receipt.
The controller reports uncertain, failed, missing or exhausted targets without
inventing an affected verdict or permitting remediation. A human retains coding,
merge and issue-closure decisions.

Run one adapter cycle after reviewing the explicit manifest:

```sh
/private/bin/tracker-intake --manifest /trusted/manifest.json --check
/private/bin/tracker-intake --manifest /trusted/manifest.json --owner cycle-unique-id
```

The template includes a protected schedule named `trackerflow reconcile` for
subsequent controller cycles. Supply `FULLSEND_TRACKER_INTAKE_BINARY`, its
`FULLSEND_TRACKER_INTAKE_SHA256`, and the reviewed `FULLSEND_TRACKER_MANIFEST`
path. Worker pipelines remain API-only. The
`after_script` can finalize retained evidence without inference, but runner loss
can prevent cleanup entirely. Ambiguous external creates/submissions stay held
until a verified receipt or operator resolution establishes their outcome.

Local verification:

```sh
go test ./...
go test -race ./internal/journal ./internal/journalhost ./internal/trackerflow ./internal/trackerworker
node --test internal/runtime/pi_extension/fullsend-tools.test.mjs
python3 -m unittest discover -s integrations/tracker-first -p 'test_*.py'
```

Synthetic transports and offline Pi startup tests do not establish hosted
GitLab concurrency, Jira publication, model accuracy or source applicability.
Run those acceptance checks in the authorized control project with controlled
source branches before treating the deployment as accepted.

After explicitly initializing a disposable protected journal, test the real
GitLab backend before enabling case dispatch:

```sh
python3 integrations/tracker-first/check_hosted_journal.py \
  --fullsend /private/bin/fullsend
```

This creates and retains labeled conformance records, races two owners and
checks fencing plus retained budgets/pending effects. It makes no Jira writes
or model calls. It is one hosted storage check, not complete saga acceptance.

The example worker retains its private attempt-output directory as restricted
GitLab job artifacts even after job failure. Credentials are prepared outside
that directory and are not artifact paths. Review the profile's artifact policy
and adjust the example seven-day retention for the deployment. Runner loss can
still prevent upload; missing evidence remains unresolved rather than becoming
an applicability verdict. Pipeline termination must be reconciled before its
concurrency reservation is released.


Protected `FULLSEND_TRACKERFLOW_PROFILE.jira.issue_controls` preserves domain Jira
admission gates through `required_labels` and `blocked_labels`. Enabled controls
require explicit public security classification, the configured project, issue
type and assignee, and an active known status category. Metadata is checked before
content, worker inference and assessment publication. Workers need the same
host-only Jira credentials as the controller. A policy digest does not execute
these gates; omitting controls keeps the legacy installation policy. Use manifest
`advisory_id` for a canonical CVE separately from fixture/display text.
