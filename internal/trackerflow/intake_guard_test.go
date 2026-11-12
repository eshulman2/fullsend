package trackerflow

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/stretchr/testify/require"
)

func typedIntake(m Manifest, t Target) map[string]string {
	return map[string]string{"product": t.Product, "release": t.Release, "cve": m.Advisory, "disclosure": "public", "repository": "example/repo", "owner": t.Owner, "stream": t.Stream, "fix_category": "dependency-update", "component": t.Component, "advisory_url": "https://example.org/advisory"}
}
func guardedFixture(t *testing.T) (Manifest, Target, *metadataFake, JiraTracker, TrackerReceipt) {
	t.Helper()
	m := manifest()
	target := m.Targets[0]
	target.Intake = typedIntake(m, target)
	api := &metadataFake{jiraFake: &jiraFake{}}
	tracker := JiraTracker{Client: api, Controls: publicControls(), AssigneeAccountID: m.Jira.AssigneeAccountID}
	receipt, err := tracker.Create(context.Background(), m, target)
	require.NoError(t, err)
	api.issue.Fields.Security = json.RawMessage(`null`)
	api.issue.Fields.Status = publicIssue().Fields.Status
	api.issue.Fields.Assignee.AccountID = m.Jira.AssigneeAccountID
	return m, target, api, tracker, receipt
}
func TestCurrentTypedIntakeCannotBeChangedOrRemoved(t *testing.T) {
	for _, mode := range []string{"unchanged", "cve", "release", "owner", "missing", "extra", "wrong-type", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			m, target, api, tracker, receipt := guardedFixture(t)
			current := typedIntake(m, target)
			switch mode {
			case "cve", "release", "owner":
				current[mode] = "changed"
			case "extra":
				current["extra"] = "value"
			}
			api.properties[IntakeProperty] = marshal(current)
			if mode == "missing" {
				delete(api.properties, IntakeProperty)
			}
			if mode == "wrong-type" {
				api.properties[IntakeProperty] = json.RawMessage(`{"cve":1}`)
			}
			if mode == "duplicate" {
				api.properties[IntakeProperty] = json.RawMessage(`{"cve":"one","cve":"two"}`)
			}
			err := tracker.Verify(context.Background(), m, target, receipt)
			if mode == "unchanged" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

type guardParent struct{ record *journal.Record }

func (p guardParent) Read(context.Context, string) (*journal.Record, error) { return p.record, nil }
func TestWorkerGuardUsesParentIntakeNotEditablePropertyAuthority(t *testing.T) {
	m, target, api, tracker, receipt := guardedFixture(t)
	r := request()
	r.TargetID = TargetID(m.CaseID, target)
	r.ManifestDigest = m.Digest()
	state := CaseState{ManifestDigest: r.ManifestDigest, Required: []string{r.TargetID}, Targets: map[string]TargetState{r.TargetID: {Target: target, Tracker: &receipt, Attempts: []Attempt{{Request: r, State: "accepted"}}}}}
	record := &journal.Record{Binding: r.ManifestDigest, Data: marshal(state)}
	p := Profile{Agent: r.Agent, PolicyDigest: r.PolicyDigest, ProfileDigest: r.ProfileDigest, AllowedTargetIDs: []string{r.TargetID}, Jira: JiraProfile{Project: m.Jira.Project, IssueTypeID: m.Jira.IssueTypeID, AssigneeAccountID: m.Jira.AssigneeAccountID, IssueControls: publicControls()}}
	ctx := context.Background()
	require.NoError(t, CheckWorkerIssue(ctx, guardParent{record}, p, tracker, r))
	// A current edit revokes the same previously admitted request.
	changed := typedIntake(m, target)
	changed["owner"] = "changed"
	api.properties[IntakeProperty] = marshal(changed)
	require.Error(t, CheckWorkerIssue(ctx, guardParent{record}, p, tracker, r))
	api.properties[IntakeProperty] = marshal(target.Intake)
	require.NoError(t, CheckWorkerIssue(ctx, guardParent{record}, p, tracker, r))
	// Optional domain intake is selected only by the protected parent declaration.
	var genericState CaseState
	require.NoError(t, json.Unmarshal(marshal(state), &genericState))
	genericTarget := genericState.Targets[r.TargetID]
	genericTarget.Target.Intake = nil
	genericState.Targets[r.TargetID] = genericTarget
	genericRecord := *record
	genericRecord.Data = marshal(genericState)
	delete(api.properties, IntakeProperty)
	require.NoError(t, CheckWorkerIssue(ctx, guardParent{&genericRecord}, p, tracker, r))
	// The same missing editable property still revokes a CVE-declared parent.
	require.Error(t, CheckWorkerIssue(ctx, guardParent{record}, p, tracker, r))
	api.properties[IntakeProperty] = marshal(target.Intake)
	for _, mode := range []string{"binding", "manifest", "source", "tracker", "required", "allowlist", "attempt", "invalid-cve", "profile", "no-controls"} {
		t.Run(mode, func(t *testing.T) {
			var copyState CaseState
			require.NoError(t, json.Unmarshal(marshal(state), &copyState))
			copyRecord := *record
			copyProfile := p
			ts := copyState.Targets[r.TargetID]
			switch mode {
			case "binding":
				copyRecord.Binding = "stale"
			case "manifest":
				copyState.ManifestDigest = "stale"
			case "source":
				ts.Target.SourceSHA = strings.Repeat("f", 40)
			case "tracker":
				ts.Tracker.Key = "PROJ-2"
			case "required":
				copyState.Required = nil
			case "allowlist":
				copyProfile.AllowedTargetIDs = nil
			case "attempt":
				ts.Attempts = nil
			case "invalid-cve":
				ts.Target.Intake["cve"] = "invalid"
			case "profile":
				copyProfile.PolicyDigest = strings.Repeat("e", 64)
			case "no-controls":
				copyProfile.Jira.IssueControls = nil
			}
			copyState.Targets[r.TargetID] = ts
			copyRecord.Data = marshal(copyState)
			require.Error(t, CheckWorkerIssue(ctx, guardParent{&copyRecord}, copyProfile, tracker, r))
		})
	}
}
