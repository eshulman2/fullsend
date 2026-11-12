package trackerworker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/stretchr/testify/require"
)

type intakeJira struct {
	issue      *jira.Issue
	properties map[string]json.RawMessage
}

func (f *intakeJira) SearchIssues(context.Context, string, int) ([]jira.Issue, error) {
	return nil, nil
}
func (f *intakeJira) GetIssue(context.Context, string) (*jira.Issue, error) { return f.issue, nil }
func (f *intakeJira) GetIssueMetadata(context.Context, string) (*jira.Issue, error) {
	return f.issue, nil
}
func (f *intakeJira) GetEntityProperty(_ context.Context, _ string, key string) (json.RawMessage, error) {
	return f.properties[key], nil
}
func (f *intakeJira) CreateIssue(_ context.Context, in jira.CreateIssueInput) (*jira.CreatedIssue, error) {
	f.issue = &jira.Issue{ID: "1", Key: "TEST-1", Fields: jira.IssueFields{Project: &jira.ProjectRef{Key: in.ProjectKey}, IssueType: &jira.IssueType{ID: in.IssueType}, Assignee: jira.User{AccountID: in.AssigneeAccountID}, Security: json.RawMessage(`null`), Labels: in.Labels}}
	f.issue.Fields.Status.StatusCategory.Key = "new"
	f.properties = map[string]json.RawMessage{}
	for _, p := range in.Properties {
		f.properties[p.Key] = p.Value
	}
	return &jira.CreatedIssue{ID: "1", Key: "TEST-1"}, nil
}
func TestActualIntakeRevocationStopsWorkerBeforeInferenceAndAcceptance(t *testing.T) {
	for _, mode := range []string{"allowed", "before", "after"} {
		t.Run(mode, func(t *testing.T) {
			w, r, source, out := workerFixture(t)
			ctx := context.Background()
			target := trackerflow.Target{Repository: r.Repository, Branch: r.Branch, SourceSHA: r.SourceSHA, Component: "package.json", Product: "demo", Release: "1", Stream: "release", Owner: "owner"}
			target.Intake = map[string]string{"product": "demo", "release": "1", "cve": "CVE-2021-23337", "disclosure": "public", "repository": "example/repo", "owner": "owner", "stream": "release", "fix_category": "dependency-update", "component": "package.json", "advisory_url": "https://example.org/advisory"}
			r.TargetID = trackerflow.TargetID(r.CaseID, target)
			controls := &trackerflow.IssueControls{RequiredLabels: []string{"public-cve"}, BlockedLabels: []string{"embargoed"}}
			w.FlowProfile.AllowedTargetIDs = []string{r.TargetID}
			w.FlowProfile.Jira = trackerflow.JiraProfile{Project: "TEST", IssueTypeID: "1", AssigneeAccountID: "owner", IssueControls: controls}
			m := trackerflow.Manifest{CaseID: r.CaseID, AdvisoryID: target.Intake["cve"], Jira: trackerflow.Destination{Project: "TEST", IssueTypeID: "1", AssigneeAccountID: "owner"}}
			api := &intakeJira{}
			tracker := trackerflow.JiraTracker{Client: api, Controls: controls, AssigneeAccountID: "owner"}
			receipt, err := tracker.Create(ctx, m, target)
			require.NoError(t, err)
			parent := trackerflow.CaseState{ManifestDigest: r.ManifestDigest, Required: []string{r.TargetID}, Targets: map[string]trackerflow.TargetState{r.TargetID: {Target: target, Tracker: &receipt, Attempts: []trackerflow.Attempt{{Request: r, State: "accepted"}}}}}
			raw, err := json.Marshal(parent)
			require.NoError(t, err)
			changeRecord(t, w.Journal, r.CaseID, func(record *journal.Record) error { record.Data = raw; return nil })
			lease, err := w.Journal.Claim(ctx, r.OperationID, "fixture-rebind", time.Minute)
			require.NoError(t, err)
			raw, err = json.Marshal(trackerflow.WorkerState{Request: r, State: "admitted"})
			require.NoError(t, err)
			_, err = w.Journal.Rebind(ctx, r.OperationID, lease, r.Digest(), raw)
			require.NoError(t, err)
			require.NoError(t, w.Journal.Release(ctx, r.OperationID, lease))
			w.RunReceipt.RequestDigest = r.Digest()
			w.CheckIssue = func(ctx context.Context, req trackerflow.Request) error {
				return trackerflow.CheckWorkerIssue(ctx, w.Journal, w.FlowProfile, tracker, req)
			}
			revoke := func() {
				changed := map[string]string{}
				for k, v := range target.Intake {
					changed[k] = v
				}
				changed["release"] = "changed"
				api.properties[trackerflow.IntakeProperty], _ = json.Marshal(changed)
			}
			if mode == "before" {
				revoke()
			}
			calls := 0
			w.Execute = func(_ context.Context, req trackerflow.Request, p Profile, _ string, output string) error {
				calls++
				writeAssessment(t, output, p, req, "uncertain")
				if mode == "after" {
					revoke()
				}
				return nil
			}
			err = w.Run(ctx, r, source, out, false)
			if mode == "allowed" {
				require.NoError(t, err)
				require.Equal(t, "assessed", workerState(t, w, r).State)
			} else {
				require.Error(t, err)
				require.NotEqual(t, "assessed", workerState(t, w, r).State)
			}
			if mode == "before" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}
