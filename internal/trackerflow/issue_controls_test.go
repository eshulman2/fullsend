package trackerflow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/stretchr/testify/require"
)

func publicIssue() *jira.Issue {
	return &jira.Issue{ID: "100", Key: "PROJ-1", Fields: jira.IssueFields{Security: json.RawMessage(`null`), Project: &jira.ProjectRef{Key: "PROJ"}, IssueType: &jira.IssueType{ID: "1"}, Status: jira.Status{StatusCategory: jira.StatusCategory{Key: "new"}}, Assignee: jira.User{AccountID: "owner"}, Labels: []string{"public-cve"}}}
}
func publicControls() *IssueControls {
	return &IssueControls{RequiredLabels: []string{"public-cve"}, BlockedLabels: []string{"embargoed"}}
}

func TestIssueControlsRejectChangedOrUnknownClassification(t *testing.T) {
	for _, mode := range []string{"public", "active", "missing-security", "restricted", "closed", "unknown-status", "unassigned", "reassigned", "wrong-project", "missing-project", "wrong-type", "missing-type", "required-label", "case-sensitive-required", "blocked-label", "nil"} {
		t.Run(mode, func(t *testing.T) {
			issue := publicIssue()
			switch mode {
			case "active":
				issue.Fields.Status.StatusCategory.Key = "indeterminate"
			case "missing-security":
				issue.Fields.Security = nil
			case "restricted":
				issue.Fields.Security = json.RawMessage(`{"id":"1"}`)
			case "closed":
				issue.Fields.Status.StatusCategory.Key = "done"
			case "unknown-status":
				issue.Fields.Status.StatusCategory.Key = ""
			case "unassigned":
				issue.Fields.Assignee.AccountID = ""
			case "reassigned":
				issue.Fields.Assignee.AccountID = "other"
			case "wrong-project":
				issue.Fields.Project.Key = "OTHER"
			case "missing-project":
				issue.Fields.Project = nil
			case "wrong-type":
				issue.Fields.IssueType.ID = "other"
			case "missing-type":
				issue.Fields.IssueType = nil
			case "required-label":
				issue.Fields.Labels = nil
			case "case-sensitive-required":
				issue.Fields.Labels = []string{"PUBLIC-CVE"}
			case "blocked-label":
				issue.Fields.Labels = append(issue.Fields.Labels, "EmBaRgOeD")
			case "nil":
				issue = nil
			}
			err := publicControls().Check(issue, "PROJ", "1", "owner")
			if mode == "public" || mode == "active" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrAuthorization)
			}
		})
	}
	for _, c := range []IssueControls{{}, {RequiredLabels: []string{"bad label"}}, {RequiredLabels: []string{"a"}, BlockedLabels: []string{"A"}}, {RequiredLabels: []string{"a\n"}}} {
		require.Error(t, c.Validate())
	}
}

type metadataFake struct {
	*jiraFake
	readErr  error
	reads    int
	searches int
}

func (f *metadataFake) GetIssueMetadata(context.Context, string) (*jira.Issue, error) {
	f.reads++
	return f.issue, f.readErr
}
func (f *metadataFake) SearchIssueMetadata(context.Context, string, int) ([]jira.Issue, error) {
	f.searches++
	return f.search, f.readErr
}

func TestCurrentIssueGatePrecedesContentAndPublication(t *testing.T) {
	ctx := context.Background()
	m := manifest()
	target := m.Targets[0]
	f := &metadataFake{jiraFake: &jiraFake{}}
	j := JiraTracker{Client: f, Controls: publicControls(), AssigneeAccountID: "owner"}
	receipt, err := j.Create(ctx, m, target)
	require.NoError(t, err)
	require.Contains(t, f.created.Labels, "public-cve")
	// Preserve the publication marker and typed provenance from the original create.
	issue := publicIssue()
	issue.Fields.Project.Key = m.Jira.Project
	issue.Fields.IssueType.ID = m.Jira.IssueTypeID
	issue.Fields.Labels = append(issue.Fields.Labels, f.created.Labels...)
	f.issue = issue
	require.NoError(t, j.Verify(ctx, m, target, receipt))
	f.search = []jira.Issue{*issue}
	got, err := j.Find(ctx, m, target)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, 1, f.searches)
	f.issue.Fields.Security = nil
	require.ErrorIs(t, j.Verify(ctx, m, target, receipt), ErrAuthorization)
	// No comment/property reads or writes may follow a failed metadata gate.
	r := request()
	a := Assessment{RequestDigest: r.Digest(), Outcome: "uncertain", ReceiptRef: "artifact:canonical"}
	_, err = j.FindAssessment(ctx, m, target, r, a)
	require.ErrorIs(t, err, ErrAuthorization)
	_, err = j.PublishAssessment(ctx, m, target, r, a)
	require.ErrorIs(t, err, ErrAuthorization)
	err = j.VerifyAssessment(ctx, m, target, r, a, AssessmentPublicationReceipt{JiraKey: r.JiraKey, CommentID: "1", Binding: Hash(assessmentBinding(m, target, r, a))})
	require.ErrorIs(t, err, ErrAuthorization)
	require.Zero(t, f.commentCreates)
	f.readErr = errors.New("unavailable")
	require.Error(t, j.Verify(ctx, m, target, receipt))
	// Old API implementations cannot bypass newly enabled metadata controls.
	legacy := JiraTracker{Client: &jiraFake{}, Controls: publicControls()}
	_, err = legacy.Find(ctx, m, target)
	require.Error(t, err)
	_, err = legacy.readIssue(ctx, m.Jira.Project, m.Jira.IssueTypeID, receipt.Key)
	require.Error(t, err)
	legacy.Controls = &IssueControls{}
	_, err = legacy.Create(ctx, m, target)
	require.Error(t, err)
}

func TestProfileCurrentIssueAdmission(t *testing.T) {
	ctx := context.Background()
	f := &metadataFake{jiraFake: &jiraFake{issue: publicIssue()}}
	p := Profile{Jira: JiraProfile{Project: "PROJ", IssueTypeID: "1", AssigneeAccountID: "owner", IssueControls: publicControls()}}
	require.NoError(t, p.CheckIssue(ctx, f, "PROJ-1"))
	require.Error(t, p.CheckIssue(ctx, f, "OTHER-1"))
	require.Error(t, p.CheckIssue(ctx, nil, "PROJ-1"))
	f.issue.Key = "PROJ-2"
	require.Error(t, p.CheckIssue(ctx, f, "PROJ-1"))
	f.issue = nil
	require.Error(t, p.CheckIssue(ctx, f, "PROJ-1"))
	f.readErr = errors.New("noaccess")
	require.Error(t, p.CheckIssue(ctx, f, "PROJ-1"))
	p.Jira.IssueControls = nil
	require.NoError(t, p.CheckIssue(ctx, nil, "PROJ-1"))
}

func TestCanonicalAdvisoryIdentitySeparateFromDisplay(t *testing.T) {
	m := manifest()
	m.Advisory = "Constructed fixture: CVE-2021-23337"
	m.AdvisoryID = "CVE-2021-23337"
	require.NoError(t, m.Validate())
	target := m.Targets[0]
	target.Intake = map[string]string{"product": target.Product, "release": target.Release, "cve": m.AdvisoryID, "disclosure": "public", "repository": "example/repo", "owner": target.Owner, "stream": target.Stream, "fix_category": "dependency-update", "component": target.Component, "advisory_url": "https://example.org/advisory"}
	require.NoError(t, validateIntake(m, target))
	target.Intake["cve"] = m.Advisory
	require.Error(t, validateIntake(m, target))
	m.AdvisoryID = "display"
	require.Error(t, m.Validate())
}
