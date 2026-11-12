package trackerflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/forge/jira"
)

const ProvenanceProperty = "fullsend.trackerflow.provenance"
const IntakeProperty = "fullsend.cve.intake"

// JiraAPI is implemented by the normal bounded, credential-safe Jira client.
type JiraAPI interface {
	SearchIssues(context.Context, string, int) ([]jira.Issue, error)
	GetIssue(context.Context, string) (*jira.Issue, error)
	GetEntityProperty(context.Context, string, string) (json.RawMessage, error)
	CreateIssue(context.Context, jira.CreateIssueInput) (*jira.CreatedIssue, error)
}
type JiraTracker struct {
	Client            JiraAPI
	Controls          *IssueControls
	AssigneeAccountID string
}
type scope struct {
	CaseID     string `json:"case_id"`
	TargetID   string `json:"target_id"`
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	Component  string `json:"component"`
	Product    string `json:"product"`
	Release    string `json:"release"`
	Stream     string `json:"stream"`
	Project    string `json:"project"`
	IssueType  string `json:"issue_type"`
}

func trackerScope(m Manifest, t Target) scope {
	return scope{m.CaseID, TargetID(m.CaseID, t), t.Repository, t.Branch, t.Component, t.Product, t.Release, t.Stream, m.Jira.Project, m.Jira.IssueTypeID}
}
func marker(m Manifest, t Target) string { return "fs-target-" + Hash(trackerScope(m, t)) }
func (j JiraTracker) Find(ctx context.Context, m Manifest, t Target) ([]TrackerReceipt, error) {
	if j.Client == nil {
		return nil, errors.New("Jira client required")
	}
	search := j.Client.SearchIssues
	if j.Controls != nil {
		api, ok := j.Client.(IssueMetadataAPI)
		if !ok {
			return nil, errors.New("Jira metadata admission unavailable")
		}
		search = api.SearchIssueMetadata
	}
	issues, err := search(ctx, fmt.Sprintf(`project = "%s" AND labels = "%s"`, m.Jira.Project, marker(m, t)), 2)
	if err != nil {
		return nil, errors.New("Jira candidate search failed")
	}
	result := make([]TrackerReceipt, 0, len(issues))
	for _, issue := range issues {
		r := TrackerReceipt{Key: issue.Key, ID: issue.ID, Binding: Hash(trackerScope(m, t))}
		if err = j.Verify(ctx, m, t, r); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
func (j JiraTracker) Verify(ctx context.Context, m Manifest, t Target, r TrackerReceipt) error {
	if j.Client == nil || !jiraKey.MatchString(r.Key) || !strings.HasPrefix(r.Key, m.Jira.Project+"-") || r.ID == "" || r.Binding != Hash(trackerScope(m, t)) {
		return errors.New("tracker receipt binding mismatch")
	}
	issue, err := j.readIssue(ctx, m.Jira.Project, m.Jira.IssueTypeID, r.Key)
	if err != nil {
		if errors.Is(err, ErrAuthorization) {
			return ErrAuthorization
		}
		return errors.New("Jira target lookup failed")
	}
	if issue.ID != r.ID || issue.Key != r.Key || issue.Fields.Project == nil || issue.Fields.Project.Key != m.Jira.Project || issue.Fields.IssueType == nil || issue.Fields.IssueType.ID != m.Jira.IssueTypeID {
		return errors.New("Jira target destination mismatch")
	}
	hasMarker := false
	for _, label := range issue.Fields.Labels {
		if label == marker(m, t) {
			hasMarker = true
		}
	}
	if !hasMarker {
		return errors.New("Jira original publication marker missing")
	}
	raw, err := j.Client.GetEntityProperty(ctx, r.Key, ProvenanceProperty)
	if err != nil {
		return errors.New("Jira target provenance unavailable")
	}
	var got scope
	if err = json.Unmarshal(raw, &got); err != nil || got != trackerScope(m, t) {
		return errors.New("Jira target provenance mismatch")
	}
	return nil
}
func (j JiraTracker) Create(ctx context.Context, m Manifest, t Target) (TrackerReceipt, error) {
	if j.Client == nil {
		return TrackerReceipt{}, errors.New("Jira client required")
	}
	properties := []jira.CommentProperty{{Key: ProvenanceProperty, Value: marshal(trackerScope(m, t))}}
	if len(t.Intake) > 0 {
		if err := validateIntake(m, t); err != nil {
			return TrackerReceipt{}, err
		}
		properties = append(properties, jira.CommentProperty{Key: IntakeProperty, Value: marshal(t.Intake)})
	}
	description := fmt.Sprintf("Applicability: unknown. This is an investigation, not an affected finding.\n\nAdvisory: %s\n\nTarget: %s %s, stream %s, component %s\n\nRepository: %s\n\nBranch: %s\n\nAttempted source: %s\n\nOwner: %s\n\nAssessment failures and uncertain results remain on this ticket for retry or human triage. Ticket creation grants no coding, merge or closure permission.", m.Advisory, t.Product, t.Release, t.Stream, t.Component, t.Repository, t.Branch, t.SourceSHA, t.Owner)
	summary := fmt.Sprintf("Investigate %s on %s %s", m.Advisory, t.Product, t.Release)
	if len(summary) > 255 {
		summary = summary[:255]
	}
	labels := []string{marker(m, t)}
	if j.Controls != nil {
		if err := j.Controls.Validate(); err != nil {
			return TrackerReceipt{}, err
		}
		labels = append(labels, j.Controls.RequiredLabels...)
	}
	created, err := j.Client.CreateIssue(ctx, jira.CreateIssueInput{ProjectKey: m.Jira.Project, IssueType: m.Jira.IssueTypeID, AssigneeAccountID: m.Jira.AssigneeAccountID, Summary: summary, Description: description, Labels: labels, Properties: properties})
	if err != nil {
		return TrackerReceipt{}, ErrAmbiguous
	}
	if created == nil {
		return TrackerReceipt{}, ErrAmbiguous
	}
	return TrackerReceipt{Key: created.Key, ID: created.ID, Binding: Hash(trackerScope(m, t))}, nil
}
func validateIntake(m Manifest, t Target) error {
	u, err := url.Parse(t.Repository)
	if err != nil {
		return errors.New("invalid intake source")
	}
	slug := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	advisoryID := m.AdvisoryID
	if advisoryID == "" {
		advisoryID = m.Advisory
	}
	expected := map[string]string{"product": t.Product, "release": t.Release, "cve": advisoryID, "disclosure": "public", "repository": slug, "owner": t.Owner, "stream": t.Stream, "fix_category": t.Intake["fix_category"], "component": t.Component, "advisory_url": t.Intake["advisory_url"]}
	if !reflect.DeepEqual(expected, t.Intake) || t.Intake["fix_category"] == "" || t.Intake["advisory_url"] == "" {
		return errors.New("single-target intake must exactly match admitted mapping")
	}
	return nil
}
