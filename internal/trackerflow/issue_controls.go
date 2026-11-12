package trackerflow

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/forge/jira"
)

// IssueControls are protected installation policy, never editable Jira content.
// Enabling them requires public classification, an active assigned target and
// these label gates at every assessment and publication boundary.
type IssueControls struct {
	RequiredLabels []string `json:"required_labels"`
	BlockedLabels  []string `json:"blocked_labels"`
}

func (c IssueControls) Validate() error {
	if len(c.RequiredLabels) == 0 || len(c.RequiredLabels) > 32 || len(c.BlockedLabels) > 32 {
		return errors.New("bounded public issue labels required")
	}
	required := map[string]bool{}
	for _, label := range append(append([]string{}, c.RequiredLabels...), c.BlockedLabels...) {
		if label == "" || len(label) > 128 || strings.ContainsAny(label, " \t\r\n\x00") {
			return errors.New("invalid issue label policy")
		}
	}
	for _, label := range c.RequiredLabels {
		required[strings.ToLower(label)] = true
	}
	for _, label := range c.BlockedLabels {
		if required[strings.ToLower(label)] {
			return errors.New("contradictory issue label policy")
		}
	}
	return nil
}

// IssueMetadataAPI bounds classification reads before substantive Jira content.
type IssueMetadataAPI interface {
	GetIssueMetadata(context.Context, string) (*jira.Issue, error)
	SearchIssueMetadata(context.Context, string, int) ([]jira.Issue, error)
}

type IssueMetadataReader interface {
	GetIssueMetadata(context.Context, string) (*jira.Issue, error)
}

func (c IssueControls) Check(issue *jira.Issue, project, issueType, assignee string) error {
	if c.Validate() != nil || issue == nil || issue.Fields.Project == nil || issue.Fields.Project.Key != project || issue.Fields.IssueType == nil || issue.Fields.IssueType.ID != issueType || assignee == "" || issue.Fields.Assignee.AccountID != assignee || !bytes.Equal(bytes.TrimSpace(issue.Fields.Security), []byte("null")) {
		return ErrAuthorization
	}
	switch issue.Fields.Status.StatusCategory.Key {
	case "new", "indeterminate":
	default:
		return ErrAuthorization
	}
	labels := map[string]bool{}
	folded := map[string]bool{}
	for _, label := range issue.Fields.Labels {
		labels[label] = true
		folded[strings.ToLower(label)] = true
	}
	for _, label := range c.RequiredLabels {
		if !labels[label] {
			return ErrAuthorization
		}
	}
	for _, label := range c.BlockedLabels {
		if folded[strings.ToLower(label)] {
			return ErrAuthorization
		}
	}
	return nil
}

// CheckIssue rechecks current metadata; a historic admission or policy digest
// never stands in for current issue eligibility.
func (p Profile) CheckIssue(ctx context.Context, api IssueMetadataReader, key string) error {
	if p.Jira.IssueControls == nil {
		return nil
	}
	if api == nil || !jiraKey.MatchString(key) || !strings.HasPrefix(key, p.Jira.Project+"-") {
		return ErrAuthorization
	}
	issue, err := api.GetIssueMetadata(ctx, key)
	if err != nil || issue == nil || issue.Key != key {
		return ErrAuthorization
	}
	return p.Jira.IssueControls.Check(issue, p.Jira.Project, p.Jira.IssueTypeID, p.Jira.AssigneeAccountID)
}

func (j JiraTracker) readIssue(ctx context.Context, project, issueType, key string) (*jira.Issue, error) {
	if j.Controls == nil {
		return j.Client.GetIssue(ctx, key)
	}
	api, ok := j.Client.(IssueMetadataReader)
	if !ok {
		return nil, ErrAuthorization
	}
	issue, err := api.GetIssueMetadata(ctx, key)
	if err != nil || issue == nil || issue.Key != key {
		return nil, ErrAuthorization
	}
	if err = j.Controls.Check(issue, project, issueType, j.AssigneeAccountID); err != nil {
		return nil, err
	}
	return issue, nil
}

func (j JiraTracker) checkIssue(ctx context.Context, project, issueType, key string) error {
	if j.Controls == nil {
		return nil
	}
	_, err := j.readIssue(ctx, project, issueType, key)
	return err
}
