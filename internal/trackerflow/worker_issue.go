package trackerflow

import (
	"context"
	"errors"
	"regexp"

	"github.com/fullsend-ai/fullsend/internal/journal"
)

var workerAdvisoryID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type ParentReader interface {
	Read(context.Context, string) (*journal.Record, error)
}

// CheckWorkerIssue checks current Jira intake against trusted parent admission.
// Editable properties may revoke a run; they never supply execution authority.
func CheckWorkerIssue(ctx context.Context, reader ParentReader, p Profile, tracker JiraTracker, r Request) error {
	if reader == nil || p.Jira.IssueControls == nil || r.Validate() != nil || p.ProfileDigest != r.ProfileDigest || p.PolicyDigest != r.PolicyDigest || p.Agent != r.Agent {
		return ErrAuthorization
	}
	parent, err := reader.Read(ctx, r.CaseID)
	if err != nil {
		return err
	}
	var state CaseState
	if parent == nil || parent.Binding != r.ManifestDigest || DecodeStrict(parent.Data, &state) != nil || state.ManifestDigest != r.ManifestDigest {
		return journal.ErrBinding
	}
	target, ok := state.Targets[r.TargetID]
	if !ok || target.Tracker == nil || target.Tracker.Key != r.JiraKey || TargetID(r.CaseID, target.Target) != r.TargetID || target.Target.Repository != r.Repository || target.Target.Branch != r.Branch || target.Target.SourceSHA != r.SourceSHA {
		return journal.ErrBinding
	}
	allowed := false
	for _, id := range p.AllowedTargetIDs {
		if id == r.TargetID {
			allowed = true
		}
	}
	required := false
	for _, id := range state.Required {
		if id == r.TargetID {
			required = true
		}
	}
	admitted := false
	for _, attempt := range target.Attempts {
		if attempt.Request == r && (attempt.State == "accepted" || attempt.State == "running" || attempt.State == "ambiguous") {
			admitted = true
		}
	}
	if !allowed || !required || !admitted {
		return ErrAuthorization
	}
	m := Manifest{CaseID: r.CaseID, AdvisoryID: target.Target.Intake["cve"], Jira: Destination{Project: p.Jira.Project, IssueTypeID: p.Jira.IssueTypeID, AssigneeAccountID: p.Jira.AssigneeAccountID}}
	if len(target.Target.Intake) > 0 && !workerAdvisoryID.MatchString(m.AdvisoryID) {
		return errors.New("trusted canonical intake required")
	}
	// Bind metadata policy to protected profile, not caller-selected controls.
	tracker.Controls = p.Jira.IssueControls
	tracker.AssigneeAccountID = p.Jira.AssigneeAccountID
	return tracker.Verify(ctx, m, target.Target, *target.Tracker)
}
