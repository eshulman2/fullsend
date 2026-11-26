package trackerflow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/fullsend-ai/fullsend/internal/journal"
)

// AssessmentPublicationReceipt confirms a comment, not issue closure or coding permission.
type AssessmentPublicationReceipt struct {
	JiraKey   string `json:"jira_key"`
	CommentID string `json:"comment_id"`
	Binding   string `json:"binding"`
}

// AssessmentPublisher is deliberately separate from tracker creation. A backend
// lacking it must leave validated evidence pending publication.
type AssessmentPublisher interface {
	FindAssessment(context.Context, Manifest, Target, Request, Assessment) ([]AssessmentPublicationReceipt, error)
	PublishAssessment(context.Context, Manifest, Target, Request, Assessment) (AssessmentPublicationReceipt, error)
	VerifyAssessment(context.Context, Manifest, Target, Request, Assessment, AssessmentPublicationReceipt) error
}

const AssessmentProperty = "fullsend.trackerflow.assessment"

type assessmentScope struct {
	Target     scope      `json:"target"`
	Request    Request    `json:"request"`
	Assessment Assessment `json:"assessment"`
}

func assessmentBinding(m Manifest, t Target, r Request, a Assessment) assessmentScope {
	return assessmentScope{trackerScope(m, t), r, a}
}
func assessmentBody(m Manifest, t Target, r Request, a Assessment) string {
	return fmt.Sprintf("Validated branch assessment: %s\n\nCase: %s\n\nTarget: %s %s; branch %s; component %s\n\nRepository: %s\n\nAssessed source revision: %s\n\nAttempt: %s\n\nRequest digest: %s\n\nValidated receipt: %s\n\nThis records triage evidence only. It grants no coding, merge or issue-closure permission.", a.Outcome, m.CaseID, t.Product, t.Release, t.Branch, t.Component, t.Repository, r.SourceSHA, r.OperationID, r.Digest(), a.ReceiptRef)
}

func assessmentMatches(m Manifest, t Target, r Request, a Assessment) error {
	if r.Validate() != nil || a.Validate(r) != nil || r.CaseID != m.CaseID || r.TargetID != TargetID(m.CaseID, t) || r.ManifestDigest != m.Digest() || r.ProfileDigest != m.ProfileDigest || r.PolicyDigest != m.PolicyDigest || r.Agent != m.Agent || r.Repository != t.Repository || r.Branch != t.Branch || r.SourceSHA != t.SourceSHA || !strings.HasPrefix(r.JiraKey, m.Jira.Project+"-") {
		return errors.New("assessment publication inputs mismatch")
	}
	return nil
}

type jiraAssessmentAPI interface {
	ListCommentsComplete(context.Context, string, int) ([]jira.Comment, error)
	CreateJournalComment(context.Context, string, string, []jira.CommentProperty) (*jira.Comment, error)
	GetCommentWithProperties(context.Context, string, string) (*jira.Comment, error)
	GetMyself(context.Context) (*jira.User, error)
}

func (j JiraTracker) FindAssessment(ctx context.Context, m Manifest, t Target, r Request, a Assessment) ([]AssessmentPublicationReceipt, error) {
	api, ok := j.Client.(jiraAssessmentAPI)
	if !ok {
		return nil, errors.New("Jira assessment publication unavailable")
	}
	if err := assessmentMatches(m, t, r, a); err != nil {
		return nil, err
	}
	if err := j.checkIssue(ctx, m.Jira.Project, m.Jira.IssueTypeID, r.JiraKey); err != nil {
		return nil, err
	}
	comments, err := api.ListCommentsComplete(ctx, r.JiraKey, 1000)
	if err != nil {
		return nil, errors.New("assessment comment reconciliation incomplete")
	}
	binding := Hash(assessmentBinding(m, t, r, a))
	var result []AssessmentPublicationReceipt
	for _, comment := range comments {
		for _, p := range comment.Properties {
			if p.Key == AssessmentProperty {
				var got assessmentScope
				if DecodeStrict(p.Value, &got) == nil && Hash(got) == binding {
					receipt := AssessmentPublicationReceipt{JiraKey: r.JiraKey, CommentID: comment.ID, Binding: binding}
					if err = j.VerifyAssessment(ctx, m, t, r, a, receipt); err != nil {
						return nil, err
					}
					result = append(result, receipt)
					break
				}
			}
		}
	}
	return result, nil
}
func (j JiraTracker) PublishAssessment(ctx context.Context, m Manifest, t Target, r Request, a Assessment) (AssessmentPublicationReceipt, error) {
	api, ok := j.Client.(jiraAssessmentAPI)
	if !ok {
		return AssessmentPublicationReceipt{}, errors.New("Jira assessment publication unavailable")
	}
	if err := assessmentMatches(m, t, r, a); err != nil {
		return AssessmentPublicationReceipt{}, err
	}
	if err := j.checkIssue(ctx, m.Jira.Project, m.Jira.IssueTypeID, r.JiraKey); err != nil {
		return AssessmentPublicationReceipt{}, err
	}
	bound := assessmentBinding(m, t, r, a)
	comment, err := api.CreateJournalComment(ctx, r.JiraKey, assessmentBody(m, t, r, a), []jira.CommentProperty{{Key: AssessmentProperty, Value: marshal(bound)}})
	if err != nil || comment == nil || comment.ID == "" {
		return AssessmentPublicationReceipt{}, ErrAmbiguous
	}
	return AssessmentPublicationReceipt{JiraKey: r.JiraKey, CommentID: comment.ID, Binding: Hash(bound)}, nil
}
func (j JiraTracker) VerifyAssessment(ctx context.Context, m Manifest, t Target, r Request, a Assessment, receipt AssessmentPublicationReceipt) error {
	api, ok := j.Client.(jiraAssessmentAPI)
	if !ok {
		return errors.New("Jira assessment publication unavailable")
	}
	if assessmentMatches(m, t, r, a) != nil || receipt.JiraKey != r.JiraKey || receipt.CommentID == "" || receipt.Binding != Hash(assessmentBinding(m, t, r, a)) {
		return errors.New("assessment publication binding mismatch")
	}
	if err := j.checkIssue(ctx, m.Jira.Project, m.Jira.IssueTypeID, r.JiraKey); err != nil {
		return err
	}
	comment, err := api.GetCommentWithProperties(ctx, receipt.JiraKey, receipt.CommentID)
	if err != nil || comment == nil || comment.ID != receipt.CommentID {
		return errors.New("assessment comment identity mismatch")
	}
	me, err := api.GetMyself(ctx)
	if err != nil || me == nil || me.AccountID == "" || comment.Author.AccountID != me.AccountID {
		return errors.New("assessment comment writer mismatch")
	}
	matched := false
	for _, p := range comment.Properties {
		if p.Key == AssessmentProperty {
			var got assessmentScope
			if DecodeStrict(p.Value, &got) == nil && Hash(got) == receipt.Binding {
				matched = true
			}
		}
	}
	expected, err := jira.MarkdownToADF(assessmentBody(m, t, r, a))
	if err != nil {
		return errors.New("assessment comment rendering failed")
	}
	if !matched || strings.TrimSpace(jira.ADFToMarkdown(comment.Body)) != strings.TrimSpace(jira.ADFToMarkdown(expected)) {
		return errors.New("assessment comment evidence mismatch")
	}
	return nil
}

// publishAssessment checkpoints an independently recoverable effect. Its false
// result is an explicit publication hold, never successful case completion.
func (c *Controller) publishAssessment(ctx context.Context, m Manifest, l journal.Lease, state *CaseState, id string, index int) (bool, error) {
	t := state.Targets[id]
	attempt := t.Attempts[index]
	r := attempt.Request
	publisher, ok := c.Tracker.(AssessmentPublisher)
	if !ok {
		t.Status = "publication_pending"
		t.Blocker = "assessment_publisher_unavailable"
		state.Targets[id] = t
		return false, nil
	}
	if attempt.Assessment == nil || assessmentMatches(m, t.Target, r, *attempt.Assessment) != nil || t.Tracker == nil || r.JiraKey != t.Tracker.Key {
		return false, errors.New("assessment publication inputs stale")
	}
	if err := c.authorize(ctx, m, t.Target, "publish"); err != nil {
		t.Status = "publication_pending"
		t.Blocker = "assessment_publication_authorization_required"
		state.Targets[id] = t
		return false, nil
	}
	assessment := *attempt.Assessment
	binding := Hash(assessmentBinding(m, t.Target, r, assessment))
	effectID := "assessment-" + r.OperationID
	record, err := c.Journal.Read(ctx, m.CaseID)
	if err != nil {
		return false, err
	}
	effect, exists := record.Effects[effectID]
	if !exists {
		effect = journal.Effect{ID: effectID, Kind: "assessment_publication", Binding: binding, Status: "intended"}
		if err = c.save(ctx, m, l, *state, func(current *journal.Record) error { current.Effects[effectID] = effect; return nil }); err != nil {
			return false, err
		}
	}
	if effect.Binding != binding {
		return false, journal.ErrBinding
	}
	var receipt AssessmentPublicationReceipt
	if effect.Status == "confirmed" {
		if DecodeStrict(effect.Receipt, &receipt) != nil {
			return false, journal.ErrIntegrity
		}
		if err = publisher.VerifyAssessment(ctx, m, t.Target, r, assessment, receipt); err != nil {
			return false, err
		}
		t.Attempts[index].Publication = &receipt
		state.Targets[id] = t
		return true, nil
	}
	candidates, err := publisher.FindAssessment(ctx, m, t.Target, r, assessment)
	if err != nil {
		return false, err
	}
	if len(candidates) > 1 {
		return false, errors.New("multiple assessment publication candidates")
	}
	if len(candidates) == 1 {
		receipt = candidates[0]
		if err = publisher.VerifyAssessment(ctx, m, t.Target, r, assessment, receipt); err != nil {
			return false, err
		}
	} else {
		if effect.Status != "intended" {
			t.Status = "publication_pending"
			t.Blocker = "assessment_publication_unresolved"
			state.Targets[id] = t
			return false, nil
		}
		if err = c.authorize(ctx, m, t.Target, "publish"); err != nil {
			return false, err
		}
		if err = c.save(ctx, m, l, *state, func(current *journal.Record) error {
			e := current.Effects[effectID]
			if e.Status != "intended" {
				return ErrAmbiguous
			}
			e.Status = "in_flight"
			current.Effects[effectID] = e
			return nil
		}); err != nil {
			return false, err
		}
		receipt, err = publisher.PublishAssessment(ctx, m, t.Target, r, assessment)
		if err == nil {
			err = publisher.VerifyAssessment(ctx, m, t.Target, r, assessment, receipt)
		}
		if err != nil {
			t.Status = "publication_pending"
			t.Blocker = "assessment_publication_unresolved"
			state.Targets[id] = t
			err = c.save(ctx, m, l, *state, func(current *journal.Record) error {
				e := current.Effects[effectID]
				e.Status = "ambiguous"
				current.Effects[effectID] = e
				return nil
			})
			return false, err
		}
	}
	if err = c.authorize(ctx, m, t.Target, "publish"); err != nil {
		return false, err
	}
	t.Attempts[index].Publication = &receipt
	state.Targets[id] = t
	err = c.save(ctx, m, l, *state, func(current *journal.Record) error {
		e := current.Effects[effectID]
		e.Status = "confirmed"
		e.Receipt = marshal(receipt)
		current.Effects[effectID] = e
		return nil
	})
	return err == nil, err
}
