package trackerflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/stretchr/testify/require"
)

type jiraFake struct {
	issue            *jira.Issue
	properties       map[string]json.RawMessage
	created          jira.CreateIssueInput
	createError      error
	search           []jira.Issue
	me               string
	comments         map[string]jira.Comment
	commentCreates   int
	commentError     error
	commentListError error
}

func (j *jiraFake) SearchIssues(context.Context, string, int) ([]jira.Issue, error) {
	return j.search, nil
}
func (j *jiraFake) GetIssue(context.Context, string) (*jira.Issue, error) {
	if j.issue == nil {
		return nil, errors.New("not found")
	}
	return j.issue, nil
}
func (j *jiraFake) GetEntityProperty(_ context.Context, _ string, key string) (json.RawMessage, error) {
	return j.properties[key], nil
}
func (j *jiraFake) CreateIssue(_ context.Context, in jira.CreateIssueInput) (*jira.CreatedIssue, error) {
	j.created = in
	if j.createError != nil {
		return nil, j.createError
	}
	j.issue = &jira.Issue{ID: "100", Key: "PROJ-1", Fields: jira.IssueFields{Project: &jira.ProjectRef{Key: in.ProjectKey}, IssueType: &jira.IssueType{ID: in.IssueType}, Labels: in.Labels}}
	j.properties = map[string]json.RawMessage{}
	for _, p := range in.Properties {
		j.properties[p.Key] = p.Value
	}
	return &jira.CreatedIssue{ID: "100", Key: "PROJ-1"}, nil
}
func (j *jiraFake) GetMyself(context.Context) (*jira.User, error) {
	return &jira.User{AccountID: j.me}, nil
}
func TestJiraOriginalCreateCarriesTypedScopeAndIntake(t *testing.T) {
	m := manifest()
	target := m.Targets[0]
	target.Intake = map[string]string{"product": target.Product, "release": target.Release, "cve": m.Advisory, "disclosure": "public", "repository": "example/repo", "owner": target.Owner, "stream": target.Stream, "fix_category": "dependency-update", "component": target.Component, "advisory_url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}
	api := &jiraFake{}
	adapter := JiraTracker{Client: api}
	r, e := adapter.Create(context.Background(), m, target)
	require.NoError(t, e)
	require.NoError(t, adapter.Verify(context.Background(), m, target, r))
	require.Len(t, api.created.Properties, 2)
	require.Contains(t, api.created.Description, "Applicability: unknown")
	require.Equal(t, "account-1", api.created.AssigneeAccountID)
	api.search = []jira.Issue{*api.issue}
	got, e := adapter.Find(context.Background(), m, target)
	require.NoError(t, e)
	require.Equal(t, []TrackerReceipt{r}, got)
	target.Branch = "other"
	require.Error(t, adapter.Verify(context.Background(), m, target, r))
}
func TestJiraRejectsCandidateTamperingAndMalformedIntake(t *testing.T) {
	m := manifest()
	target := m.Targets[0]
	api := &jiraFake{}
	adapter := JiraTracker{Client: api}
	r, e := adapter.Create(context.Background(), m, target)
	require.NoError(t, e)
	api.issue.Fields.Labels = nil
	require.Error(t, adapter.Verify(context.Background(), m, target, r))
	api.issue.Fields.Labels = []string{marker(m, target)}
	api.properties[ProvenanceProperty] = json.RawMessage(`{"case_id":"other"}`)
	require.Error(t, adapter.Verify(context.Background(), m, target, r))
	api.issue.Fields.Project.Key = "OTHER"
	require.Error(t, adapter.Verify(context.Background(), m, target, r))
	target.Intake = map[string]string{"product": "wrong"}
	_, e = adapter.Create(context.Background(), m, target)
	require.Error(t, e)
	api.createError = errors.New("accepted then disconnected")
	target.Intake = nil
	_, e = adapter.Create(context.Background(), m, target)
	require.ErrorIs(t, e, ErrAmbiguous)
	_, e = (JiraTracker{}).Find(context.Background(), m, target)
	require.Error(t, e)
	_, e = (JiraTracker{}).Create(context.Background(), m, target)
	require.Error(t, e)
}

type pipelineFake struct {
	created int
	inputs  map[string]forge.PipelineInputValue
	runs    []forge.WorkflowRun
	err     error
}

func (p *pipelineFake) CreatePipelineWithInputs(_ context.Context, _, _, _ string, in map[string]forge.PipelineInputValue) (*forge.Pipeline, error) {
	p.created++
	p.inputs = in
	if p.err != nil {
		return nil, p.err
	}
	return &forge.Pipeline{ID: 12, WebURL: "https://control.example/pipelines/12"}, nil
}
func (p *pipelineFake) ListWorkflowRunsSince(context.Context, string, string, string, time.Time) ([]forge.WorkflowRun, error) {
	return p.runs, p.err
}
func (p *pipelineFake) GetWorkflowRun(context.Context, string, string, int) (*forge.WorkflowRun, error) {
	if p.err != nil {
		return nil, p.err
	}
	if len(p.runs) == 0 {
		return nil, errors.New("not found")
	}
	return &p.runs[0], nil
}
func request() Request {
	m := manifest()
	target := m.Targets[0]
	return Request{OperationID: "dispatch-target-1", CaseID: m.CaseID, TargetID: TargetID(m.CaseID, target), JiraKey: "PROJ-1", Repository: target.Repository, Branch: target.Branch, SourceSHA: target.SourceSHA, Agent: m.Agent, ProfileDigest: m.ProfileDigest, PolicyDigest: m.PolicyDigest, ManifestDigest: m.Digest()}
}
func TestGitLabSchedulingReceiptAndAssessmentAreSeparate(t *testing.T) {
	r := request()
	api := &pipelineFake{}
	adapter := GitLabScheduler{Client: api, Owner: "group", Repository: "control", Ref: "main", Since: time.Now().Add(-time.Hour)}
	receipt, e := adapter.Submit(context.Background(), r)
	require.NoError(t, e)
	require.Len(t, api.inputs, 3)
	api.runs = []forge.WorkflowRun{{ID: 12, Name: pipelineName(r), HTMLURL: receipt.RunURL, Status: "completed", Conclusion: "success"}}
	got, assessment, e := adapter.Reconcile(context.Background(), r, &receipt)
	require.NoError(t, e)
	require.Equal(t, "completed", got.State)
	require.Nil(t, assessment)
	got, _, e = adapter.Reconcile(context.Background(), r, nil)
	require.NoError(t, e)
	require.Equal(t, "12", got.RunID)
	api.runs = nil
	_, _, e = adapter.Reconcile(context.Background(), r, nil)
	require.ErrorIs(t, e, ErrAmbiguous)
	require.Equal(t, 1, api.created)
	api.err = errors.New("timeout")
	_, e = adapter.Submit(context.Background(), r)
	require.ErrorIs(t, e, ErrAmbiguous)
}
func TestGitLabRejectsMismatchedAndMultiplePipelines(t *testing.T) {
	r := request()
	api := &pipelineFake{runs: []forge.WorkflowRun{{ID: 12, Name: pipelineName(r), Status: "in_progress", HTMLURL: "https://control.example/12"}}}
	adapter := GitLabScheduler{Client: api, Owner: "g", Repository: "c", Ref: "main", Since: time.Now()}
	receipt := schedulingReceipt(r, api.runs[0])
	require.Equal(t, "running", receipt.State)
	api.runs[0].Name = "other"
	_, _, e := adapter.Reconcile(context.Background(), r, &receipt)
	require.Error(t, e)
	api.runs = []forge.WorkflowRun{{Name: pipelineName(r)}, {Name: pipelineName(r)}}
	_, _, e = adapter.Reconcile(context.Background(), r, nil)
	require.Error(t, e)
	adapter.Since = time.Time{}
	_, _, e = adapter.Reconcile(context.Background(), r, nil)
	require.Error(t, e)
	r.SourceSHA = "bad"
	_, e = adapter.Submit(context.Background(), r)
	require.Error(t, e)
}
func protectedProfile(m Manifest) Profile {
	p := Profile{PolicyDigest: m.PolicyDigest, ProfileDigest: m.ProfileDigest, Agent: m.Agent, Jira: JiraProfile{BaseURL: "https://jira.example", Project: m.Jira.Project, IssueTypeID: m.Jira.IssueTypeID, AssigneeAccountID: m.Jira.AssigneeAccountID, ActorAccountID: "actor"}, Control: ControlProfile{BaseURL: "https://gitlab.example", Owner: "group", Repository: "control", WorkerRef: "main", DispatchRole: "poller", LookupSince: time.Now()}}
	for _, target := range m.Targets {
		p.AllowedTargetIDs = append(p.AllowedTargetIDs, TargetID(m.CaseID, target))
	}
	return p
}
func TestProtectedProfileAuthorizationRechecksRoleAndIdentity(t *testing.T) {
	m := manifest()
	p := protectedProfile(m)
	env := map[string]string{ProfileEnv: string(marshal(p)), "FULLSEND_GITLAB_POLLER_TOKEN": "secret"}
	getenv := func(k string) string { return env[k] }
	loaded, e := LoadProfile(getenv)
	require.NoError(t, e)
	token, e := loaded.Credential(getenv)
	require.NoError(t, e)
	require.Equal(t, "secret", token)
	control := forge.NewFakeClient()
	control.ProtectedBranches["group/control/main"] = true
	account := &jiraFake{me: "actor"}
	authority := ProfileAuthority{Profile: p, Control: control, Jira: account, Getenv: getenv, Token: token}
	require.NoError(t, authority.Authorize(context.Background(), m, m.Targets[0], "admit"))
	require.NoError(t, authority.Authorize(context.Background(), m, m.Targets[0], "publish"))
	require.NoError(t, authority.Authorize(context.Background(), m, m.Targets[0], "dispatch"))
	account.me = "different"
	require.ErrorIs(t, authority.Authorize(context.Background(), m, m.Targets[0], "dispatch"), ErrAuthorization)
	account.me = "actor"
	env["FULLSEND_GITLAB_POLLER_TOKEN"] = "rotated"
	require.ErrorIs(t, authority.Authorize(context.Background(), m, m.Targets[0], "dispatch"), ErrAuthorization)
	env["FULLSEND_GITLAB_POLLER_TOKEN"] = "secret"
	control.ProtectedBranches["group/control/main"] = false
	require.ErrorIs(t, authority.Authorize(context.Background(), m, m.Targets[0], "dispatch"), ErrAuthorization)
	env[ProfileEnv] = `{"unknown":true}`
	_, e = LoadProfile(getenv)
	require.Error(t, e)
}
func TestManifestIdentityAndBounds(t *testing.T) {
	m := manifest()
	id := TargetID(m.CaseID, m.Targets[0])
	m.Targets[0].SourceSHA = strings.Repeat("e", 40)
	require.Equal(t, id, TargetID(m.CaseID, m.Targets[0]))
	require.NoError(t, m.Validate())
	m.Targets = append(m.Targets, m.Targets[0])
	require.Error(t, m.Validate())
	m = manifest()
	m.Targets[0].Repository = "https://user:secret@github.com/example/repo"
	require.Error(t, m.Validate())
	m = manifest()
	m.Limits.MaxConcurrent = 1000
	require.Error(t, m.Validate())
	m = manifest()
	m.Targets[0].Branch = "../bad"
	require.Error(t, m.Validate())
}

func (j *jiraFake) ListCommentsComplete(context.Context, string, int) ([]jira.Comment, error) {
	if j.commentListError != nil {
		return nil, j.commentListError
	}
	var result []jira.Comment
	for _, comment := range j.comments {
		result = append(result, comment)
	}
	return result, nil
}
func (j *jiraFake) CreateJournalComment(_ context.Context, _ string, body string, properties []jira.CommentProperty) (*jira.Comment, error) {
	j.commentCreates++
	if j.commentError != nil {
		return nil, j.commentError
	}
	adf, err := jira.MarkdownToADF(body)
	if err != nil {
		return nil, err
	}
	comment := jira.Comment{ID: fmt.Sprint(j.commentCreates), Body: adf, Properties: properties, Author: jira.User{AccountID: j.me}}
	if j.comments == nil {
		j.comments = map[string]jira.Comment{}
	}
	j.comments[comment.ID] = comment
	return &comment, nil
}
func (j *jiraFake) GetCommentWithProperties(_ context.Context, _ string, id string) (*jira.Comment, error) {
	comment, ok := j.comments[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return &comment, nil
}
func TestJiraAssessmentCommentBindsAttemptAndSourceAndWriter(t *testing.T) {
	m := manifest()
	target := m.Targets[0]
	r := request()
	a := Assessment{RequestDigest: r.Digest(), Outcome: "not_affected", ReceiptRef: "sha256:validated"}
	api := &jiraFake{me: "actor"}
	adapter := JiraTracker{Client: api}
	receipt, err := adapter.PublishAssessment(context.Background(), m, target, r, a)
	require.NoError(t, err)
	require.NoError(t, adapter.VerifyAssessment(context.Background(), m, target, r, a, receipt))
	require.Equal(t, 1, api.commentCreates)
	comments, err := adapter.FindAssessment(context.Background(), m, target, r, a)
	require.NoError(t, err)
	require.Equal(t, []AssessmentPublicationReceipt{receipt}, comments)
	comment := api.comments[receipt.CommentID]
	require.Contains(t, jira.ADFToMarkdown(comment.Body), r.SourceSHA)
	require.Contains(t, strings.ReplaceAll(jira.ADFToMarkdown(comment.Body), `\_`, `_`), "not_affected")
	api.me = "other"
	require.Error(t, adapter.VerifyAssessment(context.Background(), m, target, r, a, receipt))
	api.me = "actor"
	comment.Body = map[string]any{"type": "doc", "version": 1, "content": []any{}}
	api.comments[receipt.CommentID] = comment
	require.Error(t, adapter.VerifyAssessment(context.Background(), m, target, r, a, receipt))
}
func TestJiraAssessmentPublicationRejectsUnboundOrIncompleteEvidence(t *testing.T) {
	m := manifest()
	target := m.Targets[0]
	r := request()
	a := Assessment{RequestDigest: r.Digest(), Outcome: "uncertain", ReceiptRef: "sha256:validated"}
	api := &jiraFake{me: "actor"}
	adapter := JiraTracker{Client: api}
	receipt, err := adapter.PublishAssessment(context.Background(), m, target, r, a)
	require.NoError(t, err)
	wrong := receipt
	wrong.JiraKey = "OTHER-1"
	require.Error(t, adapter.VerifyAssessment(context.Background(), m, target, r, a, wrong))
	wrong = receipt
	wrong.CommentID = "missing"
	require.Error(t, adapter.VerifyAssessment(context.Background(), m, target, r, a, wrong))
	invalid := a
	invalid.RequestDigest = "wrong"
	_, err = adapter.PublishAssessment(context.Background(), m, target, r, invalid)
	require.Error(t, err)
	api.commentError = errors.New("possibly accepted")
	_, err = adapter.PublishAssessment(context.Background(), m, target, r, a)
	require.ErrorIs(t, err, ErrAmbiguous)
	api.commentListError = errors.New("partial history")
	_, err = adapter.FindAssessment(context.Background(), m, target, r, a)
	require.Error(t, err)
	other := JiraTracker{Client: jiraWithoutAssessment{api}}
	_, err = other.PublishAssessment(context.Background(), m, target, r, a)
	require.Error(t, err)
	_, err = other.FindAssessment(context.Background(), m, target, r, a)
	require.Error(t, err)
	require.Error(t, other.VerifyAssessment(context.Background(), m, target, r, a, receipt))
}

type jiraWithoutAssessment struct{ JiraAPI }
