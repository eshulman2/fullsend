package trackerflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
)

// PipelineAPI is the forge abstraction required by the GitLab control adapter.
type PipelineAPI interface {
	CreatePipelineWithInputs(context.Context, string, string, string, map[string]forge.PipelineInputValue) (*forge.Pipeline, error)
	ListWorkflowRunsSince(context.Context, string, string, string, time.Time) ([]forge.WorkflowRun, error)
	GetWorkflowRun(context.Context, string, string, int) (*forge.WorkflowRun, error)
}

// GitLabScheduler uses a reviewed worker wrapper on a protected control ref.
// Pipeline names correlate acceptance only. A successful pipeline never supplies
// an assessment; the admitted worker writes that separately to its journal record.
type GitLabScheduler struct {
	Client                 PipelineAPI
	Owner, Repository, Ref string
	Since                  time.Time
}

func pipelineName(r Request) string { return "trackerflow-" + r.OperationID + "-" + r.Digest() }
func (g GitLabScheduler) Submit(ctx context.Context, r Request) (RunReceipt, error) {
	if err := r.Validate(); err != nil {
		return RunReceipt{}, err
	}
	if g.Client == nil || g.Owner == "" || g.Repository == "" || g.Ref == "" {
		return RunReceipt{}, errors.New("GitLab control binding required")
	}
	request, _ := json.Marshal(r)
	pipeline, err := g.Client.CreatePipelineWithInputs(ctx, g.Owner, g.Repository, g.Ref, map[string]forge.PipelineInputValue{"operation_id": forge.StringInput(r.OperationID), "request_digest": forge.StringInput(r.Digest()), "request_b64": forge.StringInput(base64.StdEncoding.EncodeToString(request))})
	if err != nil || pipeline == nil {
		return RunReceipt{}, ErrAmbiguous
	}
	return RunReceipt{OperationID: r.OperationID, RequestDigest: r.Digest(), RunID: strconv.FormatInt(pipeline.ID, 10), RunURL: pipeline.WebURL, State: "accepted"}, nil
}
func (g GitLabScheduler) Reconcile(ctx context.Context, r Request, known *RunReceipt) (RunReceipt, *Assessment, error) {
	if err := r.Validate(); err != nil {
		return RunReceipt{}, nil, err
	}
	if g.Client == nil {
		return RunReceipt{}, nil, errors.New("GitLab client required")
	}
	if known != nil {
		if err := receiptValid(r, *known); err != nil {
			return RunReceipt{}, nil, err
		}
		id, err := strconv.Atoi(known.RunID)
		if err != nil {
			return RunReceipt{}, nil, errors.New("invalid GitLab pipeline identity")
		}
		run, err := g.Client.GetWorkflowRun(ctx, g.Owner, g.Repository, id)
		if err != nil {
			return RunReceipt{}, nil, ErrAmbiguous
		}
		if run == nil || run.ID != id || run.Name != pipelineName(r) {
			return RunReceipt{}, nil, errors.New("GitLab pipeline correlation mismatch")
		}
		return schedulingReceipt(r, *run), nil, nil
	}
	since := g.Since
	if since.IsZero() {
		return RunReceipt{}, nil, errors.New("durable dispatch lookup boundary required")
	}
	runs, err := g.Client.ListWorkflowRunsSince(ctx, g.Owner, g.Repository, g.Ref, since)
	if err != nil {
		return RunReceipt{}, nil, ErrAmbiguous
	}
	var found *forge.WorkflowRun
	for _, run := range runs {
		if run.Name == pipelineName(r) {
			if found != nil {
				return RunReceipt{}, nil, errors.New("multiple correlated GitLab pipelines")
			}
			copy := run
			found = &copy
		}
	}
	if found == nil {
		return RunReceipt{}, nil, ErrAmbiguous
	}
	return schedulingReceipt(r, *found), nil, nil
}
func schedulingReceipt(r Request, run forge.WorkflowRun) RunReceipt {
	state := "accepted"
	if run.Status == "in_progress" {
		state = "running"
	}
	if run.Status == "completed" {
		switch run.Conclusion {
		case "success":
			state = "completed"
		case "cancelled":
			state = "cancelled"
		default:
			state = "failed"
		}
	}
	return RunReceipt{OperationID: r.OperationID, RequestDigest: r.Digest(), RunID: strconv.Itoa(run.ID), RunURL: run.HTMLURL, State: state}
}
