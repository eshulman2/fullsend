package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/fullsend-ai/fullsend/internal/resolve"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/fullsend-ai/fullsend/internal/trackerworker"
	"github.com/fullsend-ai/fullsend/internal/ui"
	"github.com/spf13/cobra"
)

var trackerAssessmentExecutor trackerworker.Executor = executeTrackerAssessment
var runTrackerAssessmentAgent = runAgent
var trackerEvidenceFinalizer trackerworker.Finalizer = executeTrackerValidation

func newTrackerWorkerCmd() *cobra.Command {
	var requestFile, targetRepo, outputDir, owner string
	var finalizeOnly, check bool
	cmd := &cobra.Command{Use: "tracker-worker", Short: "Run one journal-admitted tracker assessment through Fullsend", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&requestFile, "request-file", "", "bounded admitted request JSON file")
	cmd.Flags().StringVar(&targetRepo, "target-repo", "", "clean checkout of the exact source branch and SHA")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "private host output directory for this attempt")
	cmd.Flags().StringVar(&owner, "owner", "", "unique host execution owner")
	cmd.Flags().BoolVar(&check, "check", false, "verify journal admission and protected profile before source fetch")
	cmd.Flags().BoolVar(&finalizeOnly, "finalize-only", false, "accept retained validated host evidence without repeating inference")
	for _, name := range []string{"request-file", "target-repo", "output-dir", "owner"} {
		_ = cmd.MarkFlagRequired(name)
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		input, e := os.Open(requestFile)
		if e != nil {
			return errors.New("worker request unavailable")
		}
		raw, e := io.ReadAll(io.LimitReader(input, (1<<20)+1))
		_ = input.Close()
		if e != nil {
			return errors.New("worker request unavailable")
		}
		var request trackerflow.Request
		if e := trackerworker.Decode(raw, &request); e != nil {
			return e
		}
		// Capture trusted host capabilities before ordinary agent role selection
		// clears sibling role secrets. They stay in host memory, not sandbox env.
		environment := map[string]string{}
		for _, entry := range os.Environ() {
			k, v, _ := strings.Cut(entry, "=")
			environment[k] = v
		}
		getenv := func(k string) string { return environment[k] }
		profile, e := trackerworker.Load(getenv)
		if e != nil {
			return e
		}
		flow, e := trackerflow.LoadProfile(getenv)
		if e != nil {
			return e
		}
		if getenv("GITLAB_CI") != "true" || getenv("CI_PROJECT_PATH") != flow.Control.Owner+"/"+flow.Control.Repository || getenv("CI_COMMIT_REF_NAME") != flow.Control.WorkerRef || getenv("CI_COMMIT_REF_PROTECTED") != "true" {
			return errors.New("protected control-project worker job required")
		}
		engine, _, e := openJournalHost(getenv)
		if e != nil {
			return sanitizeJournalError(e)
		}
		worker := trackerworker.Worker{Journal: engine, Profile: profile, FlowProfile: flow, Owner: owner, RunnerRevision: commitSHA,
			RunReceipt: trackerflow.RunReceipt{OperationID: request.OperationID, RequestDigest: request.Digest(), RunID: getenv("CI_PIPELINE_ID"), RunURL: getenv("CI_PIPELINE_URL"), State: "running"},
			Execute:    trackerAssessmentExecutor,
			Finalize:   trackerEvidenceFinalizer,
		}
		if flow.Jira.IssueControls != nil {
			creds, err := jira.CredentialsFromEnv(getenv)
			if err != nil {
				return errors.New("worker Jira credentials required")
			}
			client, err := jira.NewScoped(jira.ScopedConfig{BaseURL: flow.Jira.BaseURL, APIURL: flow.Jira.APIURL}, creds)
			if err != nil {
				return errors.New("worker Jira connection unavailable")
			}
			worker.CheckIssue = func(ctx context.Context, r trackerflow.Request) error {
				return trackerflow.CheckWorkerIssue(ctx, engine, flow, trackerflow.JiraTracker{Client: client, Controls: flow.Jira.IssueControls, AssigneeAccountID: flow.Jira.AssigneeAccountID}, r)
			}
		}
		if check {
			return worker.Validate(cmd.Context(), request)
		}
		return worker.Run(cmd.Context(), request, targetRepo, outputDir, finalizeOnly)
	}
	return cmd
}

func executeTrackerAssessment(ctx context.Context, request trackerflow.Request, p trackerworker.Profile, targetRepo, outputDir string) error {
	body, e := json.Marshal(request)
	if e != nil {
		return e
	}
	// Host scripts may create context and validate a canonical assessment history.
	// An arbitrary model response or CI success is never the assessment receipt.
	values := map[string]string{
		"FULLSEND_TRACKER_REQUEST":         string(body),
		"FULLSEND_TRACKER_ASSESSMENT_PATH": filepath.Join(outputDir, p.AssessmentFile),
		"FULLSEND_SANDBOX_IMAGE":           p.Image,
		"JIRA_ISSUE_KEY":                   request.JiraKey,
	}
	originals := map[string]*string{}
	for k, v := range values {
		if old, ok := os.LookupEnv(k); ok {
			copy := old
			originals[k] = &copy
		}
		if e := os.Setenv(k, v); e != nil {
			return e
		}
	}
	defer func() {
		for k := range values {
			if old := originals[k]; old != nil {
				_ = os.Setenv(k, *old)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}()
	return runTrackerAssessmentAgent(ctx, request.Agent, p.FullsendDir, outputDir, targetRepo, "", nil, true, "", "gitlab", "", resolveFlags{maxDepth: resolve.DefaultMaxDepth, maxResources: resolve.DefaultMaxResources}, statusOpts{}, ui.New(os.Stdout), false, runOverrideFlags{runtime: "pi", model: p.Model, effort: p.Effort})
}

// executeTrackerValidation is pure local evidence validation after fresh saga
// admission. It receives no forge/Jira/model credentials and cannot grant coding.
func executeTrackerValidation(ctx context.Context, r trackerflow.Request, p trackerworker.Profile, source, output string) (trackerflow.Assessment, error) {
	var result trackerflow.Assessment
	if p.ValidatorFile == "" || p.Files[p.ValidatorFile] == "" {
		return result, errors.New("pinned host validator required")
	}
	if err := p.CheckPins(); err != nil {
		return result, err
	}
	raw, _ := json.Marshal(r)
	command := exec.CommandContext(ctx, filepath.Join(p.FullsendDir, p.ValidatorFile), string(raw), source, output)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
	var stdout boundedWorkerOutput
	command.Stdout = &stdout
	// No arbitrary validator error text or inherited credentials reach receipts.
	if err := command.Run(); err != nil {
		return result, errors.New("host evidence validation failed")
	}
	if err := trackerworker.Decode(stdout.Bytes(), &result); err != nil {
		return result, err
	}
	if err := result.Validate(r); err != nil {
		return result, err
	}
	return result, nil
}

type boundedWorkerOutput struct{ bytes.Buffer }

func (b *boundedWorkerOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 1<<20 {
		return 0, errors.New("validator output exceeds bound")
	}
	return b.Buffer.Write(data)
}
