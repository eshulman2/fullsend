package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/fullsend-ai/fullsend/internal/trackerworker"
	"github.com/fullsend-ai/fullsend/internal/ui"
	"github.com/stretchr/testify/require"
)

func trackerCLIGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}
func trackerCLISetup(t *testing.T) (*journal.Engine, trackerflow.Request, trackerworker.Profile, []string) {
	t.Helper()
	engine, backend := journalCommandFixture(t)
	require.NoError(t, backend.Initialize(context.Background()))
	source := t.TempDir()
	trackerCLIGit(t, source, "init", "--initial-branch=release/1")
	trackerCLIGit(t, source, "config", "user.name", "Test Worker")
	trackerCLIGit(t, source, "config", "user.email", "test@example.invalid")
	require.NoError(t, os.WriteFile(filepath.Join(source, "source.txt"), []byte("source"), 0600))
	trackerCLIGit(t, source, "add", "source.txt")
	trackerCLIGit(t, source, "commit", "-m", "fixture")
	trackerCLIGit(t, source, "remote", "add", "origin", "https://github.com/example/repo.git")
	sourceSHA := trackerCLIGit(t, source, "rev-parse", "HEAD")
	trackerCLIGit(t, source, "update-ref", "refs/remotes/origin/release/1", sourceSHA)
	p := trackerworker.Profile{Agent: "cve", FullsendDir: t.TempDir(), RunnerRevision: strings.Repeat("a", 40), Image: "example.invalid/sandbox@sha256:" + strings.Repeat("b", 64), Model: "example/model", Effort: "low", Files: map[string]string{}, AssessmentFile: "assessment.json", ValidatorFile: "validate"}
	for _, name := range []string{"config.yaml", "lock.yaml", "harness/cve.yaml", "validate"} {
		path := filepath.Join(p.FullsendDir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		data := []byte("trusted " + name)
		require.NoError(t, os.WriteFile(path, data, 0600))
		sum := sha256.Sum256(data)
		p.Files[name] = hex.EncodeToString(sum[:])
	}
	r := trackerflow.Request{OperationID: "dispatch-1", CaseID: "case-1", TargetID: "target-" + strings.Repeat("c", 64), JiraKey: "TEST-1", Repository: "https://github.com/example/repo", Branch: "release/1", SourceSHA: sourceSHA, Agent: p.Agent, ProfileDigest: p.Digest(), PolicyDigest: strings.Repeat("d", 64), ManifestDigest: strings.Repeat("e", 64)}
	flow := trackerflow.Profile{Agent: r.Agent, ProfileDigest: r.ProfileDigest, PolicyDigest: r.PolicyDigest, AllowedTargetIDs: []string{r.TargetID}, Jira: trackerflow.JiraProfile{BaseURL: "https://jira.example.com", Project: "TEST", IssueTypeID: "1", AssigneeAccountID: "assignee", ActorAccountID: "actor"}, Control: trackerflow.ControlProfile{BaseURL: "https://gitlab.example.com", Owner: "control", Repository: "fullsend", WorkerRef: "main", DispatchRole: "dispatcher", LookupSince: time.Now().Add(-time.Hour)}}
	state := trackerflow.CaseState{ManifestDigest: r.ManifestDigest, Required: []string{r.TargetID}, Targets: map[string]trackerflow.TargetState{r.TargetID: {Target: trackerflow.Target{Repository: r.Repository, Branch: r.Branch, SourceSHA: r.SourceSHA}, Tracker: &trackerflow.TrackerReceipt{Key: r.JiraKey}, Attempts: []trackerflow.Attempt{{Request: r, State: "accepted"}}}}}
	data, err := json.Marshal(state)
	require.NoError(t, err)
	_, err = engine.Admit(context.Background(), r.CaseID, r.ManifestDigest, data)
	require.NoError(t, err)
	data, err = json.Marshal(trackerflow.WorkerState{Request: r, State: "admitted"})
	require.NoError(t, err)
	_, err = engine.Admit(context.Background(), r.OperationID, r.Digest(), data)
	require.NoError(t, err)
	profileRaw, err := json.Marshal(p)
	require.NoError(t, err)
	flowRaw, err := json.Marshal(flow)
	require.NoError(t, err)
	t.Setenv(trackerworker.ProfileEnv, string(profileRaw))
	t.Setenv(trackerflow.ProfileEnv, string(flowRaw))
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_PATH", "control/fullsend")
	t.Setenv("CI_COMMIT_REF_NAME", "main")
	t.Setenv("CI_COMMIT_REF_PROTECTED", "true")
	t.Setenv("CI_PIPELINE_ID", "1")
	t.Setenv("CI_PIPELINE_URL", "https://gitlab.example.com/control/fullsend/-/pipelines/1")
	oldSHA := commitSHA
	commitSHA = p.RunnerRevision
	t.Cleanup(func() { commitSHA = oldSHA })
	oldExecutor, oldFinalizer := trackerAssessmentExecutor, trackerEvidenceFinalizer
	t.Cleanup(func() { trackerAssessmentExecutor = oldExecutor; trackerEvidenceFinalizer = oldFinalizer })
	trackerAssessmentExecutor = func(context.Context, trackerflow.Request, trackerworker.Profile, string, string) error { return nil }
	trackerEvidenceFinalizer = func(ctx context.Context, req trackerflow.Request, _ trackerworker.Profile, _, _ string) (trackerflow.Assessment, error) {
		return trackerflow.Assessment{RequestDigest: req.Digest(), Outcome: "uncertain", ReceiptRef: "validated-host"}, nil
	}
	requestPath := filepath.Join(t.TempDir(), "request.json")
	requestRaw, err := json.Marshal(r)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(requestPath, requestRaw, 0600))
	out := filepath.Join(t.TempDir(), "output")
	args := []string{"--request-file", requestPath, "--target-repo", source, "--output-dir", out, "--owner", "host-1"}
	return engine, r, p, args
}
func runTrackerCLI(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newTrackerWorkerCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}
func TestTrackerWorkerCLIAdmitsSingleTargetAndRejectsRepeat(t *testing.T) {
	engine, r, _, args := trackerCLISetup(t)
	calls := 0
	trackerAssessmentExecutor = func(context.Context, trackerflow.Request, trackerworker.Profile, string, string) error {
		calls++
		return nil
	}
	require.NoError(t, runTrackerCLI(t, args...))
	record, err := engine.Read(context.Background(), r.OperationID)
	require.NoError(t, err)
	var state trackerflow.WorkerState
	require.NoError(t, json.Unmarshal(record.Data, &state))
	require.Equal(t, "assessed", state.State)
	require.Equal(t, "uncertain", state.Assessment.Outcome)
	require.Error(t, runTrackerCLI(t, args...))
	require.Equal(t, 1, calls)
}
func TestTrackerWorkerCLIRequiresProtectedConfiguration(t *testing.T) {
	for _, mode := range []string{"missing-request", "bad-json", "missing-worker-profile", "missing-flow-profile", "wrong-control-project", "unprotected-ref", "journal-denied", "bad-scheduler-id"} {
		t.Run(mode, func(t *testing.T) {
			_, _, _, args := trackerCLISetup(t)
			calls := 0
			trackerAssessmentExecutor = func(context.Context, trackerflow.Request, trackerworker.Profile, string, string) error {
				calls++
				return nil
			}
			switch mode {
			case "missing-request":
				require.NoError(t, os.Remove(args[1]))
			case "bad-json":
				require.NoError(t, os.WriteFile(args[1], []byte("bad"), 0600))
			case "missing-worker-profile":
				t.Setenv(trackerworker.ProfileEnv, "")
			case "missing-flow-profile":
				t.Setenv(trackerflow.ProfileEnv, "")
			case "wrong-control-project":
				t.Setenv("CI_PROJECT_PATH", "other/project")
			case "unprotected-ref":
				t.Setenv("CI_COMMIT_REF_PROTECTED", "false")
			case "journal-denied":
				old := openJournalHost
				openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
					return nil, nil, errors.New("private-token-value")
				}
				t.Cleanup(func() { openJournalHost = old })
			case "bad-scheduler-id":
				t.Setenv("CI_PIPELINE_ID", "")
			}
			err := runTrackerCLI(t, args...)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private-token-value")
			require.Equal(t, 0, calls)
		})
	}
	require.Error(t, runTrackerCLI(t))
}
func TestTrackerAssessmentUsesOrdinaryRunWithoutPublicationAndRestoresEnv(t *testing.T) {
	_, r, p, args := trackerCLISetup(t)
	old := runTrackerAssessmentAgent
	t.Cleanup(func() { runTrackerAssessmentAgent = old })
	t.Setenv("JIRA_ISSUE_KEY", "original")
	t.Setenv("FULLSEND_SANDBOX_IMAGE", "old-image")
	t.Setenv("FULLSEND_TRACKER_REQUEST", "old-request")
	t.Setenv("FULLSEND_TRACKER_ASSESSMENT_PATH", "old-path")
	calls := 0
	runTrackerAssessmentAgent = func(ctx context.Context, agent, dir, out, target, binary string, envFiles []string, noPost bool, debug, forgeFlag, eventFile string, resolve resolveFlags, status statusOpts, printer *ui.Printer, keep bool, overrides runOverrideFlags) error {
		calls++
		require.Equal(t, r.Agent, agent)
		require.Equal(t, p.FullsendDir, dir)
		require.Equal(t, args[3], target)
		require.Equal(t, args[5], out)
		require.True(t, noPost)
		require.Equal(t, "pi", overrides.runtime)
		require.Equal(t, p.Model, overrides.model)
		require.Equal(t, p.Effort, overrides.effort)
		require.Equal(t, r.JiraKey, os.Getenv("JIRA_ISSUE_KEY"))
		require.Equal(t, p.Image, os.Getenv("FULLSEND_SANDBOX_IMAGE"))
		require.Contains(t, os.Getenv("FULLSEND_TRACKER_REQUEST"), r.OperationID)
		return errors.New("execution failed")
	}
	require.Error(t, executeTrackerAssessment(context.Background(), r, p, args[3], args[5]))
	require.Equal(t, 1, calls)
	require.Equal(t, "original", os.Getenv("JIRA_ISSUE_KEY"))
	require.Equal(t, "old-image", os.Getenv("FULLSEND_SANDBOX_IMAGE"))
	require.Equal(t, "old-request", os.Getenv("FULLSEND_TRACKER_REQUEST"))
	require.Equal(t, "old-path", os.Getenv("FULLSEND_TRACKER_ASSESSMENT_PATH"))
}
