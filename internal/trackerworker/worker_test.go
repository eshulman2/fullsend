package trackerworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/stretchr/testify/require"
)

func workerFixture(t *testing.T, wrappers ...func(journal.Backend) journal.Backend) (Worker, trackerflow.Request, string, string) {
	t.Helper()
	ctx := context.Background()
	p := pinnedProfile(t)
	source, sha := localSource(t)
	targetID := "target-" + strings.Repeat("c", 64)
	r := trackerflow.Request{OperationID: "dispatch-1", CaseID: "case-1", TargetID: targetID, JiraKey: "TEST-1", Repository: "https://github.com/example/repo", Branch: "release/1", SourceSHA: sha, Agent: p.Agent, ProfileDigest: p.Digest(), PolicyDigest: strings.Repeat("d", 64), ManifestDigest: strings.Repeat("e", 64)}
	fc := forge.NewFakeClient()
	fc.BranchRefs["control/repo/journal"] = "head"
	backend, err := journal.NewForgeBackend(fc, journal.Location{Owner: "control", Repo: "repo", Branch: "journal", Path: "journal.json"}, func(context.Context, journal.Location, string) error { return nil })
	require.NoError(t, err)
	require.NoError(t, backend.Initialize(ctx))
	var store journal.Backend = backend
	if len(wrappers) > 0 {
		store = wrappers[0](backend)
	}
	engine := journal.New(store, nil)
	state := trackerflow.CaseState{ManifestDigest: r.ManifestDigest, Required: []string{targetID}, Targets: map[string]trackerflow.TargetState{targetID: {Target: trackerflow.Target{Repository: r.Repository, Branch: r.Branch, SourceSHA: r.SourceSHA}, Tracker: &trackerflow.TrackerReceipt{Key: r.JiraKey}, Attempts: []trackerflow.Attempt{{Request: r}}}}}
	data, err := json.Marshal(state)
	require.NoError(t, err)
	_, err = engine.Admit(ctx, r.CaseID, r.ManifestDigest, data)
	require.NoError(t, err)
	data, err = json.Marshal(trackerflow.WorkerState{Request: r, State: "admitted"})
	require.NoError(t, err)
	_, err = engine.Admit(ctx, r.OperationID, r.Digest(), data)
	require.NoError(t, err)
	w := Worker{Journal: engine, Profile: p, FlowProfile: trackerflow.Profile{Agent: r.Agent, ProfileDigest: r.ProfileDigest, PolicyDigest: r.PolicyDigest, AllowedTargetIDs: []string{r.TargetID}}, Owner: "worker-host", RunnerRevision: p.RunnerRevision, RunReceipt: trackerflow.RunReceipt{OperationID: r.OperationID, RequestDigest: r.Digest(), RunID: "pipeline-1", RunURL: "https://gitlab.example.com/control/repo/-/pipelines/1", State: "running"}, Execute: func(context.Context, trackerflow.Request, Profile, string, string) error { return nil }}
	return w, r, source, filepath.Join(t.TempDir(), "output")
}
func writeAssessment(t *testing.T, out string, p Profile, r trackerflow.Request, outcome string) {
	t.Helper()
	data, err := json.Marshal(trackerflow.Assessment{RequestDigest: r.Digest(), Outcome: outcome, ReceiptRef: "host-receipt:" + r.OperationID})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(out, p.AssessmentFile), data, 0600))
}
func workerState(t *testing.T, w Worker, r trackerflow.Request) trackerflow.WorkerState {
	t.Helper()
	record, err := w.Journal.Read(context.Background(), r.OperationID)
	require.NoError(t, err)
	var state trackerflow.WorkerState
	require.NoError(t, json.Unmarshal(record.Data, &state))
	return state
}
func changeRecord(t *testing.T, e *journal.Engine, id string, change func(*journal.Record) error) {
	t.Helper()
	ctx := context.Background()
	lease, err := e.Claim(ctx, id, "test-controller", time.Minute)
	require.NoError(t, err)
	_, err = e.Update(ctx, id, lease, change)
	require.NoError(t, err)
	require.NoError(t, e.Release(ctx, id, lease))
}
func TestWorkerAcceptsTypedOutcomesOnce(t *testing.T) {
	for _, outcome := range []string{"affected", "not_affected", "uncertain", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			w, r, source, out := workerFixture(t)
			var calls atomic.Int32
			w.Execute = func(ctx context.Context, request trackerflow.Request, p Profile, src, output string) error {
				calls.Add(1)
				require.Equal(t, r, request)
				require.Equal(t, source, src)
				writeAssessment(t, output, p, request, outcome)
				return nil
			}
			require.NoError(t, w.Run(context.Background(), r, source, out, false))
			state := workerState(t, w, r)
			require.Equal(t, "assessed", state.State)
			require.Equal(t, outcome, state.Assessment.Outcome)
			require.NotNil(t, state.RunReceipt)
			require.Error(t, w.Run(context.Background(), r, source, out, false))
			require.Error(t, w.Run(context.Background(), r, source, out, true))
			require.Equal(t, int32(1), calls.Load())
		})
	}
}
func TestMissingReceiptSupportsFinalizeWithoutInference(t *testing.T) {
	w, r, source, out := workerFixture(t)
	calls := 0
	w.Execute = func(context.Context, trackerflow.Request, Profile, string, string) error { calls++; return nil }
	require.ErrorContains(t, w.Run(context.Background(), r, source, out, false), "receipt required")
	require.Equal(t, "running", workerState(t, w, r).State)
	require.Error(t, w.Run(context.Background(), r, source, out, false))
	writeAssessment(t, out, w.Profile, r, "uncertain")
	require.NoError(t, w.Run(context.Background(), r, source, out, true))
	require.Equal(t, 1, calls)
	require.Equal(t, "uncertain", workerState(t, w, r).Assessment.Outcome)
}
func TestExecutionFailureRetainsInvestigation(t *testing.T) {
	w, r, source, out := workerFixture(t)
	w.Execute = func(context.Context, trackerflow.Request, Profile, string, string) error {
		return errors.New("private transport detail")
	}
	err := w.Run(context.Background(), r, source, out, false)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private transport detail")
	state := workerState(t, w, r)
	require.Equal(t, "failed", state.State)
	require.Equal(t, "failed", state.Assessment.Outcome)
	require.Error(t, w.Run(context.Background(), r, source, out, false))
}
func TestWorkerRejectsUnboundHostAndSource(t *testing.T) {
	for _, mode := range []string{"nil-journal", "bad-request", "runner", "profile", "policy", "agent", "allowlist", "pins", "source", "case-binding", "case-data", "case-target", "case-attempt", "operation-binding", "operation-data", "ttl", "executor", "scheduler", "existing-evidence", "output-file"} {
		t.Run(mode, func(t *testing.T) {
			w, r, source, out := workerFixture(t)
			called := false
			w.Execute = func(context.Context, trackerflow.Request, Profile, string, string) error { called = true; return nil }
			switch mode {
			case "nil-journal":
				w.Journal = nil
			case "bad-request":
				r.OperationID = ""
			case "runner":
				w.RunnerRevision = "wrong"
			case "profile":
				w.FlowProfile.ProfileDigest = strings.Repeat("f", 64)
			case "policy":
				w.FlowProfile.PolicyDigest = strings.Repeat("f", 64)
			case "agent":
				w.FlowProfile.Agent = "other"
			case "allowlist":
				w.FlowProfile.AllowedTargetIDs = nil
			case "pins":
				require.NoError(t, os.WriteFile(filepath.Join(w.Profile.FullsendDir, "config.yaml"), []byte("changed"), 0600))
			case "source":
				r.SourceSHA = strings.Repeat("f", 40)
			case "case-binding":
				lease, err := w.Journal.Claim(context.Background(), r.CaseID, "controller", time.Minute)
				require.NoError(t, err)
				record, err := w.Journal.Read(context.Background(), r.CaseID)
				require.NoError(t, err)
				_, err = w.Journal.Rebind(context.Background(), r.CaseID, lease, "new-manifest", record.Data)
				require.NoError(t, err)
			case "case-data":
				changeRecord(t, w.Journal, r.CaseID, func(record *journal.Record) error { record.Data = json.RawMessage(`[]`); return nil })
			case "case-target":
				changeRecord(t, w.Journal, r.CaseID, func(record *journal.Record) error {
					var state trackerflow.CaseState
					require.NoError(t, json.Unmarshal(record.Data, &state))
					delete(state.Targets, r.TargetID)
					record.Data, _ = json.Marshal(state)
					return nil
				})
			case "case-attempt":
				changeRecord(t, w.Journal, r.CaseID, func(record *journal.Record) error {
					var state trackerflow.CaseState
					require.NoError(t, json.Unmarshal(record.Data, &state))
					target := state.Targets[r.TargetID]
					target.Attempts = nil
					state.Targets[r.TargetID] = target
					record.Data, _ = json.Marshal(state)
					return nil
				})
			case "operation-binding":
				lease, err := w.Journal.Claim(context.Background(), r.OperationID, "controller", time.Minute)
				require.NoError(t, err)
				record, err := w.Journal.Read(context.Background(), r.OperationID)
				require.NoError(t, err)
				_, err = w.Journal.Rebind(context.Background(), r.OperationID, lease, "new-binding", record.Data)
				require.NoError(t, err)
			case "operation-data":
				changeRecord(t, w.Journal, r.OperationID, func(record *journal.Record) error { record.Data = json.RawMessage(`[]`); return nil })
			case "ttl":
				w.LeaseTTL = time.Nanosecond
			case "executor":
				w.Execute = nil
			case "scheduler":
				w.RunReceipt.RequestDigest = "wrong"
			case "existing-evidence":
				require.NoError(t, os.MkdirAll(out, 0700))
				writeAssessment(t, out, w.Profile, r, "affected")
			case "output-file":
				require.NoError(t, os.WriteFile(out, []byte("file"), 0600))
			}
			require.Error(t, w.Run(context.Background(), r, source, out, false))
			require.False(t, called)
		})
	}
}
func TestWorkerRevalidatesBeforeAcceptingEvidence(t *testing.T) {
	for _, mode := range []string{"parent-superseded", "source-dirty", "pins-changed", "bad-digest", "bad-outcome", "linked-receipt", "oversized-receipt"} {
		t.Run(mode, func(t *testing.T) {
			w, r, source, out := workerFixture(t)
			w.Execute = func(ctx context.Context, request trackerflow.Request, p Profile, src, output string) error {
				writeAssessment(t, output, p, request, "affected")
				switch mode {
				case "parent-superseded":
					record, err := w.Journal.Read(ctx, r.CaseID)
					require.NoError(t, err)
					lease, err := w.Journal.Claim(ctx, r.CaseID, "controller", time.Minute)
					require.NoError(t, err)
					_, err = w.Journal.Rebind(ctx, r.CaseID, lease, "superseded", record.Data)
					require.NoError(t, err)
				case "source-dirty":
					require.NoError(t, os.WriteFile(filepath.Join(src, "package.json"), []byte("changed"), 0600))
				case "pins-changed":
					require.NoError(t, os.WriteFile(filepath.Join(p.FullsendDir, "lock.yaml"), []byte("changed"), 0600))
				case "bad-digest":
					other := request
					other.SourceSHA = strings.Repeat("f", 40)
					writeAssessment(t, output, p, other, "affected")
				case "bad-outcome":
					writeAssessment(t, output, p, request, "done")
				case "linked-receipt":
					path := filepath.Join(output, p.AssessmentFile)
					data, err := os.ReadFile(path)
					require.NoError(t, err)
					target := filepath.Join(t.TempDir(), "receipt.json")
					require.NoError(t, os.WriteFile(target, data, 0600))
					require.NoError(t, os.Remove(path))
					require.NoError(t, os.Symlink(target, path))
				case "oversized-receipt":
					require.NoError(t, os.WriteFile(filepath.Join(output, p.AssessmentFile), []byte(strings.Repeat("x", (1<<20)+1)), 0600))
				}
				return nil
			}
			require.Error(t, w.Run(context.Background(), r, source, out, false))
			require.Equal(t, "running", workerState(t, w, r).State)
		})
	}
}

func TestWorkerFinalizerRunsOnlyAfterFreshBindings(t *testing.T) {
	for _, mode := range []string{"success", "rejected", "invalid-assessment", "changed-source"} {
		t.Run(mode, func(t *testing.T) {
			w, r, source, out := workerFixture(t)
			calls := 0
			w.Finalize = func(ctx context.Context, request trackerflow.Request, p Profile, src, output string) (trackerflow.Assessment, error) {
				calls++
				a := trackerflow.Assessment{RequestDigest: request.Digest(), Outcome: "uncertain", ReceiptRef: "validated-host"}
				switch mode {
				case "rejected":
					return a, errors.New("validation rejected")
				case "invalid-assessment":
					a.RequestDigest = "wrong"
				case "changed-source":
					require.NoError(t, os.WriteFile(filepath.Join(src, "untracked"), []byte("mutated"), 0600))
				}
				return a, nil
			}
			err := w.Run(context.Background(), r, source, out, false)
			if mode == "success" {
				require.NoError(t, err)
				state := workerState(t, w, r)
				require.Equal(t, "assessed", state.State)
				data, err := os.ReadFile(filepath.Join(out, w.Profile.AssessmentFile))
				require.NoError(t, err)
				require.Contains(t, string(data), "validated-host")
			} else {
				require.Error(t, err)
				require.Equal(t, "running", workerState(t, w, r).State)
			}
			require.Equal(t, 1, calls)
		})
	}
}

func TestWorkerRenewsLeaseDuringInference(t *testing.T) {
	w, r, source, out := workerFixture(t)
	w.LeaseTTL = time.Second
	w.Execute = func(ctx context.Context, request trackerflow.Request, p Profile, src, output string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
		writeAssessment(t, output, p, request, "uncertain")
		return nil
	}
	require.NoError(t, w.Run(context.Background(), r, source, out, false))
}

type workerHookBackend struct {
	journal.Backend
	hook func(context.Context, string, journal.Document) (string, error)
}

func (b workerHookBackend) CompareAndSwap(ctx context.Context, rev string, d journal.Document) (string, error) {
	return b.hook(ctx, rev, d)
}
func TestWorkerCheckpointConflictsNeverRepeatInference(t *testing.T) {
	for _, failures := range []int{1, 4} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			left := failures
			wrap := func(base journal.Backend) journal.Backend {
				return workerHookBackend{Backend: base, hook: func(ctx context.Context, rev string, d journal.Document) (string, error) {
					if record, ok := d.Records["dispatch-1"]; ok {
						var state trackerflow.WorkerState
						_ = json.Unmarshal(record.Data, &state)
						if state.State == "assessed" && left > 0 {
							left--
							return "", journal.ErrConflict
						}
					}
					return base.CompareAndSwap(ctx, rev, d)
				}}
			}
			w, r, source, out := workerFixture(t, wrap)
			calls := 0
			w.Execute = func(ctx context.Context, request trackerflow.Request, p Profile, src, output string) error {
				calls++
				writeAssessment(t, output, p, request, "uncertain")
				return nil
			}
			err := w.Run(context.Background(), r, source, out, false)
			if failures == 1 {
				require.NoError(t, err)
				require.Equal(t, "assessed", workerState(t, w, r).State)
			} else {
				require.ErrorIs(t, err, journal.ErrConflict)
				require.Equal(t, "running", workerState(t, w, r).State)
			}
			require.Equal(t, 1, calls)
		})
	}
}
func TestWorkerLosingRenewalCancelsInference(t *testing.T) {
	var originalExpiry time.Time
	wrap := func(base journal.Backend) journal.Backend {
		return workerHookBackend{Backend: base, hook: func(ctx context.Context, rev string, d journal.Document) (string, error) {
			if record, ok := d.Records["dispatch-1"]; ok && record.Lease.Owner == "worker-host" {
				var state trackerflow.WorkerState
				_ = json.Unmarshal(record.Data, &state)
				if state.State == "admitted" {
					originalExpiry = record.Lease.ExpiresAt
				}
				if state.State == "running" && record.Lease.ExpiresAt.After(originalExpiry) {
					return "", journal.ErrOwnership
				}
			}
			return base.CompareAndSwap(ctx, rev, d)
		}}
	}
	w, r, source, out := workerFixture(t, wrap)
	w.LeaseTTL = time.Second
	w.Execute = func(ctx context.Context, _ trackerflow.Request, _ Profile, _, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	require.ErrorIs(t, w.Run(context.Background(), r, source, out, false), journal.ErrOwnership)
	require.Equal(t, "running", workerState(t, w, r).State)
}
func TestTwoWorkersCannotRunSameAttempt(t *testing.T) {
	first, r, source, out := workerFixture(t)
	second := first
	second.Owner = "other-worker"
	var calls atomic.Int32
	execute := func(ctx context.Context, request trackerflow.Request, p Profile, src, output string) error {
		calls.Add(1)
		time.Sleep(60 * time.Millisecond)
		writeAssessment(t, output, p, request, "uncertain")
		return nil
	}
	first.Execute = execute
	second.Execute = execute
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for index, w := range []Worker{first, second} {
		idx, worker := index, w
		wg.Go(func() {
			<-start
			output := out
			if idx == 1 {
				output = filepath.Join(filepath.Dir(out), "other")
			}
			results <- worker.Run(context.Background(), r, source, output, false)
		})
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, int32(1), calls.Load())
}
