package trackerworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
)

type Finalizer func(context.Context, trackerflow.Request, Profile, string, string) (trackerflow.Assessment, error)

type Executor func(context.Context, trackerflow.Request, Profile, string, string) error

type Worker struct {
	Journal        *journal.Engine
	Profile        Profile
	FlowProfile    trackerflow.Profile
	Owner          string
	RunnerRevision string
	RunReceipt     trackerflow.RunReceipt
	Execute        Executor
	Finalize       Finalizer
	LeaseTTL       time.Duration
	CheckIssue     func(context.Context, trackerflow.Request) error
}

func (w Worker) Validate(ctx context.Context, r trackerflow.Request) error {
	if e := r.Validate(); e != nil {
		return e
	}
	p := w.Profile
	f := w.FlowProfile
	if w.RunnerRevision != p.RunnerRevision || r.ProfileDigest != p.Digest() || f.ProfileDigest != r.ProfileDigest || f.PolicyDigest != r.PolicyDigest || f.Agent != r.Agent || p.Agent != r.Agent {
		return errors.New("worker protected profile binding mismatch")
	}
	allowed := false
	for _, id := range f.AllowedTargetIDs {
		if id == r.TargetID {
			allowed = true
		}
	}
	if !allowed {
		return trackerflow.ErrAuthorization
	}
	if e := p.CheckPins(); e != nil {
		return e
	}
	parent, e := w.Journal.Read(ctx, r.CaseID)
	if e != nil {
		return e
	}
	if parent.Binding != r.ManifestDigest {
		return journal.ErrBinding
	}
	var state trackerflow.CaseState
	if e := Decode(parent.Data, &state); e != nil {
		return e
	}
	target, ok := state.Targets[r.TargetID]
	if !ok || target.Tracker == nil || target.Tracker.Key != r.JiraKey || target.Target.SourceSHA != r.SourceSHA || target.Target.Repository != r.Repository || target.Target.Branch != r.Branch {
		return journal.ErrBinding
	}
	found := false
	for _, a := range target.Attempts {
		if a.Request != r {
			continue
		}
		// A retained request is not permission to replay a terminal attempt.
		// The controller may already have admitted a newer attempt for this target.
		if found {
			return journal.ErrBinding
		}
		switch a.State {
		case "accepted", "running", "ambiguous":
		default:
			return journal.ErrBinding
		}
		if a.Receipt != nil && a.Receipt.RunID != "" {
			if a.Receipt.OperationID != r.OperationID || a.Receipt.RequestDigest != r.Digest() || w.RunReceipt.OperationID != r.OperationID || w.RunReceipt.RequestDigest != r.Digest() || a.Receipt.RunID != w.RunReceipt.RunID {
				return journal.ErrBinding
			}
		}
		found = true
	}
	if !found {
		return journal.ErrBinding
	}
	record, e := w.Journal.Read(ctx, r.OperationID)
	if e != nil {
		return e
	}
	var admitted trackerflow.WorkerState
	if record.Binding != r.Digest() || Decode(record.Data, &admitted) != nil || admitted.Request != r {
		return journal.ErrBinding
	}
	if f.Jira.IssueControls != nil {
		if w.CheckIssue == nil {
			return errors.New("live Jira admission required")
		}
		if err := w.CheckIssue(ctx, r); err != nil {
			return err
		}
	}
	return nil
}
func (w Worker) Run(ctx context.Context, r trackerflow.Request, sourceDir, outputDir string, finalizeOnly bool) error {
	if w.Journal == nil {
		return errors.New("worker journal required")
	}
	if e := w.Validate(ctx, r); e != nil {
		return e
	}
	if e := VerifySource(ctx, sourceDir, r); e != nil {
		return e
	}
	record, e := w.Journal.Read(ctx, r.OperationID)
	if e != nil {
		return e
	}
	var state trackerflow.WorkerState
	if Decode(record.Data, &state) != nil {
		return journal.ErrIntegrity
	}
	if (!finalizeOnly && state.State != "admitted") || (finalizeOnly && state.State != "running") {
		return errors.New("worker attempt requires reconciliation, not repeated inference")
	}
	ttl := w.LeaseTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	if ttl < time.Second {
		return errors.New("worker lease lifetime too short")
	}
	lease, e := w.Journal.Claim(ctx, r.OperationID, w.Owner, ttl)
	if e != nil {
		return e
	}
	defer func() { _ = w.Journal.Release(context.WithoutCancel(ctx), r.OperationID, lease) }()
	// The attempt may have advanced while this process waited for ownership.
	// Re-read under the acquired lease rather than acting on the earlier snapshot.
	record, e = w.Journal.Read(ctx, r.OperationID)
	if e != nil {
		return e
	}
	if record.Binding != r.Digest() || Decode(record.Data, &state) != nil || state.Request != r {
		return journal.ErrBinding
	}
	if (!finalizeOnly && state.State != "admitted") || (finalizeOnly && state.State != "running") {
		return errors.New("worker attempt requires reconciliation, not repeated inference")
	}

	save := func(next trackerflow.WorkerState) error {
		data, _ := json.Marshal(next)
		// Repeat only a local checkpoint after unrelated document conflicts.
		// The engine rechecks ownership; external calls are outside this loop.
		for i := 0; i < 4; i++ {
			_, err := w.Journal.Update(ctx, r.OperationID, lease, func(current *journal.Record) error {
				var old trackerflow.WorkerState
				if Decode(current.Data, &old) != nil || old.Request != r {
					return journal.ErrBinding
				}
				// The parent admission is a predicate of the same document CAS.
				// A parent change during these reads invalidates the write revision.
				if err := w.Validate(ctx, r); err != nil {
					return err
				}

				if old.State == "assessed" || old.State == "failed" {
					if reflect.DeepEqual(old, next) {
						return nil
					}
					return journal.ErrTransition
				}
				if (next.State == "running" && old.State != "admitted") || ((next.State == "assessed" || next.State == "failed") && old.State != "running") {
					return journal.ErrTransition
				}
				current.Data = data
				return nil
			})
			if !errors.Is(err, journal.ErrConflict) {
				return err
			}
		}
		return journal.ErrConflict
	}
	if e := os.MkdirAll(outputDir, 0o700); e != nil {
		return errors.New("worker output unavailable")
	}
	assessmentPath := filepath.Join(outputDir, w.Profile.AssessmentFile)
	if !finalizeOnly {
		if _, e := os.Lstat(assessmentPath); !errors.Is(e, os.ErrNotExist) {
			return errors.New("existing worker evidence requires reconciliation")
		}
		if w.Execute == nil {
			return errors.New("worker executor required")
		}
		if w.RunReceipt.OperationID != r.OperationID || w.RunReceipt.RequestDigest != r.Digest() || w.RunReceipt.RunID == "" || w.RunReceipt.RunURL == "" {
			return errors.New("worker scheduling receipt required")
		}
		state.State = "running"
		state.RunReceipt = &w.RunReceipt
		if e := save(state); e != nil {
			return e
		}
		runCtx, cancel := context.WithCancel(ctx)
		renewDone := make(chan error, 1)
		go func() {
			ticker := time.NewTicker(ttl / 3)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					renewDone <- nil
					return
				case <-ticker.C:
					if _, err := w.Journal.Renew(runCtx, r.OperationID, lease, ttl); err != nil {
						renewDone <- err
						cancel()
						return
					}
				}
			}
		}()
		runErr := w.Execute(runCtx, r, w.Profile, sourceDir, outputDir)
		cancel()
		renewErr := <-renewDone
		if renewErr != nil {
			return renewErr
		}
		if runErr != nil {
			state.State = "failed"
			state.Assessment = &trackerflow.Assessment{RequestDigest: r.Digest(), Outcome: "failed", ReceiptRef: "worker-failure:" + r.OperationID}
			if e := save(state); e != nil {
				return e
			}
			return errors.New("worker execution failed; investigation retained")
		}
	}
	if e := w.Validate(ctx, r); e != nil {
		return e
	}
	if e := VerifySource(ctx, sourceDir, r); e != nil {
		return e
	}
	if w.Finalize != nil {
		assessment, err := w.Finalize(ctx, r, w.Profile, sourceDir, outputDir)
		if err != nil {
			return err
		}
		if err := assessment.Validate(r); err != nil {
			return err
		}
		if err := w.Validate(ctx, r); err != nil {
			return err
		}
		if err := VerifySource(ctx, sourceDir, r); err != nil {
			return err
		}
		encoded, err := json.Marshal(assessment)
		if err != nil {
			return err
		}
		temporary, err := os.CreateTemp(outputDir, ".assessment-*")
		if err != nil {
			return errors.New("host receipt checkpoint unavailable")
		}
		name := temporary.Name()
		defer os.Remove(name)
		if _, err = temporary.Write(encoded); err != nil {
			_ = temporary.Close()
			return err
		}
		if err = temporary.Close(); err != nil {
			return err
		}
		if err = os.Rename(name, assessmentPath); err != nil {
			return err
		}
	}
	info, e := os.Lstat(assessmentPath)
	if e != nil || !info.Mode().IsRegular() {
		return errors.New("validated host assessment receipt required")
	}
	f, e := os.Open(assessmentPath)
	if e != nil {
		return errors.New("validated host assessment receipt required")
	}
	raw, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	_ = f.Close()
	if e != nil {
		return errors.New("assessment receipt unavailable")
	}
	var assessment trackerflow.Assessment
	if e := Decode(raw, &assessment); e != nil {
		return e
	}
	if e := assessment.Validate(r); e != nil {
		return e
	}
	state.State = "assessed"
	state.Assessment = &assessment
	return save(state)
}
