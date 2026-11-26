package trackerflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/stretchr/testify/require"
)

type memoryBackend struct {
	mu         sync.Mutex
	d          journal.Document
	rev        int
	failFlight bool
	conflicts  int
}

func (b *memoryBackend) Load(context.Context) (journal.Document, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw, _ := json.Marshal(b.d)
	var d journal.Document
	_ = json.Unmarshal(raw, &d)
	return d, fmt.Sprint(b.rev), nil
}
func (b *memoryBackend) CompareAndSwap(_ context.Context, r string, d journal.Document) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conflicts > 0 {
		b.conflicts--
		b.rev++
		return "", journal.ErrConflict
	}
	if b.failFlight {
		for _, record := range d.Records {
			for _, effect := range record.Effects {
				if effect.Kind == "dispatch" && effect.Status == "in_flight" {
					return "", errors.New("simulated controller stop")
				}
			}
		}
	}
	if r != fmt.Sprint(b.rev) {
		return "", journal.ErrConflict
	}
	raw, _ := json.Marshal(d)
	_ = json.Unmarshal(raw, &b.d)
	b.rev++
	return fmt.Sprint(b.rev), nil
}

type allow struct{ deny string }

func (a *allow) Authorize(_ context.Context, _ Manifest, _ Target, action string) error {
	if a.deny == action {
		return ErrAuthorization
	}
	return nil
}

type fakeTracker struct {
	created             int
	ambiguous           bool
	find                []TrackerReceipt
	verifyErr           error
	assessmentCreated   int
	assessmentAmbiguous bool
	assessmentHidden    bool
	assessmentReceipts  map[string]AssessmentPublicationReceipt
}

func (f *fakeTracker) Find(context.Context, Manifest, Target) ([]TrackerReceipt, error) {
	return f.find, nil
}
func (f *fakeTracker) Create(_ context.Context, m Manifest, t Target) (TrackerReceipt, error) {
	f.created++
	if f.ambiguous {
		return TrackerReceipt{}, ErrAmbiguous
	}
	return TrackerReceipt{Key: fmt.Sprintf("PROJ-%d", f.created), ID: fmt.Sprint(f.created), Binding: Hash(trackerScope(m, t))}, nil
}
func (f *fakeTracker) Verify(context.Context, Manifest, Target, TrackerReceipt) error {
	return f.verifyErr
}

type fakeScheduler struct {
	submitted      int
	ambiguous      bool
	result         string
	reconcileError error
	requests       []Request
}

func (f *fakeScheduler) Submit(_ context.Context, r Request) (RunReceipt, error) {
	f.submitted++
	f.requests = append(f.requests, r)
	if f.ambiguous {
		return RunReceipt{}, ErrAmbiguous
	}
	return RunReceipt{OperationID: r.OperationID, RequestDigest: r.Digest(), RunID: fmt.Sprint(f.submitted), RunURL: "https://control.example/pipelines/1", State: "accepted"}, nil
}
func (f *fakeScheduler) Reconcile(_ context.Context, r Request, known *RunReceipt) (RunReceipt, *Assessment, error) {
	if f.reconcileError != nil {
		return RunReceipt{}, nil, f.reconcileError
	}
	if known == nil {
		return RunReceipt{}, nil, ErrAmbiguous
	}
	v := *known
	if f.result != "" {
		v.State = f.result
	}
	return v, nil, nil
}
func manifest() Manifest {
	m := Manifest{SchemaVersion: 1, CaseID: "case-1", Revision: "mapping-1", Public: true, Advisory: "CVE-2021-23337", PolicyDigest: strings.Repeat("a", 64), ProfileDigest: strings.Repeat("b", 64), Agent: "triage", Jira: Destination{Project: "PROJ", IssueTypeID: "10001", AssigneeAccountID: "account-1"}, Limits: Limits{MaxTargets: 10, MaxConcurrent: 2, MaxAttempts: 2}}
	for _, branch := range []string{"main", "release/1"} {
		m.Targets = append(m.Targets, Target{Repository: "https://github.com/example/repo", Branch: branch, SourceSHA: strings.Repeat("c", 40), Component: "package.json", Product: "demo", Release: branch, Stream: branch, Owner: "security"})
	}
	return m
}
func setup() (*Controller, *fakeTracker, *fakeScheduler) {
	b := &memoryBackend{d: journal.Empty()}
	j := journal.New(b, nil)
	t := &fakeTracker{}
	s := &fakeScheduler{}
	return &Controller{Journal: j, Tracker: t, Scheduler: s, Authorizer: &allow{}, Owner: "controller-1"}, t, s
}
func TestCycleTracksTwoBranchesAndCollectsBoundWorkerEvidence(t *testing.T) {
	c, tr, s := setup()
	m := manifest()
	report, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.False(t, report.Complete)
	require.Equal(t, 2, tr.created)
	require.Equal(t, 2, s.submitted)
	for _, req := range s.requests {
		known := scheduledReceipt(t, c, req)
		lease, e := c.Journal.Claim(context.Background(), req.OperationID, "worker", time.Minute)
		require.NoError(t, e)
		_, e = c.Journal.Update(context.Background(), req.OperationID, lease, func(r *journal.Record) error {
			var state WorkerState
			_ = json.Unmarshal(r.Data, &state)
			state.State = "assessed"
			state.RunReceipt = known
			state.Assessment = &Assessment{RequestDigest: req.Digest(), Outcome: "not_affected", ReceiptRef: "artifact:sha256:receipt"}
			r.Data = marshal(state)
			return nil
		})
		require.NoError(t, e)
	}
	s.result = "completed"
	report, err = c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.True(t, report.Complete)
	require.Equal(t, 2, report.Assessed)
	require.Equal(t, 2, tr.created)
	require.Equal(t, 2, s.submitted)
}
func TestAmbiguousTrackerNeverRetriesEmptySearch(t *testing.T) {
	c, tr, s := setup()
	tr.ambiguous = true
	m := manifest()
	m.Targets = m.Targets[:1]
	for range 3 {
		r, e := c.Cycle(context.Background(), m)
		require.NoError(t, e)
		require.False(t, r.Complete)
	}
	require.Equal(t, 1, tr.created)
	require.Zero(t, s.submitted)
}
func TestAmbiguousDispatchNeverResubmits(t *testing.T) {
	c, _, s := setup()
	s.ambiguous = true
	m := manifest()
	m.Targets = m.Targets[:1]
	for range 3 {
		_, e := c.Cycle(context.Background(), m)
		require.NoError(t, e)
	}
	require.Equal(t, 1, s.submitted)
}
func TestConcurrencyIncludesUnterminatedSupersededAttempt(t *testing.T) {
	c, tr, s := setup()
	m := manifest()
	m.Limits.MaxConcurrent = 1
	_, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.Equal(t, 1, s.submitted)
	require.Equal(t, 2, tr.created)
	m.Targets[0].SourceSHA = strings.Repeat("d", 40)
	m.Revision = "mapping-2"
	r, e := c.Cycle(context.Background(), m)
	require.NoError(t, e)
	require.False(t, r.Complete)
	require.Equal(t, 1, s.submitted)
	require.Equal(t, 2, tr.created)
}
func TestFailureRetriesBoundedAndUncertainStaysHumanPending(t *testing.T) {
	c, _, s := setup()
	m := manifest()
	m.Targets = m.Targets[:1]
	s.result = "failed"
	for range 4 {
		r, e := c.Cycle(context.Background(), m)
		require.NoError(t, e)
		require.False(t, r.Complete)
	}
	require.Equal(t, 2, s.submitted)
	c, _, s = setup()
	_, e := c.Cycle(context.Background(), m)
	require.NoError(t, e)
	req := s.requests[0]
	known := scheduledReceipt(t, c, req)
	lease, e := c.Journal.Claim(context.Background(), req.OperationID, "worker", time.Minute)
	require.NoError(t, e)
	_, e = c.Journal.Update(context.Background(), req.OperationID, lease, func(r *journal.Record) error {
		r.Data = marshal(WorkerState{Request: req, State: "assessed", RunReceipt: known, Assessment: &Assessment{RequestDigest: req.Digest(), Outcome: "uncertain", ReceiptRef: "receipt"}})
		return nil
	})
	require.NoError(t, e)
	s.result = "completed"
	r, e := c.Cycle(context.Background(), m)
	require.NoError(t, e)
	require.False(t, r.Complete)
	require.Equal(t, "uncertain", r.Targets[req.TargetID].Status)
	require.Equal(t, 1, s.submitted)
}
func TestAuthorizationAndBlockedTargetsRemainAccounted(t *testing.T) {
	c, tr, s := setup()
	m := manifest()
	m.Targets[0].BlockedReason = "unmapped"
	m.Targets[0].SourceSHA = ""
	c.Authorizer = &allow{deny: "dispatch"}
	r, e := c.Cycle(context.Background(), m)
	require.NoError(t, e)
	require.False(t, r.Complete)
	require.Equal(t, 2, r.Pending)
	require.Equal(t, 1, tr.created)
	require.Zero(t, s.submitted)
}
func TestRejectInvalidAndMismatchedEvidence(t *testing.T) {
	c, _, s := setup()
	m := manifest()
	m.Public = false
	_, e := c.Cycle(context.Background(), m)
	require.Error(t, e)
	m = manifest()
	_, e = c.Cycle(context.Background(), m)
	require.NoError(t, e)
	req := s.requests[0]
	known := scheduledReceipt(t, c, req)
	lease, e := c.Journal.Claim(context.Background(), req.OperationID, "worker", time.Minute)
	require.NoError(t, e)
	_, e = c.Journal.Update(context.Background(), req.OperationID, lease, func(r *journal.Record) error {
		r.Data = marshal(WorkerState{Request: req, State: "assessed", RunReceipt: known, Assessment: &Assessment{RequestDigest: "wrong", Outcome: "affected", ReceiptRef: "receipt"}})
		return nil
	})
	require.NoError(t, e)
	_, e = c.Cycle(context.Background(), m)
	require.Error(t, e)
}
func TestConfirmedTrackerReceiptVerifiedOnRetry(t *testing.T) {
	c, tr, _ := setup()
	m := manifest()
	_, e := c.Cycle(context.Background(), m)
	require.NoError(t, e)
	tr.verifyErr = errors.New("scope changed")
	_, e = c.Cycle(context.Background(), m)
	require.Error(t, e)
	require.Equal(t, 2, tr.created)
}

func TestCrashBeforeDispatchAdmissionResumesExactIntendedAttempt(t *testing.T) {
	b := &memoryBackend{d: journal.Empty(), failFlight: true}
	engine := journal.New(b, nil)
	tr := &fakeTracker{}
	scheduler := &fakeScheduler{}
	c := Controller{Journal: engine, Tracker: tr, Scheduler: scheduler, Authorizer: &allow{}, Owner: "owner"}
	m := manifest()
	m.Targets = m.Targets[:1]
	_, err := c.Cycle(context.Background(), m)
	require.Error(t, err)
	require.Zero(t, scheduler.submitted)
	b.failFlight = false
	report, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.False(t, report.Complete)
	require.Equal(t, 1, scheduler.submitted)
	require.Equal(t, 1, tr.created)
	record, err := engine.Read(context.Background(), m.CaseID)
	require.NoError(t, err)
	require.Equal(t, uint64(1), record.Counters["attempts-"+TargetID(m.CaseID, m.Targets[0])])
}
func TestSaveReloadsOwnedCaseAfterUnrelatedRecordConflict(t *testing.T) {
	b := &memoryBackend{d: journal.Empty()}
	engine := journal.New(b, nil)
	m := manifest()
	state := newState(m)
	_, err := engine.Admit(context.Background(), m.CaseID, m.Digest(), marshal(state))
	require.NoError(t, err)
	lease, err := engine.Claim(context.Background(), m.CaseID, "owner", time.Minute)
	require.NoError(t, err)
	b.conflicts = 1
	first := state.Required[0]
	target := state.Targets[first]
	target.Status = "blocked"
	state.Targets[first] = target
	c := Controller{Journal: engine}
	require.NoError(t, c.save(context.Background(), m, lease, state, nil))
	require.Zero(t, b.conflicts)
	wrong := lease
	wrong.Generation++
	require.ErrorIs(t, c.save(context.Background(), m, wrong, state, nil), journal.ErrOwnership)
}

// Interleave another controller after admission returned its snapshot but before
// the tested controller acquires ownership. Reads after Claim must retain history.
type interleavedBackend struct {
	journal.Backend
	loads       int
	beforeClaim func()
}

func (b *interleavedBackend) Load(ctx context.Context) (journal.Document, string, error) {
	b.loads++
	if b.loads == 2 {
		b.beforeClaim()
	}
	return b.Backend.Load(ctx)
}
func TestClaimReloadRetainsInterleavedControllerHistory(t *testing.T) {
	ctx := context.Background()
	m := manifest()
	base := &memoryBackend{d: journal.Empty()}
	other := journal.New(base, nil)
	_, err := other.Admit(ctx, m.CaseID, m.Digest(), marshal(newState(m)))
	require.NoError(t, err)
	interleaved := &interleavedBackend{Backend: base}
	interleaved.beforeClaim = func() {
		lease, e := other.Claim(ctx, m.CaseID, "other-controller", time.Minute)
		require.NoError(t, e)
		_, e = other.Update(ctx, m.CaseID, lease, func(r *journal.Record) error {
			state, e := readState(r)
			if e != nil {
				return e
			}
			state.Targets["historical-target"] = TargetState{Target: m.Targets[0], Status: "superseded"}
			r.Data = marshal(state)
			return nil
		})
		require.NoError(t, e)
		require.NoError(t, other.Release(ctx, m.CaseID, lease))
	}
	c := Controller{Journal: journal.New(interleaved, nil), Tracker: &fakeTracker{}, Scheduler: &fakeScheduler{}, Authorizer: &allow{}, Owner: "current-controller"}
	report, err := c.Cycle(ctx, m)
	require.NoError(t, err)
	require.Contains(t, report.Targets, "historical-target")
	record, err := other.Read(ctx, m.CaseID)
	require.NoError(t, err)
	state, err := readState(record)
	require.NoError(t, err)
	require.Contains(t, state.Targets, "historical-target")
}
func TestSupersededIntendedDispatchCancelsWithoutReservingConcurrency(t *testing.T) {
	ctx := context.Background()
	m := manifest()
	m.Targets = m.Targets[:1]
	m.Limits.MaxConcurrent = 1
	backend := &memoryBackend{d: journal.Empty(), failFlight: true}
	engine := journal.New(backend, nil)
	scheduler := &fakeScheduler{}
	c := Controller{Journal: engine, Tracker: &fakeTracker{}, Scheduler: scheduler, Authorizer: &allow{}, Owner: "controller"}
	_, err := c.Cycle(ctx, m)
	require.Error(t, err)
	require.Zero(t, scheduler.submitted)
	old, err := engine.Read(ctx, m.CaseID)
	require.NoError(t, err)
	oldState, err := readState(old)
	require.NoError(t, err)
	id := TargetID(m.CaseID, m.Targets[0])
	oldRequest := oldState.Targets[id].Attempts[0].Request
	backend.failFlight = false
	m.Revision = "mapping-2"
	m.Targets[0].SourceSHA = strings.Repeat("d", 40)
	report, err := c.Cycle(ctx, m)
	require.NoError(t, err)
	require.Equal(t, 1, scheduler.submitted)
	require.Equal(t, "cancelled", report.Targets[id].Attempts[0].State)
	require.Equal(t, "accepted", report.Targets[id].Attempts[1].State)
	child, err := engine.Read(ctx, oldRequest.OperationID)
	require.NoError(t, err)
	var worker WorkerState
	require.NoError(t, DecodeStrict(child.Data, &worker))
	require.Equal(t, "cancelled", worker.State)
	record, err := engine.Read(ctx, m.CaseID)
	require.NoError(t, err)
	effect := record.Effects[oldRequest.OperationID]
	require.Equal(t, "confirmed", effect.Status)
	var cancellation CancellationReceipt
	require.NoError(t, DecodeStrict(effect.Receipt, &cancellation))
	require.Equal(t, "cancelled_before_submission", cancellation.Outcome)
	require.Equal(t, uint64(2), record.Counters["attempts-"+id], "supersession must not reset consumed attempt bounds")
}
func TestSupersededAmbiguousDispatchStillReservesConcurrency(t *testing.T) {
	c, _, scheduler := setup()
	m := manifest()
	m.Targets = m.Targets[:1]
	m.Limits.MaxConcurrent = 1
	scheduler.ambiguous = true
	_, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.Equal(t, 1, scheduler.submitted)
	m.Revision = "mapping-2"
	m.Targets[0].SourceSHA = strings.Repeat("d", 40)
	report, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.Equal(t, 1, scheduler.submitted)
	target := report.Targets[TargetID(m.CaseID, m.Targets[0])]
	require.Equal(t, "case_concurrency_bound", target.Blocker)
	require.Equal(t, "ambiguous", target.Attempts[0].State)
}

func (f *fakeTracker) FindAssessment(_ context.Context, m Manifest, t Target, r Request, a Assessment) ([]AssessmentPublicationReceipt, error) {
	if f.assessmentHidden {
		return nil, nil
	}
	receipt, ok := f.assessmentReceipts[Hash(assessmentBinding(m, t, r, a))]
	if !ok {
		return nil, nil
	}
	return []AssessmentPublicationReceipt{receipt}, nil
}
func (f *fakeTracker) PublishAssessment(_ context.Context, m Manifest, t Target, r Request, a Assessment) (AssessmentPublicationReceipt, error) {
	f.assessmentCreated++
	binding := Hash(assessmentBinding(m, t, r, a))
	receipt := AssessmentPublicationReceipt{JiraKey: r.JiraKey, CommentID: fmt.Sprint(f.assessmentCreated), Binding: binding}
	if f.assessmentReceipts == nil {
		f.assessmentReceipts = map[string]AssessmentPublicationReceipt{}
	}
	f.assessmentReceipts[binding] = receipt
	if f.assessmentAmbiguous {
		return AssessmentPublicationReceipt{}, ErrAmbiguous
	}
	return receipt, nil
}
func (f *fakeTracker) VerifyAssessment(_ context.Context, m Manifest, t Target, r Request, a Assessment, receipt AssessmentPublicationReceipt) error {
	if f.verifyErr != nil {
		return f.verifyErr
	}
	expected := f.assessmentReceipts[Hash(assessmentBinding(m, t, r, a))]
	if receipt != expected {
		return errors.New("assessment receipt mismatch")
	}
	return nil
}
func completeWorker(t *testing.T, c *Controller, request Request, outcome string) {
	t.Helper()
	if scheduler, ok := c.Scheduler.(*fakeScheduler); ok {
		scheduler.result = "completed"
	}
	known := scheduledReceipt(t, c, request)
	lease, err := c.Journal.Claim(context.Background(), request.OperationID, "worker", time.Minute)
	require.NoError(t, err)
	_, err = c.Journal.Update(context.Background(), request.OperationID, lease, func(record *journal.Record) error {
		record.Data = marshal(WorkerState{Request: request, State: "assessed", RunReceipt: known, Assessment: &Assessment{RequestDigest: request.Digest(), Outcome: outcome, ReceiptRef: "sha256:validated-receipt"}})
		return nil
	})
	require.NoError(t, err)
}

type noAssessmentPublisher struct{ Tracker }

func TestCaseRequiresConfirmedAssessmentPublication(t *testing.T) {
	c, tracker, scheduler := setup()
	m := manifest()
	m.Targets = m.Targets[:1]
	_, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	completeWorker(t, c, scheduler.requests[0], "not_affected")
	c.Tracker = noAssessmentPublisher{tracker}
	report, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.False(t, report.Complete)
	require.Equal(t, "assessment_publisher_unavailable", report.Targets[scheduler.requests[0].TargetID].Blocker)
	c.Tracker = tracker
	report, err = c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.True(t, report.Complete)
	require.Equal(t, 1, tracker.assessmentCreated)
	report, err = c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.True(t, report.Complete)
	require.Equal(t, 1, tracker.assessmentCreated)
}
func TestAmbiguousAssessmentPublicationHoldsEmptySearchThenReconciles(t *testing.T) {
	c, tracker, scheduler := setup()
	m := manifest()
	m.Targets = m.Targets[:1]
	_, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	request := scheduler.requests[0]
	completeWorker(t, c, request, "affected")
	tracker.assessmentAmbiguous = true
	tracker.assessmentHidden = true
	for range 3 {
		report, e := c.Cycle(context.Background(), m)
		require.NoError(t, e)
		require.False(t, report.Complete)
		require.Equal(t, "assessment_publication_unresolved", report.Targets[request.TargetID].Blocker)
	}
	require.Equal(t, 1, tracker.assessmentCreated)
	require.Equal(t, 1, scheduler.submitted, "publication retry must never rerun inference")
	tracker.assessmentHidden = false
	report, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.True(t, report.Complete)
	require.Equal(t, 1, tracker.assessmentCreated)
	record, err := c.Journal.Read(context.Background(), m.CaseID)
	require.NoError(t, err)
	effect := record.Effects["assessment-"+request.OperationID]
	require.Equal(t, "confirmed", effect.Status)
}

func scheduledReceipt(t *testing.T, c *Controller, r Request) *RunReceipt {
	t.Helper()
	record, err := c.Journal.Read(context.Background(), r.CaseID)
	require.NoError(t, err)
	state, err := readState(record)
	require.NoError(t, err)
	for _, attempt := range state.Targets[r.TargetID].Attempts {
		if attempt.Request == r {
			require.NotNil(t, attempt.Receipt)
			return attempt.Receipt
		}
	}
	t.Fatal("missing scheduled attempt")
	return nil
}
func TestCollectRejectsWorkerFromDifferentAcceptedPipeline(t *testing.T) {
	for _, state := range []string{"running", "assessed"} {
		changes := []string{"run_id", "run_url"}
		if state == "assessed" {
			changes = append(changes, "missing_receipt")
		}
		for _, changed := range changes {
			t.Run(state+"_"+changed, func(t *testing.T) {
				c, _, _ := setup()
				r := request()
				known := RunReceipt{OperationID: r.OperationID, RequestDigest: r.Digest(), RunID: "scheduled-1", RunURL: "https://control.example/pipelines/1", State: "accepted"}
				candidate := known
				candidate.State = "running"
				worker := WorkerState{Request: r, State: state, RunReceipt: &candidate}
				switch changed {
				case "run_id":
					candidate.RunID = "replayed-2"
				case "run_url":
					candidate.RunURL = "https://other.example/pipelines/1"
				case "missing_receipt":
					worker.RunReceipt = nil
				}
				if state == "assessed" {
					worker.Assessment = &Assessment{RequestDigest: r.Digest(), Outcome: "affected", ReceiptRef: "sha256:validated"}
				}
				_, err := c.Journal.Admit(context.Background(), r.OperationID, r.Digest(), marshal(worker))
				require.NoError(t, err)
				attempt := Attempt{Request: r, Receipt: &known, State: "accepted"}
				require.ErrorIs(t, c.collect(context.Background(), &attempt), journal.ErrBinding)
				require.Equal(t, known, *attempt.Receipt)
				require.Nil(t, attempt.Assessment)
				require.Equal(t, "accepted", attempt.State)
			})
		}
	}
}
func TestCollectRetainsKnownPipelineIdentityAcrossStateUpdates(t *testing.T) {
	c, _, scheduler := setup()
	scheduler.result = "completed"
	r := request()
	known := RunReceipt{OperationID: r.OperationID, RequestDigest: r.Digest(), RunID: "scheduled-1", RunURL: "https://control.example/pipelines/1", State: "accepted"}
	running := known
	running.State = "running"
	worker := WorkerState{Request: r, State: "assessed", RunReceipt: &running, Assessment: &Assessment{RequestDigest: r.Digest(), Outcome: "not_affected", ReceiptRef: "sha256:validated"}}
	_, err := c.Journal.Admit(context.Background(), r.OperationID, r.Digest(), marshal(worker))
	require.NoError(t, err)
	attempt := Attempt{Request: r, Receipt: &known, State: "accepted"}
	require.NoError(t, c.collect(context.Background(), &attempt))
	require.Equal(t, known.RunID, attempt.Receipt.RunID)
	require.Equal(t, "assessed", attempt.State)
	require.NotNil(t, attempt.Assessment)
}

func TestValidatedWorkerEvidenceKeepsRunningPipelineInConcurrencyBound(t *testing.T) {
	c, tracker, scheduler := setup()
	m := manifest()
	m.Limits.MaxConcurrent = 1
	first, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.False(t, first.Complete)
	require.Equal(t, 1, scheduler.submitted)
	request := scheduler.requests[0]
	completeWorker(t, c, request, "not_affected")
	scheduler.result = "running"
	report, err := c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.False(t, report.Complete)
	require.Equal(t, 1, scheduler.submitted, "validated evidence cannot release a still-running pipeline's slot")
	require.Zero(t, tracker.assessmentCreated, "assessment publication waits for scheduler termination")
	attempt := report.Targets[request.TargetID].Attempts[0]
	require.Equal(t, "running", attempt.State)
	require.NotNil(t, attempt.Assessment, "validated evidence is retained while CI remains running")
	record, err := c.Journal.Read(context.Background(), m.CaseID)
	require.NoError(t, err)
	state, err := readState(record)
	require.NoError(t, err)
	require.Equal(t, 1, active(state))
	for id, target := range report.Targets {
		if id != request.TargetID {
			require.Equal(t, "case_concurrency_bound", target.Blocker)
		}
	}
	// Reconcile earlier journal checkpoints that prematurely marked retained
	// worker evidence terminal while the same CI pipeline remained running.
	legacyLease, e := c.Journal.Claim(context.Background(), m.CaseID, "legacy-checkpoint", time.Minute)
	require.NoError(t, e)
	_, e = c.Journal.Update(context.Background(), m.CaseID, legacyLease, func(r *journal.Record) error {
		saved, e := readState(r)
		if e != nil {
			return e
		}
		target := saved.Targets[request.TargetID]
		target.Attempts[0].State = "assessed"
		saved.Targets[request.TargetID] = target
		r.Data = marshal(saved)
		return nil
	})
	require.NoError(t, e)
	require.NoError(t, c.Journal.Release(context.Background(), m.CaseID, legacyLease))
	report, err = c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.Equal(t, "running", report.Targets[request.TargetID].Attempts[0].State)
	require.Equal(t, 1, scheduler.submitted)
	scheduler.result = "completed"
	report, err = c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.False(t, report.Complete)
	require.Equal(t, 2, scheduler.submitted)
	require.Equal(t, 1, tracker.assessmentCreated)
	completeWorker(t, c, scheduler.requests[1], "not_affected")
	report, err = c.Cycle(context.Background(), m)
	require.NoError(t, err)
	require.True(t, report.Complete)
	require.Equal(t, 2, tracker.assessmentCreated)
}
func TestCollectRetainsValidatedEvidenceAfterConfirmedFailedPipeline(t *testing.T) {
	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			c, _, scheduler := setup()
			scheduler.result = terminalState
			request := request()
			receipt := RunReceipt{OperationID: request.OperationID, RequestDigest: request.Digest(), RunID: "pipeline-1", RunURL: "https://control.example/pipelines/1", State: "running"}
			assessment := Assessment{RequestDigest: request.Digest(), Outcome: "uncertain", ReceiptRef: "sha256:validated"}
			worker := WorkerState{Request: request, State: "assessed", RunReceipt: &receipt, Assessment: &assessment}
			_, err := c.Journal.Admit(context.Background(), request.OperationID, request.Digest(), marshal(worker))
			require.NoError(t, err)
			attempt := Attempt{Request: request, Receipt: &receipt, State: "running"}
			require.NoError(t, c.collect(context.Background(), &attempt))
			require.Equal(t, "assessed", attempt.State)
			require.Equal(t, terminalState, attempt.Receipt.State)
			require.Equal(t, &assessment, attempt.Assessment)
		})
	}
}
