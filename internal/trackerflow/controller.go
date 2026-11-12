package trackerflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fullsend-ai/fullsend/internal/journal"
)

// Controller advances a bounded case once. Repeated invocations reconcile durable
// effects; they never blindly repeat a possibly accepted create or dispatch.
type Controller struct {
	Journal    *journal.Engine
	Tracker    Tracker
	Scheduler  Scheduler
	Authorizer Authorizer
	Owner      string
	LeaseTTL   time.Duration
}

func marshal(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func readState(r *journal.Record) (CaseState, error) {
	var s CaseState
	if err := json.Unmarshal(r.Data, &s); err != nil || s.Targets == nil {
		return s, journal.ErrIntegrity
	}
	return s, nil
}
func newState(m Manifest) CaseState {
	s := CaseState{ManifestDigest: m.Digest(), Targets: map[string]TargetState{}}
	for _, t := range m.Targets {
		id := TargetID(m.CaseID, t)
		s.Required = append(s.Required, id)
		s.Targets[id] = TargetState{Target: t, Status: "pending"}
	}
	return s
}
func (c *Controller) save(ctx context.Context, m Manifest, l journal.Lease, s CaseState, change func(*journal.Record) error) error {
	for attempt := 0; attempt < 8; attempt++ {
		_, err := c.Journal.Update(ctx, m.CaseID, l, func(r *journal.Record) error {
			if r.Binding != m.Digest() {
				return journal.ErrBinding
			}
			if change != nil {
				if err := change(r); err != nil {
					return err
				}
			}
			r.Data = marshal(s)
			return nil
		})
		if !errors.Is(err, journal.ErrConflict) {
			return err
		}
		// Reload through Engine.Update: current case ownership and binding are
		// rechecked. Only unrelated records may change under this exclusive lease.
	}
	return journal.ErrConflict
}
func (c *Controller) authorize(ctx context.Context, m Manifest, t Target, action string) error {
	if c.Authorizer == nil {
		return ErrAuthorization
	}
	return c.Authorizer.Authorize(ctx, m, t, action)
}
func (c *Controller) Cycle(ctx context.Context, m Manifest) (Report, error) {
	report := Report{CaseID: m.CaseID}
	if err := m.Validate(); err != nil {
		return report, err
	}
	if c.Journal == nil || c.Tracker == nil || c.Scheduler == nil || !safeID.MatchString(c.Owner) {
		return report, errors.New("controller dependencies and owner required")
	}
	for _, target := range m.Targets {
		if err := c.authorize(ctx, m, target, "admit"); err != nil {
			return report, err
		}
	}
	state := newState(m)
	r, err := c.Journal.Admit(ctx, m.CaseID, m.Digest(), marshal(state))
	if errors.Is(err, journal.ErrBinding) {
		r, err = c.Journal.Read(ctx, m.CaseID)
	}
	if err != nil {
		return report, err
	}
	l, err := c.Journal.Claim(ctx, m.CaseID, c.Owner, c.ttl())
	if err != nil {
		return report, err
	}
	defer func() { _ = c.Journal.Release(ctx, m.CaseID, l) }()
	// Admission observes eligibility, not exclusive ownership. Another controller
	// may advance history before this claim, so consume only a post-claim snapshot.
	r, err = c.Journal.Read(ctx, m.CaseID)
	if err != nil {
		return report, err
	}
	state, err = readState(r)
	if err != nil {
		return report, err
	}
	if state.ManifestDigest != m.Digest() {
		next := newState(m)
		for id, old := range state.Targets {
			if current, ok := next.Targets[id]; ok {
				old.Target = current.Target
				old.Status = "stale"
				old.Blocker = "inputs_changed"
				next.Targets[id] = old
			} else {
				old.Status = "superseded"
				next.Targets[id] = old
			}
		}
		state = next
		if _, err = c.Journal.Rebind(ctx, m.CaseID, l, m.Digest(), marshal(state)); err != nil {
			return report, err
		}
	}
	// Reconcile every historical attempt, including targets removed from the plan;
	// supersession does not make an accepted remote run stop consuming concurrency.
	for id, t := range state.Targets {
		for i := range t.Attempts {
			a := &t.Attempts[i]
			if terminal(a.State) {
				continue
			}
			if a.Request.ManifestDigest != m.Digest() && a.Receipt == nil {
				cancelled, e := c.cancelUnsubmitted(ctx, m, l, &state, id, i)
				if e != nil {
					return report, e
				}
				if cancelled {
					t = state.Targets[id]
					continue
				}
			}
			if err = c.collect(ctx, a); err != nil && !errors.Is(err, ErrAmbiguous) {
				return report, err
			}
		}
		state.Targets[id] = t
	}
	if err = c.save(ctx, m, l, state, func(r *journal.Record) error {
		for _, target := range state.Targets {
			for _, a := range target.Attempts {
				effect, ok := r.Effects[a.Request.OperationID]
				if ok && a.Receipt != nil && effect.Status != "confirmed" {
					effect.Status = "confirmed"
					effect.Receipt = marshal(a.Receipt)
					r.Effects[effect.ID] = effect
				}
			}
		}
		return nil
	}); err != nil {
		return report, err
	}
	for _, id := range state.Required {
		t := state.Targets[id]
		if t.Target.BlockedReason != "" {
			t.Status = "blocked"
			t.Blocker = t.Target.BlockedReason
			state.Targets[id] = t
			continue
		}
		if err = c.authorize(ctx, m, t.Target, "publish"); err != nil {
			t.Status = "pending_authorization"
			t.Blocker = "publication_authorization_required"
			state.Targets[id] = t
			continue
		}
		if t.Tracker == nil {
			if err = c.publish(ctx, m, l, id, &t, state); err != nil {
				return report, err
			}
			state.Targets[id] = t
		} else if err = c.Tracker.Verify(ctx, m, t.Target, *t.Tracker); err != nil {
			return report, err
		}
		if t.Tracker == nil {
			continue
		}
		// An intended dispatch has not crossed the external-action boundary.
		// Resume that exact attempt after a crash instead of consuming another one.
		for i, a := range t.Attempts {
			if a.Request.ManifestDigest == m.Digest() && !terminal(a.State) && a.Receipt == nil {
				record, e := c.Journal.Read(ctx, m.CaseID)
				if e != nil {
					return report, e
				}
				if record.Effects[a.Request.OperationID].Status == "intended" {
					state.Targets[id] = t
					if e = c.submitAttempt(ctx, m, l, &state, id, i); e != nil {
						return report, e
					}
					t = state.Targets[id]
				}
			}
		}
		current := false
		for index, a := range t.Attempts {
			if a.Request.ManifestDigest == m.Digest() {
				if a.Assessment != nil && a.State == "assessed" {
					state.Targets[id] = t
					published, e := c.publishAssessment(ctx, m, l, &state, id, index)
					if e != nil {
						return report, e
					}
					t = state.Targets[id]
					if !published {
						current = true
						continue
					}
					switch a.Assessment.Outcome {
					case "affected", "not_affected":
						t.Status = "assessed"
						t.Blocker = ""
						current = true
					case "uncertain":
						t.Status = "uncertain"
						t.Blocker = "human_assessment_required"
						current = true
					case "failed":
						t.Status = "failed"
						t.Blocker = "assessment_failed"
					}
				}
				if !terminal(a.State) {
					t.Status = a.State
					t.Blocker = ""
					current = true
				}
			}
		}
		if current {
			state.Targets[id] = t
			continue
		}
		if err = c.authorize(ctx, m, t.Target, "dispatch"); err != nil {
			t.Status = "pending_authorization"
			t.Blocker = "triage_authorization_required"
			state.Targets[id] = t
			continue
		}
		record, e := c.Journal.Read(ctx, m.CaseID)
		if e != nil {
			return report, e
		}
		count := record.Counters["attempts-"+id]
		if count >= uint64(m.Limits.MaxAttempts) {
			t.Status = "exhausted"
			t.Blocker = "attempt_budget_exhausted"
			state.Targets[id] = t
			continue
		}
		if active(state) >= m.Limits.MaxConcurrent {
			t.Status = "pending"
			t.Blocker = "case_concurrency_bound"
			state.Targets[id] = t
			continue
		}
		req := Request{OperationID: fmt.Sprintf("dispatch-%s-%d", id, count+1), CaseID: m.CaseID, TargetID: id, JiraKey: t.Tracker.Key, Repository: t.Target.Repository, Branch: t.Target.Branch, SourceSHA: t.Target.SourceSHA, Agent: m.Agent, ProfileDigest: m.ProfileDigest, PolicyDigest: m.PolicyDigest, ManifestDigest: m.Digest()}
		if e = req.Validate(); e != nil {
			return report, e
		}
		if _, e = c.Journal.Admit(ctx, req.OperationID, req.Digest(), marshal(WorkerState{Request: req, State: "admitted"})); e != nil {
			return report, e
		}
		attempt := Attempt{Request: req, State: "accepted"}
		t.Attempts = append(t.Attempts, attempt)
		t.Status = "accepted"
		t.Blocker = ""
		state.Targets[id] = t
		if e = c.save(ctx, m, l, state, func(r *journal.Record) error {
			r.Counters["attempts-"+id] = count + 1
			r.Effects[req.OperationID] = journal.Effect{ID: req.OperationID, Kind: "dispatch", Binding: req.Digest(), Status: "intended"}
			return nil
		}); e != nil {
			return report, e
		}
		if e = c.submitAttempt(ctx, m, l, &state, id, len(t.Attempts)-1); e != nil {
			return report, e
		}
	}
	if err = c.save(ctx, m, l, state, nil); err != nil {
		return report, err
	}
	report.Targets = state.Targets
	report.Complete = true
	for _, id := range state.Required {
		if state.Targets[id].Status == "assessed" {
			report.Assessed++
		} else {
			report.Complete = false
			report.Pending++
		}
	}
	return report, nil
}
func (c *Controller) ttl() time.Duration {
	if c.LeaseTTL > 0 {
		return c.LeaseTTL
	}
	return 15 * time.Minute
}
func (c *Controller) collect(ctx context.Context, a *Attempt) error {
	r, err := c.Journal.Read(ctx, a.Request.OperationID)
	if err != nil {
		return err
	}
	if r.Binding != a.Request.Digest() {
		return journal.ErrBinding
	}
	var worker WorkerState
	if err = json.Unmarshal(r.Data, &worker); err != nil || worker.Request != a.Request {
		return journal.ErrIntegrity
	}
	if worker.RunReceipt != nil {
		if err = receiptValid(a.Request, *worker.RunReceipt); err != nil {
			return err
		}
		a.Receipt = worker.RunReceipt
	}
	if (worker.State == "failed" || worker.State == "cancelled") && worker.Assessment == nil {
		a.State = worker.State
		return nil
	}
	if worker.Assessment != nil {
		if err = worker.Assessment.Validate(a.Request); err != nil {
			return err
		}
		a.Assessment = worker.Assessment
		a.State = "assessed"
		return nil
	}
	receipt, assessment, err := c.Scheduler.Reconcile(ctx, a.Request, a.Receipt)
	if err != nil {
		return err
	}
	if err = receiptValid(a.Request, receipt); err != nil {
		return err
	}
	a.Receipt = &receipt
	if assessment != nil {
		if err = assessment.Validate(a.Request); err != nil {
			return err
		}
		a.Assessment = assessment
		a.State = "assessed"
		return nil
	}
	switch receipt.State {
	case "failed", "cancelled":
		a.State = receipt.State
	case "completed":
		a.State = "failed"
	default:
		a.State = receipt.State
	}
	return nil
}
func (c *Controller) publish(ctx context.Context, m Manifest, l journal.Lease, id string, t *TargetState, s CaseState) error {
	op := "tracker-" + id
	record, err := c.Journal.Read(ctx, m.CaseID)
	if err != nil {
		return err
	}
	effect, exists := record.Effects[op]
	binding := Hash(trackerScope(m, t.Target))
	if !exists {
		effect = journal.Effect{ID: op, Kind: "tracker", Binding: binding, Status: "intended"}
		if err = c.save(ctx, m, l, s, func(r *journal.Record) error { r.Effects[op] = effect; return nil }); err != nil {
			return err
		}
	}
	if effect.Binding != binding {
		return journal.ErrBinding
	}
	if effect.Status == "confirmed" {
		var receipt TrackerReceipt
		if err = json.Unmarshal(effect.Receipt, &receipt); err != nil {
			return journal.ErrIntegrity
		}
		if err = c.Tracker.Verify(ctx, m, t.Target, receipt); err != nil {
			return err
		}
		t.Tracker = &receipt
		return nil
	}
	candidates, err := c.Tracker.Find(ctx, m, t.Target)
	if err != nil {
		return err
	}
	if len(candidates) > 1 {
		return errors.New("multiple tracker candidates")
	}
	var receipt TrackerReceipt
	if len(candidates) == 1 {
		receipt = candidates[0]
		if err = c.Tracker.Verify(ctx, m, t.Target, receipt); err != nil {
			return err
		}
	} else {
		if effect.Status != "intended" {
			t.Status = "ambiguous"
			t.Blocker = "tracker_publication_unresolved"
			return nil
		}
		if err = c.authorize(ctx, m, t.Target, "publish"); err != nil {
			return err
		}
		if err = c.save(ctx, m, l, s, func(r *journal.Record) error {
			v := r.Effects[op]
			v.Status = "in_flight"
			r.Effects[op] = v
			return nil
		}); err != nil {
			return err
		}
		receipt, err = c.Tracker.Create(ctx, m, t.Target)
		if err == nil {
			err = c.Tracker.Verify(ctx, m, t.Target, receipt)
		}
		if err != nil {
			t.Status = "ambiguous"
			t.Blocker = "tracker_publication_unresolved"
			return c.save(ctx, m, l, s, func(r *journal.Record) error {
				v := r.Effects[op]
				v.Status = "ambiguous"
				r.Effects[op] = v
				return nil
			})
		}
	}
	if err = c.authorize(ctx, m, t.Target, "publish"); err != nil {
		return err
	}
	if err = c.save(ctx, m, l, s, func(r *journal.Record) error {
		v := r.Effects[op]
		v.Status = "confirmed"
		v.Receipt = marshal(receipt)
		r.Effects[op] = v
		return nil
	}); err != nil {
		return err
	}
	t.Tracker = &receipt
	t.Status = "pending"
	t.Blocker = ""
	return nil
}

func (c *Controller) submitAttempt(ctx context.Context, m Manifest, l journal.Lease, state *CaseState, id string, index int) error {
	t := state.Targets[id]
	req := t.Attempts[index].Request
	if err := c.authorize(ctx, m, t.Target, "dispatch"); err != nil {
		return err
	}
	if err := c.save(ctx, m, l, *state, func(r *journal.Record) error {
		effect := r.Effects[req.OperationID]
		if effect.Status != "intended" {
			return ErrAmbiguous
		}
		effect.Status = "in_flight"
		r.Effects[effect.ID] = effect
		return nil
	}); err != nil {
		return err
	}
	receipt, err := c.Scheduler.Submit(ctx, req)
	if err != nil || receiptValid(req, receipt) != nil {
		t.Attempts[index].State = "ambiguous"
		t.Status = "ambiguous"
		t.Blocker = "dispatch_acceptance_unresolved"
		state.Targets[id] = t
		return c.save(ctx, m, l, *state, func(r *journal.Record) error {
			v := r.Effects[req.OperationID]
			v.Status = "ambiguous"
			r.Effects[v.ID] = v
			return nil
		})
	}
	t.Attempts[index].Receipt = &receipt
	state.Targets[id] = t
	return c.save(ctx, m, l, *state, func(r *journal.Record) error {
		v := r.Effects[req.OperationID]
		v.Status = "confirmed"
		v.Receipt = marshal(receipt)
		r.Effects[v.ID] = v
		return nil
	})
}

// CancellationReceipt proves a locally admitted operation never crossed its
// submission boundary. It is deliberately distinct from a scheduling receipt.
type CancellationReceipt struct {
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
	Outcome       string `json:"outcome"`
}

func (c *Controller) cancelUnsubmitted(ctx context.Context, m Manifest, l journal.Lease, state *CaseState, id string, index int) (bool, error) {
	t := state.Targets[id]
	a := t.Attempts[index]
	record, err := c.Journal.Read(ctx, m.CaseID)
	if err != nil {
		return false, err
	}
	effect, ok := record.Effects[a.Request.OperationID]
	if !ok || effect.Status != "intended" {
		return false, nil
	}
	child, err := c.Journal.Read(ctx, a.Request.OperationID)
	if err != nil {
		return false, err
	}
	var worker WorkerState
	if err = DecodeStrict(child.Data, &worker); err != nil || child.Binding != a.Request.Digest() || worker.Request != a.Request {
		return false, journal.ErrIntegrity
	}
	if worker.State != "admitted" && worker.State != "cancelled" {
		return false, nil
	}
	if worker.State == "admitted" {
		lease, e := c.Journal.Claim(ctx, a.Request.OperationID, c.Owner, c.ttl())
		if errors.Is(e, journal.ErrOwnership) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		_, e = c.Journal.Update(ctx, a.Request.OperationID, lease, func(r *journal.Record) error {
			var current WorkerState
			if DecodeStrict(r.Data, &current) != nil || current.Request != a.Request || current.State != "admitted" || r.Binding != a.Request.Digest() {
				return journal.ErrTransition
			}
			current.State = "cancelled"
			r.Data = marshal(current)
			return nil
		})
		_ = c.Journal.Release(ctx, a.Request.OperationID, lease)
		if e != nil {
			return false, e
		}
	}
	t.Attempts[index].State = "cancelled"
	state.Targets[id] = t
	receipt := CancellationReceipt{OperationID: a.Request.OperationID, RequestDigest: a.Request.Digest(), Outcome: "cancelled_before_submission"}
	err = c.save(ctx, m, l, *state, func(r *journal.Record) error {
		current := r.Effects[a.Request.OperationID]
		if current.Status != "intended" {
			return journal.ErrTransition
		}
		current.Status = "confirmed"
		current.Receipt = marshal(receipt)
		r.Effects[current.ID] = current
		return nil
	})
	return err == nil, err
}
