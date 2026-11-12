// Package trackerpromotion exports fresh domain context from accepted saga evidence.
// It grants no model execution, coding, external publication or human approval.
package trackerpromotion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf16"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/fullsend-ai/fullsend/internal/trackerworker"
)

type Reader interface {
	Read(context.Context, string) (*journal.Record, error)
}
type Exporter struct {
	Journal           Reader
	Authorize         func(context.Context, trackerflow.Manifest, trackerflow.Target) error
	CheckIssue        func(context.Context, string) error
	VerifyTracker     func(context.Context, trackerflow.Manifest, trackerflow.Target, trackerflow.TrackerReceipt) error
	VerifyPublication func(context.Context, trackerflow.Manifest, trackerflow.Target, trackerflow.Request, trackerflow.Assessment, trackerflow.AssessmentPublicationReceipt) error
	VerifySource      func(context.Context, string, trackerflow.Request) error
}

// DomainDigest matches the original Python domain digest for JSON values.
// In particular JSON is sorted, compact, ASCII and does not HTML-escape URLs.
func DomainDigest(v any) (string, error) {
	// Normalize RawMessage and structs into maps before sorting nested keys.
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return "", err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return "", err
	}
	var ascii strings.Builder
	for _, r := range strings.TrimSuffix(b.String(), "\n") {
		if r < 128 {
			ascii.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&ascii, "\\u%04x", r)
		} else {
			a, z := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, "\\u%04x\\u%04x", a, z)
		}
	}
	// Hash raw canonical bytes, not a JSON-encoded string.
	return rawDigest([]byte(ascii.String())), nil
}

func decode(raw []byte, v any) error { return trackerflow.DecodeStrict(raw, v) }

// Export requires already admitted current source refs. VerifySource proves local
// exact pins; it does not pretend a local tracking ref is a fresh remote lookup.
func (e Exporter) Export(ctx context.Context, m trackerflow.Manifest, targetID, source string) (map[string]any, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if e.Journal == nil || e.Authorize == nil || e.CheckIssue == nil || e.VerifyTracker == nil || e.VerifyPublication == nil {
		return nil, errors.New("fresh protected admission required")
	}
	var target trackerflow.Target
	found := false
	for _, t := range m.Targets {
		if trackerflow.TargetID(m.CaseID, t) == targetID {
			target = t
			found = true
		}
	}
	if !found || target.BlockedReason != "" || (len(target.DomainContext) == 0 || len(target.DomainContext) > 32768) {
		return nil, journal.ErrBinding
	}
	if err := e.Authorize(ctx, m, target); err != nil {
		return nil, err
	}
	parent, err := e.Journal.Read(ctx, m.CaseID)
	if err != nil {
		return nil, err
	}
	if parent.Binding != m.Digest() {
		return nil, journal.ErrBinding
	}
	var state trackerflow.CaseState
	if decode(parent.Data, &state) != nil || state.ManifestDigest != m.Digest() {
		return nil, journal.ErrIntegrity
	}
	ts, ok := state.Targets[targetID]
	if !ok || trackerflow.Hash(ts.Target) != trackerflow.Hash(target) || ts.Tracker == nil {
		return nil, journal.ErrBinding
	}
	required := false
	for _, id := range state.Required {
		if id == targetID {
			required = true
		}
	}
	if !required {
		return nil, journal.ErrBinding
	}
	// A newer pending or failed attempt invalidates promotion of an older result.
	var latest *trackerflow.Attempt
	for i := range ts.Attempts {
		if ts.Attempts[i].Request.ManifestDigest == m.Digest() {
			latest = &ts.Attempts[i]
		}
	}
	if latest == nil || latest.State != "assessed" || latest.Assessment == nil || latest.Receipt == nil || latest.Publication == nil {
		return nil, errors.New("current published assessment required")
	}
	r := latest.Request
	a := *latest.Assessment
	effect, ok := parent.Effects["assessment-"+r.OperationID]
	var published trackerflow.AssessmentPublicationReceipt
	if !ok || effect.Kind != "assessment_publication" || effect.Status != journal.EffectConfirmed || decode(effect.Receipt, &published) != nil || published != *latest.Publication || effect.Binding != published.Binding {
		return nil, journal.ErrBinding
	}
	if r.Validate() != nil || a.Validate(r) != nil || r.TargetID != targetID || r.CaseID != m.CaseID || r.JiraKey != ts.Tracker.Key || r.Repository != target.Repository || r.Branch != target.Branch || r.SourceSHA != target.SourceSHA || r.Agent != m.Agent || r.PolicyDigest != m.PolicyDigest || r.ProfileDigest != m.ProfileDigest {
		return nil, journal.ErrBinding
	}
	if latest.Receipt.OperationID != r.OperationID || latest.Receipt.RequestDigest != r.Digest() || latest.Receipt.RunID == "" || latest.Receipt.RunURL == "" {
		return nil, journal.ErrBinding
	}
	switch latest.Receipt.State {
	case "completed", "failed", "cancelled":
	default:
		return nil, errors.New("assessment pipeline still active")
	}
	worker, err := e.Journal.Read(ctx, r.OperationID)
	if err != nil {
		return nil, err
	}
	var ws trackerflow.WorkerState
	if worker.Binding != r.Digest() || decode(worker.Data, &ws) != nil || ws.Request != r || ws.State != "assessed" || ws.Assessment == nil || *ws.Assessment != a || ws.RunReceipt == nil || ws.RunReceipt.OperationID != r.OperationID || ws.RunReceipt.RequestDigest != r.Digest() || ws.RunReceipt.RunID != latest.Receipt.RunID || ws.RunReceipt.RunURL != latest.Receipt.RunURL {
		return nil, journal.ErrBinding
	}
	if err = e.CheckIssue(ctx, r.JiraKey); err != nil {
		return nil, err
	}
	if err = e.VerifyTracker(ctx, m, target, *ts.Tracker); err != nil {
		return nil, err
	}
	if err = e.VerifyPublication(ctx, m, target, r, a, *latest.Publication); err != nil {
		return nil, err
	}
	verify := e.VerifySource
	if verify == nil {
		verify = trackerworker.VerifySource
	}
	if err = verify(ctx, source, r); err != nil {
		return nil, err
	}
	var domain map[string]any
	decoder := json.NewDecoder(bytes.NewReader(target.DomainContext))
	decoder.UseNumber()
	if decoder.Decode(&domain) != nil || domain == nil {
		return nil, errors.New("reviewed domain mapping required")
	}
	// Domain input may supply evidence/capabilities, never authoritative identity.
	intake, ok := domain["intake"].(map[string]any)
	if !ok || m.AdvisoryID == "" || intake["cve"] != m.AdvisoryID {
		return nil, errors.New("canonical domain advisory required")
	}
	connection, ok := domain["target_connection"].(map[string]any)
	if !ok {
		return nil, errors.New("domain target connection required")
	}
	if _, ok = domain["remediation_capabilities"].(map[string]any); !ok {
		return nil, errors.New("domain remediation capabilities required")
	}
	connection["status"] = "verified"
	connection["repository"] = strings.TrimSuffix(strings.TrimPrefix(target.Repository, "https://github.com/"), ".git")
	connection["branch"] = target.Branch
	connection["repository_sha"] = target.SourceSHA
	// The original domain contract uses owner/repo while generic worker admission
	// uses credential-free HTTPS. The repository identity remains exact.
	if !strings.HasPrefix(target.Repository, "https://github.com/") {
		return nil, errors.New("GitHub remediation source required")
	}
	domain["case_id"] = m.CaseID
	domain["target_id"] = targetID
	domain["request_digest"] = r.Digest()
	domain["manifest_digest"] = m.Digest()
	domain["policy_digest"] = m.PolicyDigest
	domain["profile_digest"] = m.ProfileDigest
	domain["issue_key"] = r.JiraKey
	domain["repository_sha"] = r.SourceSHA
	domain["parent_generation"] = parent.Generation
	domain["parent_data_digest"] = rawDigest(parent.Data)
	domain["target"] = map[string]any{"repository": connection["repository"], "branch": target.Branch, "component": target.Component, "product": target.Product, "release": target.Release, "stream": target.Stream, "owner": target.Owner}
	domain["accepted_native_assessment"] = a
	domain["accepted_native_request"] = r
	domain["intake_digest"], err = DomainDigest(map[string]any{"intake": intake, "policy_digest": m.PolicyDigest, "mapping": target.DomainContext, "assignee": m.Jira.AssigneeAccountID})
	if err != nil {
		return nil, err
	}
	domain["target_digest"], err = DomainDigest(connection)
	if err != nil {
		return nil, err
	}
	// Fresh reads detect concurrent parent/worker changes. This is an observation,
	// not atomic effect authorization: the caller still needs its own journal CAS.
	again, err := e.Journal.Read(ctx, m.CaseID)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(parent, again) {
		return nil, journal.ErrConflict
	}
	again, err = e.Journal.Read(ctx, r.OperationID)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(worker, again) {
		return nil, journal.ErrConflict
	}
	return domain, nil
}
