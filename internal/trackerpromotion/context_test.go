package trackerpromotion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
)

type records map[string]*journal.Record

func (r records) Read(_ context.Context, id string) (*journal.Record, error) {
	v := r[id]
	if v == nil {
		return nil, journal.ErrNotFound
	}
	b, _ := json.Marshal(v)
	var copy journal.Record
	_ = json.Unmarshal(b, &copy)
	return &copy, nil
}
func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func fixture() (Exporter, trackerflow.Manifest, string, records) {
	m := trackerflow.Manifest{SchemaVersion: 1, CaseID: "case", Revision: "v1", Public: true, Advisory: "Public advisory", AdvisoryID: "CVE-2021-23337", PolicyDigest: strings.Repeat("a", 64), ProfileDigest: strings.Repeat("b", 64), Agent: "cve-saga", Jira: trackerflow.Destination{Project: "KONFLUX", IssueTypeID: "10014", AssigneeAccountID: "assignee"}, Limits: trackerflow.Limits{MaxTargets: 1, MaxConcurrent: 1, MaxAttempts: 2}, Targets: []trackerflow.Target{{Repository: "https://github.com/org/repo", Branch: "release", SourceSHA: strings.Repeat("c", 40), Component: "src/a.js", Product: "product", Release: "v1", Stream: "stream", Owner: "owner", DomainContext: raw(map[string]any{"intake": map[string]any{"cve": "CVE-2021-23337"}, "target_connection": map[string]any{"mapping_revision": "v1"}, "remediation_capabilities": map[string]any{"coding_types": []string{}, "change_paths": []string{}, "preference_order": [][]string{{"patch_backport"}, {"dependency_update", "patched_fork", "source_fix", "rebuild"}}}})}}}
	id := trackerflow.TargetID(m.CaseID, m.Targets[0])
	r := trackerflow.Request{OperationID: "op", CaseID: m.CaseID, TargetID: id, JiraKey: "KONFLUX-1", Repository: m.Targets[0].Repository, Branch: "release", SourceSHA: m.Targets[0].SourceSHA, Agent: m.Agent, PolicyDigest: m.PolicyDigest, ProfileDigest: m.ProfileDigest, ManifestDigest: m.Digest()}
	a := trackerflow.Assessment{RequestDigest: r.Digest(), Outcome: "affected", ReceiptRef: "https://gitlab.example/job/artifacts/revision.json#sha256=" + strings.Repeat("f", 64)}
	receipt := trackerflow.RunReceipt{OperationID: "op", RequestDigest: r.Digest(), RunID: "10", RunURL: "https://gitlab.example/job/10", State: "completed"}
	pub := trackerflow.AssessmentPublicationReceipt{JiraKey: r.JiraKey, CommentID: "11", Binding: strings.Repeat("e", 64)}
	state := trackerflow.CaseState{ManifestDigest: m.Digest(), Required: []string{id}, Targets: map[string]trackerflow.TargetState{id: {Target: m.Targets[0], Tracker: &trackerflow.TrackerReceipt{Key: r.JiraKey, ID: "1"}, Attempts: []trackerflow.Attempt{{Request: r, Receipt: &receipt, Assessment: &a, Publication: &pub, State: "assessed"}}}}}
	db := records{m.CaseID: &journal.Record{ID: m.CaseID, Binding: m.Digest(), Generation: 3, Data: raw(state), Effects: map[string]journal.Effect{"assessment-op": {Kind: "assessment_publication", Status: journal.EffectConfirmed, Binding: pub.Binding, Receipt: raw(pub)}}}, "op": &journal.Record{ID: "op", Binding: r.Digest(), Data: raw(trackerflow.WorkerState{Request: r, State: "assessed", RunReceipt: &receipt, Assessment: &a})}}
	e := Exporter{Journal: db, Authorize: func(context.Context, trackerflow.Manifest, trackerflow.Target) error { return nil }, CheckIssue: func(context.Context, string) error { return nil }, VerifyTracker: func(context.Context, trackerflow.Manifest, trackerflow.Target, trackerflow.TrackerReceipt) error {
		return nil
	}, VerifyPublication: func(context.Context, trackerflow.Manifest, trackerflow.Target, trackerflow.Request, trackerflow.Assessment, trackerflow.AssessmentPublicationReceipt) error {
		return nil
	}, VerifySource: func(context.Context, string, trackerflow.Request) error { return nil }}
	return e, m, id, db
}
func TestExportCurrentAcceptedPublishedAssessment(t *testing.T) {
	e, m, id, _ := fixture()
	v, err := e.Export(context.Background(), m, id, "source")
	if err != nil {
		t.Fatal(err)
	}
	if v["issue_key"] != "KONFLUX-1" || v["parent_generation"] != uint64(3) {
		t.Fatal(v)
	}
	connection := v["target_connection"].(map[string]any)
	if connection["repository"] != "org/repo" || connection["status"] != "verified" {
		t.Fatal(connection)
	}
	if v["parent_data_digest"] == "" {
		t.Fatal("missing atomic parent data observation")
	}
	if v["target_digest"] == "" || v["intake_digest"] == "" {
		t.Fatal("missing domain binding")
	}
}
func TestRejectUnprovenOrStaleEvidence(t *testing.T) {
	cases := map[string]func(*Exporter, *trackerflow.Manifest, string, records){
		"parent rebind":  func(_ *Exporter, m *trackerflow.Manifest, _ string, db records) { db[m.CaseID].Binding = "new" },
		"worker missing": func(_ *Exporter, _ *trackerflow.Manifest, _ string, db records) { delete(db, "op") },
		"worker running": func(_ *Exporter, _ *trackerflow.Manifest, _ string, db records) {
			var s trackerflow.WorkerState
			_ = json.Unmarshal(db["op"].Data, &s)
			s.State = "running"
			db["op"].Data = raw(s)
		},
		"publication ambiguous": func(_ *Exporter, m *trackerflow.Manifest, _ string, db records) {
			f := db[m.CaseID].Effects["assessment-op"]
			f.Status = "ambiguous"
			db[m.CaseID].Effects["assessment-op"] = f
		},
		"newer pending": func(_ *Exporter, m *trackerflow.Manifest, id string, db records) {
			var s trackerflow.CaseState
			_ = json.Unmarshal(db[m.CaseID].Data, &s)
			ts := s.Targets[id]
			a := ts.Attempts[0]
			a.State = "running"
			ts.Attempts = append(ts.Attempts, a)
			s.Targets[id] = ts
			db[m.CaseID].Data = raw(s)
		},
		"issue no longer public": func(e *Exporter, _ *trackerflow.Manifest, _ string, _ records) {
			e.CheckIssue = func(context.Context, string) error { return trackerflow.ErrAuthorization }
		},
		"source changed": func(e *Exporter, _ *trackerflow.Manifest, _ string, _ records) {
			e.VerifySource = func(context.Context, string, trackerflow.Request) error { return journal.ErrBinding }
		},
		"publication changed": func(e *Exporter, _ *trackerflow.Manifest, _ string, _ records) {
			e.VerifyPublication = func(context.Context, trackerflow.Manifest, trackerflow.Target, trackerflow.Request, trackerflow.Assessment, trackerflow.AssessmentPublicationReceipt) error {
				return errors.New("changed")
			}
		},
		"concurrent rebind": func(e *Exporter, m *trackerflow.Manifest, _ string, db records) {
			e.VerifySource = func(context.Context, string, trackerflow.Request) error { db[m.CaseID].Binding = "changed"; return nil }
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e, m, id, db := fixture()
			change(&e, &m, id, db)
			if _, err := e.Export(context.Background(), m, id, "source"); err == nil {
				t.Fatal("accepted stale or unproven evidence")
			}
		})
	}
}
func TestDomainDigestPythonCompatibility(t *testing.T) {
	// Python: sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).
	v := map[string]any{"url": "https://example.test/?a=1&b=2", "unicode": "hé😀", "html": "<x>"}
	got, err := DomainDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	want := rawDigest([]byte(`{"html":"<x>","unicode":"h\u00e9\ud83d\ude00","url":"https://example.test/?a=1&b=2"}`))
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
func TestDomainDigestNormalizesRawMappingOrder(t *testing.T) {
	a, _ := DomainDigest(map[string]any{"mapping": json.RawMessage(`{"z":1,"a":"é"}`)})
	b, _ := DomainDigest(map[string]any{"mapping": map[string]any{"a": "é", "z": 1}})
	if a != b {
		t.Fatal("raw protected mapping bypassed canonical ordering")
	}
}

func TestParentDataDigestMatchesRawObservedBytes(t *testing.T) {
	e, m, id, db := fixture()
	expected := rawDigest(db[m.CaseID].Data)
	v, err := e.Export(context.Background(), m, id, "source")
	if err != nil {
		t.Fatal(err)
	}
	if v["parent_data_digest"] != expected {
		t.Fatal("parent digest was not the exact observed record bytes")
	}
	var s trackerflow.CaseState
	_ = json.Unmarshal(db[m.CaseID].Data, &s)
	ts := s.Targets[id]
	ts.Blocker = "new observation"
	s.Targets[id] = ts
	db[m.CaseID].Data = raw(s)
	again, err := e.Export(context.Background(), m, id, "source")
	if err != nil {
		t.Fatal(err)
	}
	if again["parent_data_digest"] == expected {
		t.Fatal("changed parent data reused prior admission observation")
	}
}
