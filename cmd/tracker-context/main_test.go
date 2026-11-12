package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/fullsend-ai/fullsend/internal/trackerpromotion"
)

func TestMissingInputsFailBeforeRemoteAccess(t *testing.T) {
	for _, args := range [][]string{{}, {"--manifest", "file"}, {"--target-id", "target"}, {"--unknown"}, {"--manifest", "file", "--target-id", "id", "--target-repo", "source", "extra"}} {
		if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatal("incomplete command accepted")
		}
	}
}
func TestHelpIsReadOnly(t *testing.T) {
	if err := run(context.Background(), []string{"--help"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
func manifestFixture() trackerflow.Manifest {
	return trackerflow.Manifest{SchemaVersion: 1, CaseID: "case", Revision: "v1", Public: true, Advisory: "public", PolicyDigest: strings.Repeat("a", 64), ProfileDigest: strings.Repeat("b", 64), Agent: "cve-saga", Jira: trackerflow.Destination{Project: "KONFLUX", IssueTypeID: "10014", AssigneeAccountID: "assignee"}, Limits: trackerflow.Limits{MaxTargets: 1, MaxConcurrent: 1, MaxAttempts: 1}, Targets: []trackerflow.Target{{Repository: "https://github.com/org/repo", Branch: "release", SourceSHA: strings.Repeat("c", 40), Component: "src", Product: "product", Release: "v1", Stream: "stream", Owner: "owner"}}}
}
func profileFixture(m trackerflow.Manifest) trackerflow.Profile {
	return trackerflow.Profile{PolicyDigest: m.PolicyDigest, ProfileDigest: m.ProfileDigest, Agent: m.Agent, AllowedTargetIDs: []string{trackerflow.TargetID(m.CaseID, m.Targets[0])}, Jira: trackerflow.JiraProfile{IssueControls: &trackerflow.IssueControls{RequiredLabels: []string{"public"}}, BaseURL: "https://jira.example", Project: m.Jira.Project, IssueTypeID: m.Jira.IssueTypeID, AssigneeAccountID: m.Jira.AssigneeAccountID, ActorAccountID: "actor"}, Control: trackerflow.ControlProfile{BaseURL: "https://gitlab.example", Owner: "group", Repository: "control", WorkerRef: "main", DispatchRole: "poller", LookupSince: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)}}
}
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func argsFor(path string) []string {
	return []string{"--manifest", path, "--target-id", "target", "--target-repo", "source"}
}
func TestManifestAndProfileAdmission(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		profile   bool
	}{{"missing", "", false}, {"oversize", strings.Repeat("x", 1<<20+1), false}, {"unknown", "{\"unknown\":1}", false}, {"invalidmanifest", "{}", false}, {"profilemissing", "", true}} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if test.profile {
				writeJSON(t, path, manifestFixture())
			} else if test.name != "missing" {
				if err := os.WriteFile(path, []byte(test.raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(trackerflow.ProfileEnv, "")
			if err := run(context.Background(), argsFor(path), &bytes.Buffer{}); err == nil {
				t.Fatal("invalid admission accepted")
			}
		})
	}
}
func TestProtectedWiringAndExport(t *testing.T) {
	oldOpen, oldExport := openJournal, exportContext
	defer func() { openJournal, exportContext = oldOpen, oldExport }()
	for _, mode := range []string{"missingcontrols", "missingrole", "missingjiracreds", "journalunavailable", "revoked", "accepted", "outputfailed"} {
		t.Run(mode, func(t *testing.T) {
			m := manifestFixture()
			p := profileFixture(m)
			path := filepath.Join(t.TempDir(), "manifest.json")
			writeJSON(t, path, m)
			if mode == "missingcontrols" {
				p.Jira.IssueControls = nil
			}
			b, _ := json.Marshal(p)
			t.Setenv(trackerflow.ProfileEnv, string(b))
			t.Setenv("FULLSEND_GITLAB_POLLER_TOKEN", "testtoken")
			t.Setenv("FULLSEND_JIRA_TOKEN", "testtoken")
			t.Setenv("FULLSEND_JIRA_EMAIL", "test@example.com")
			t.Setenv("FULLSEND_JIRA_CLIENT_ID", "")
			t.Setenv("FULLSEND_JIRA_CLIENT_SECRET", "")
			if mode == "missingrole" {
				t.Setenv("FULLSEND_GITLAB_POLLER_TOKEN", "")
			}
			if mode == "missingjiracreds" {
				t.Setenv("FULLSEND_JIRA_TOKEN", "")
			}
			openJournal = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
				if mode == "journalunavailable" {
					return nil, nil, errors.New("unavailable")
				}
				return journal.New(nil, nil), nil, nil
			}
			exported := false
			exportContext = func(_ context.Context, e trackerpromotion.Exporter, actual trackerflow.Manifest, target, source string) (map[string]any, error) {
				exported = true
				if actual.Digest() != m.Digest() || target != "target" || source != "source" || e.Journal == nil || e.Authorize == nil || e.CheckIssue == nil || e.VerifyTracker == nil || e.VerifyPublication == nil {
					t.Fatal("trusted exporter wiring incomplete")
				}
				if mode == "revoked" {
					return nil, trackerflow.ErrAuthorization
				}
				return map[string]any{"issue_key": "KONFLUX-1", "target_id": "verified"}, nil
			}
			var output bytes.Buffer
			var out io.Writer = &output
			if mode == "outputfailed" {
				out = failWriter{}
			}
			err := run(context.Background(), argsFor(path), out)
			if mode == "accepted" {
				if err != nil {
					t.Fatal(err)
				}
				var result map[string]any
				if json.Unmarshal(output.Bytes(), &result) != nil || result["target_id"] != "verified" {
					t.Fatal("did not emit verified export")
				}
			} else if err == nil {
				t.Fatal("invalid wiring/revoked context accepted")
			}
			shouldExport := mode == "accepted" || mode == "revoked" || mode == "outputfailed"
			if exported != shouldExport {
				t.Fatalf("exported=%v mode=%s err=%v", exported, mode, err)
			}
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }
