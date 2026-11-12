package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/stretchr/testify/require"
)

func TestCheckManifestHasNoNetworkOrCredentialRequirement(t *testing.T) {
	m := trackerflow.Manifest{SchemaVersion: 1, CaseID: "case-1", Revision: "mapping-1", Public: true, Advisory: "CVE-2021-23337", PolicyDigest: strings.Repeat("a", 64), ProfileDigest: strings.Repeat("b", 64), Agent: "triage", Jira: trackerflow.Destination{Project: "PROJ", IssueTypeID: "10001", AssigneeAccountID: "account-1"}, Limits: trackerflow.Limits{MaxTargets: 2, MaxConcurrent: 1, MaxAttempts: 2}, Targets: []trackerflow.Target{{Repository: "https://github.com/example/repo", Branch: "release/1", SourceSHA: strings.Repeat("c", 40), Component: "package.json", Product: "demo", Release: "1", Stream: "1", Owner: "security"}}}
	path := filepath.Join(t.TempDir(), "manifest.json")
	raw, e := json.Marshal(m)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	var output bytes.Buffer
	require.NoError(t, run(context.Background(), []string{"--manifest", path, "--check"}, &output))
	require.Contains(t, output.String(), m.Digest())
	require.Contains(t, output.String(), trackerflow.TargetID(m.CaseID, m.Targets[0]))
	t.Setenv(trackerflow.ProfileEnv, "")
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--owner", "invocation"}, &output))
	duplicate := strings.Replace(string(raw), `"case_id":"case-1"`, `"case_id":"case-1","case_id":"other"`, 1)
	require.NoError(t, os.WriteFile(path, []byte(duplicate), 0600))
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--check"}, &output))
	require.NoError(t, os.WriteFile(path, []byte(`{"extra":true}`), 0600))
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--check"}, &output))
	require.NoError(t, os.WriteFile(path, append(raw, []byte(` {}`)...), 0600))
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--check"}, &output))
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", 1<<20+1)), 0600))
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--check"}, &output))
	require.Error(t, run(context.Background(), nil, &output))
	require.Error(t, run(context.Background(), []string{"--manifest", path + "missing"}, &output))
	require.Error(t, run(context.Background(), []string{"--unknown"}, &output))
}

func TestProductionWiringRejectsUnadmittedManifestBeforeRemoteEffects(t *testing.T) {
	m := trackerflow.Manifest{SchemaVersion: 1, CaseID: "case-1", Revision: "mapping-1", Public: true, Advisory: "CVE-2021-23337", PolicyDigest: strings.Repeat("a", 64), ProfileDigest: strings.Repeat("b", 64), Agent: "triage", Jira: trackerflow.Destination{Project: "PROJ", IssueTypeID: "10001", AssigneeAccountID: "account-1"}, Limits: trackerflow.Limits{MaxTargets: 2, MaxConcurrent: 1, MaxAttempts: 2}, Targets: []trackerflow.Target{{Repository: "https://github.com/example/repo", Branch: "release/1", SourceSHA: strings.Repeat("c", 40), Component: "package.json", Product: "demo", Release: "1", Stream: "1", Owner: "security"}}}
	path := filepath.Join(t.TempDir(), "manifest.json")
	raw, e := json.Marshal(m)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	profile := trackerflow.Profile{PolicyDigest: strings.Repeat("d", 64), ProfileDigest: m.ProfileDigest, Agent: m.Agent, AllowedTargetIDs: []string{trackerflow.TargetID(m.CaseID, m.Targets[0])}, Jira: trackerflow.JiraProfile{BaseURL: "https://jira.example", Project: m.Jira.Project, IssueTypeID: m.Jira.IssueTypeID, AssigneeAccountID: m.Jira.AssigneeAccountID, ActorAccountID: "actor"}, Control: trackerflow.ControlProfile{BaseURL: "https://gitlab.example", Owner: "group", Repository: "control", WorkerRef: "main", DispatchRole: "poller", LookupSince: time.Now()}}
	raw, e = json.Marshal(profile)
	require.NoError(t, e)
	t.Setenv(trackerflow.ProfileEnv, string(raw))
	t.Setenv("FULLSEND_GITLAB_POLLER_TOKEN", "synthetic-poller")
	t.Setenv("FULLSEND_JIRA_TOKEN", "synthetic-jira")
	t.Setenv("FULLSEND_JIRA_CLIENT_ID", "")
	t.Setenv("FULLSEND_JIRA_CLIENT_SECRET", "")
	t.Setenv("FULLSEND_JOURNAL_PROFILE", `{"forge":"gitlab","base_url":"https://gitlab.example","owner":"group","repo":"control","branch":"journal","path":"journal.json","role":"journal"}`)
	t.Setenv("FULLSEND_GITLAB_ROLE_REGISTRY", `{"roles":[{"name":"journal","credential":"own","capabilities":["write_repository"],"agents":["journal"]}]}`)
	t.Setenv("FULLSEND_GITLAB_ROLE_JOURNAL_TOKEN", "synthetic-journal")
	var out bytes.Buffer
	require.ErrorIs(t, run(context.Background(), []string{"--manifest", path, "--owner", "invocation"}, &out), trackerflow.ErrAuthorization)
	t.Setenv("FULLSEND_JOURNAL_PROFILE", "")
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--owner", "invocation"}, &out))
	t.Setenv("FULLSEND_JIRA_TOKEN", "")
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--owner", "invocation"}, &out))
	t.Setenv("FULLSEND_GITLAB_POLLER_TOKEN", "")
	require.Error(t, run(context.Background(), []string{"--manifest", path, "--owner", "invocation"}, &out))
}

func TestHelpWithoutCredentials(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "manifest") {
		t.Fatal("help did not describe manifest")
	}
}
