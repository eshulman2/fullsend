package trackerflow

import (
	"context"
	"strings"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/stretchr/testify/require"
)

func TestProtectedScopeRequiresExactCompleteMapping(t *testing.T) {
	m := manifest()
	target := m.Targets[0]
	p := protectedProfile(m)
	p.AllowedTargetIDs = nil
	p.AllowedTargetScopes = []TargetScope{scopeFor(target)}
	load := func(profile Profile) error {
		_, err := LoadProfile(func(key string) string {
			if key == ProfileEnv {
				return string(marshal(profile))
			}
			return ""
		})
		return err
	}
	require.NoError(t, load(p))
	require.True(t, p.allowsTarget(m.CaseID, target))
	require.True(t, p.allowsTarget("another-case", target))
	next := target
	next.SourceSHA = strings.Repeat("e", 40)
	require.True(t, p.allowsTarget("another-case", next), "source identity is bound per manifest, never picked by scope")
	for _, field := range []string{"repository", "branch", "component", "product", "release", "stream", "owner"} {
		t.Run(field, func(t *testing.T) {
			changed := target
			switch field {
			case "repository":
				changed.Repository = "https://github.com/other/repo"
			case "branch":
				changed.Branch = "other"
			case "component":
				changed.Component = "other"
			case "product":
				changed.Product = "other"
			case "release":
				changed.Release = "other"
			case "stream":
				changed.Stream = "other"
			case "owner":
				changed.Owner = "other"
			}
			require.False(t, p.allowsTarget(m.CaseID, changed))
		})
	}
	for _, mode := range []string{"none", "both", "duplicate", "too-many", "repository", "branch", "empty", "wildcard", "space", "long"} {
		t.Run(mode, func(t *testing.T) {
			bad := p
			bad.AllowedTargetScopes = append([]TargetScope(nil), p.AllowedTargetScopes...)
			switch mode {
			case "none":
				bad.AllowedTargetScopes = nil
			case "both":
				bad.AllowedTargetIDs = []string{TargetID(m.CaseID, target)}
				require.False(t, bad.allowsTarget(m.CaseID, target))
			case "duplicate":
				bad.AllowedTargetScopes = append(bad.AllowedTargetScopes, bad.AllowedTargetScopes[0])
			case "too-many":
				bad.AllowedTargetScopes = make([]TargetScope, 101)
			case "repository":
				bad.AllowedTargetScopes[0].Repository = "https://token@github.com/example/repo"
			case "branch":
				bad.AllowedTargetScopes[0].Branch = "../bad"
			case "empty":
				bad.AllowedTargetScopes[0].Owner = ""
			case "wildcard":
				bad.AllowedTargetScopes[0].Component = "*"
			case "space":
				bad.AllowedTargetScopes[0].Product = "ambiguous product"
			case "long":
				bad.AllowedTargetScopes[0].Owner = strings.Repeat("a", 513)
			}
			require.Error(t, load(bad))
		})
	}
	legacy := protectedProfile(m)
	require.True(t, legacy.allowsTarget(m.CaseID, target))
	require.False(t, legacy.allowsTarget("another-case", target))
}

func TestScopeAuthorityStillRechecksProtectedProfileAndTracker(t *testing.T) {
	m := manifest()
	p := protectedProfile(m)
	p.AllowedTargetIDs = nil
	p.AllowedTargetScopes = []TargetScope{scopeFor(m.Targets[0])}
	env := map[string]string{ProfileEnv: string(marshal(p)), "FULLSEND_GITLAB_POLLER_TOKEN": "secret"}
	getenv := func(k string) string { return env[k] }
	control := forge.NewFakeClient()
	control.ProtectedBranches["group/control/main"] = true
	api := &jiraFake{me: "actor"}
	a := ProfileAuthority{Profile: p, Control: control, Jira: api, Getenv: getenv, Token: "secret"}
	m.CaseID = "another-case"
	require.NoError(t, a.Authorize(context.Background(), m, m.Targets[0], "admit"))
	changed := m.Targets[0]
	changed.Owner = "other"
	require.ErrorIs(t, a.Authorize(context.Background(), m, changed, "admit"), ErrAuthorization)
	api.me = "other"
	require.ErrorIs(t, a.Authorize(context.Background(), m, m.Targets[0], "admit"), ErrAuthorization)
	api.me = "actor"
	m.PolicyDigest = strings.Repeat("f", 64)
	require.ErrorIs(t, a.Authorize(context.Background(), m, m.Targets[0], "admit"), ErrAuthorization)
}

func TestWorkerScopeRequiresCurrentParentAndJira(t *testing.T) {
	m, target, api, tracker, receipt := guardedFixture(t)
	r := request()
	r.TargetID = TargetID(m.CaseID, target)
	r.ManifestDigest = m.Digest()
	state := CaseState{ManifestDigest: r.ManifestDigest, Required: []string{r.TargetID}, Targets: map[string]TargetState{r.TargetID: {Target: target, Tracker: &receipt, Attempts: []Attempt{{Request: r, State: "accepted"}}}}}
	record := &journal.Record{Binding: r.ManifestDigest, Data: marshal(state)}
	p := Profile{Agent: r.Agent, PolicyDigest: r.PolicyDigest, ProfileDigest: r.ProfileDigest, AllowedTargetScopes: []TargetScope{scopeFor(target)}, Jira: JiraProfile{Project: m.Jira.Project, IssueTypeID: m.Jira.IssueTypeID, AssigneeAccountID: m.Jira.AssigneeAccountID, IssueControls: publicControls()}}
	require.NoError(t, CheckWorkerIssue(context.Background(), guardParent{record}, p, tracker, r))
	p.AllowedTargetScopes[0].Owner = "other"
	require.ErrorIs(t, CheckWorkerIssue(context.Background(), guardParent{record}, p, tracker, r), ErrAuthorization)
	p.AllowedTargetScopes[0] = scopeFor(target)
	delete(api.properties, IntakeProperty)
	require.Error(t, CheckWorkerIssue(context.Background(), guardParent{record}, p, tracker, r))
}
