package journalhost

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/gitlabroles"
	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/stretchr/testify/require"
)

func trustedEnv(t *testing.T) map[string]string {
	t.Helper()
	p := Profile{Forge: "gitlab", BaseURL: "https://gitlab.example.com", Owner: "group/control", Repo: "fullsend", Branch: "fullsend-journal", Path: "state/journal.json", Role: "journal"}
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	return map[string]string{ProfileEnv: string(raw), forge.VarGitLabRoleRegistry: `{"roles":[{"name":"journal","credential":"own","capabilities":["write_repository"],"agents":["journal"]}]}`, gitlabroles.CustomSecretName("journal"): "journal-private-token"}
}
func getenv(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}
func TestLoadStrictTrustedProfile(t *testing.T) {
	env := trustedEnv(t)
	p, err := Load(getenv(env))
	require.NoError(t, err)
	require.Equal(t, journal.Location{Owner: "group/control", Repo: "fullsend", Branch: "fullsend-journal", Path: "state/journal.json"}, p.Location())
	for _, raw := range []string{"", strings.Repeat("x", 16385), "null", "[]", "{", `{"forge":`, env[ProfileEnv] + ` {}`, strings.Replace(env[ProfileEnv], `"forge":"gitlab"`, `"forge":"gitlab","forge":"github"`, 1), strings.Replace(env[ProfileEnv], `"forge":"gitlab"`, `"forge":"gitlab","token":"must-not-appear"`, 1), strings.Replace(env[ProfileEnv], `"forge":"gitlab"`, `"forge":1`, 1)} {
		env[ProfileEnv] = raw
		_, err = Load(getenv(env))
		require.Error(t, err)
		require.NotContains(t, err.Error(), "must-not-appear")
	}
}
func TestLoadRejectsUnsafeScope(t *testing.T) {
	env := trustedEnv(t)
	base, err := Load(getenv(env))
	require.NoError(t, err)
	mutations := []func(*Profile){func(p *Profile) { p.Forge = "github" }, func(p *Profile) { p.BaseURL = "http://gitlab.example.com" }, func(p *Profile) { p.BaseURL = "https://user:secret@gitlab.example.com" }, func(p *Profile) { p.BaseURL = "https://gitlab.example.com?token=secret" }, func(p *Profile) { p.BaseURL = "https://gitlab.example.com/path" }, func(p *Profile) { p.Owner = "group/../other" }, func(p *Profile) { p.Repo = "another/repo" }, func(p *Profile) { p.Branch = "../main" }, func(p *Profile) { p.Path = "../journal.json" }, func(p *Profile) { p.Path = "/journal.json" }, func(p *Profile) { p.Path = "journal.txt" }, func(p *Profile) { p.Role = "" }, func(p *Profile) { p.Owner = "" }}
	for _, mutate := range mutations {
		p := base
		mutate(&p)
		data, err := json.Marshal(p)
		require.NoError(t, err)
		env[ProfileEnv] = string(data)
		_, err = Load(getenv(env))
		require.Error(t, err)
		require.NotContains(t, err.Error(), "coder-secret")
		require.NotContains(t, err.Error(), "analyst-secret")
		require.NotContains(t, err.Error(), "ambient-secret")
	}
	t.Setenv(ProfileEnv, trustedEnv(t)[ProfileEnv])
	_, err = Load(nil)
	require.NoError(t, err)
}
func TestCredentialRequiresRegisteredCustomWriter(t *testing.T) {
	env := trustedEnv(t)
	p, err := Load(getenv(env))
	require.NoError(t, err)
	token, err := p.Credential(getenv(env))
	require.NoError(t, err)
	require.Equal(t, "journal-private-token", token)
	env[forge.SecretGitLabCoderToken] = "coder-secret"
	env[forge.SecretGitLabAnalystToken] = "analyst-secret"
	env[forge.SecretForgeToken] = "ambient-secret"
	env["GITLAB_TOKEN"] = "ambient-secret"
	for _, role := range []string{"coder", "analyst", "poller", "unregistered"} {
		bad := p
		bad.Role = role
		_, err = bad.Credential(getenv(env))
		require.Error(t, err)
		require.NotContains(t, err.Error(), "coder-secret")
		require.NotContains(t, err.Error(), "analyst-secret")
		require.NotContains(t, err.Error(), "ambient-secret")
	}
	env[forge.VarGitLabRoleRegistry] = `{"roles":[{"name":"journal","capabilities":["read_issues"]}]}`
	_, err = p.Credential(getenv(env))
	require.Error(t, err)
	env = trustedEnv(t)
	delete(env, gitlabroles.CustomSecretName("journal"))
	env["GITLAB_TOKEN"] = "ambient-secret"
	env[forge.SecretForgeToken] = "ambient-secret"
	_, err = p.Credential(getenv(env))
	require.Error(t, err)
}
func TestAuthorizerBindsCredentialScopeAndProtectedBranch(t *testing.T) {
	ctx := context.Background()
	env := trustedEnv(t)
	p, err := Load(getenv(env))
	require.NoError(t, err)
	fc := forge.NewFakeClient()
	fc.ProtectedBranches[p.Owner+"/"+p.Repo+"/"+p.Branch] = true
	authorize := p.Authorizer(fc, getenv(env), "journal-private-token")
	for _, action := range []string{"initialize", "read", "write"} {
		require.NoError(t, authorize(ctx, p.Location(), action))
	}
	wrong := p.Location()
	wrong.Repo = "unapproved"
	require.Error(t, authorize(ctx, wrong, "write"))
	require.Error(t, authorize(ctx, p.Location(), "delete"))
	env[gitlabroles.CustomSecretName("journal")] = "rotated-token"
	require.ErrorIs(t, authorize(ctx, p.Location(), "write"), gitlabroles.ErrIdentityMismatch)
	env[gitlabroles.CustomSecretName("journal")] = "journal-private-token"
	fc.ProtectedBranches[p.Owner+"/"+p.Repo+"/"+p.Branch] = false
	require.Error(t, authorize(ctx, p.Location(), "write"))
	fc.Errors["IsProtectedBranch"] = errors.New("server says journal-private-token")
	err = authorize(ctx, p.Location(), "write")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "journal-private-token")
	delete(env, gitlabroles.CustomSecretName("journal"))
	require.Error(t, authorize(ctx, p.Location(), "write"))
}
func TestOpenHasNoAmbientBackendFallback(t *testing.T) {
	env := trustedEnv(t)
	engine, backend, err := Open(getenv(env))
	require.NoError(t, err)
	require.NotNil(t, engine)
	require.NotNil(t, backend)
	delete(env, ProfileEnv)
	_, _, err = Open(getenv(env))
	require.Error(t, err)
	env = trustedEnv(t)
	delete(env, gitlabroles.CustomSecretName("journal"))
	env["GITLAB_TOKEN"] = "ambient"
	_, _, err = Open(getenv(env))
	require.Error(t, err)
}

func TestAuthorizerStopsWhenProtectedProfileChanges(t *testing.T) {
	env := trustedEnv(t)
	p, err := Load(getenv(env))
	require.NoError(t, err)
	fc := forge.NewFakeClient()
	fc.ProtectedBranches[p.Owner+"/"+p.Repo+"/"+p.Branch] = true
	authorize := p.Authorizer(fc, getenv(env), "journal-private-token")
	require.NoError(t, authorize(context.Background(), p.Location(), "write"))
	delete(env, ProfileEnv)
	require.Error(t, authorize(context.Background(), p.Location(), "write"))
}
