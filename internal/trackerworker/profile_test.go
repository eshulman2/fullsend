package trackerworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/stretchr/testify/require"
)

func pinnedProfile(t *testing.T) Profile {
	t.Helper()
	root := t.TempDir()
	p := Profile{Agent: "cve", FullsendDir: root, RunnerRevision: strings.Repeat("a", 40), Image: "example.invalid/sandbox@sha256:" + strings.Repeat("b", 64), Model: "example/model", Effort: "low", Files: map[string]string{}, AssessmentFile: "assessment.json", ValidatorFile: "validate"}
	for _, name := range []string{"config.yaml", "lock.yaml", "harness/cve.yaml", "validate"} {
		full := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0700))
		content := []byte("trusted " + name)
		require.NoError(t, os.WriteFile(full, content, 0600))
		sum := sha256.Sum256(content)
		p.Files[name] = hex.EncodeToString(sum[:])
	}
	return p
}
func localSource(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	gitFor(t, dir, "init", "--initial-branch=release/1")
	gitFor(t, dir, "config", "user.name", "Test Worker")
	gitFor(t, dir, "config", "user.email", "test@example.invalid")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0600))
	gitFor(t, dir, "add", "package.json")
	gitFor(t, dir, "commit", "-m", "fixture")
	gitFor(t, dir, "remote", "add", "origin", "https://github.com/example/repo.git")
	sha := gitFor(t, dir, "rev-parse", "HEAD")
	gitFor(t, dir, "update-ref", "refs/remotes/origin/release/1", sha)
	return dir, sha
}
func gitFor(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}
func TestWorkerProfilePinsAndStrictInput(t *testing.T) {
	p := pinnedProfile(t)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	loaded, err := Load(func(string) string { return string(raw) })
	require.NoError(t, err)
	require.Equal(t, p.Digest(), loaded.Digest())
	require.NoError(t, loaded.CheckPins())
	for _, data := range [][]byte{nil, []byte(strings.Repeat("x", (1<<20)+1)), []byte(`{}` + ` {}`), []byte(`{"unknown":true}`), []byte("bad")} {
		var value Profile
		require.Error(t, Decode(data, &value))
	}
	for _, change := range []func(*Profile){func(p *Profile) { p.Agent = "../cve" }, func(p *Profile) { p.FullsendDir = "relative" }, func(p *Profile) { p.RunnerRevision = "main" }, func(p *Profile) { p.Image = "sandbox:latest" }, func(p *Profile) { p.Model = "" }, func(p *Profile) { p.AssessmentFile = "../assessment.json" }, func(p *Profile) { delete(p.Files, "config.yaml"); p.Files["extra"] = "fake" }} {
		candidate := p
		candidate.Files = map[string]string{}
		for key, value := range p.Files {
			candidate.Files[key] = value
		}
		change(&candidate)
		raw, err := json.Marshal(candidate)
		require.NoError(t, err)
		_, err = Load(func(string) string { return string(raw) })
		require.Error(t, err)
	}
}
func TestPinnedResourceRejections(t *testing.T) {
	for _, mode := range []string{"root-symlink", "traversal", "invalid-digest", "missing", "linked", "changed", "directory", "too-large"} {
		t.Run(mode, func(t *testing.T) {
			p := pinnedProfile(t)
			path := filepath.Join(p.FullsendDir, "config.yaml")
			switch mode {
			case "root-symlink":
				link := filepath.Join(t.TempDir(), "profile")
				require.NoError(t, os.Symlink(p.FullsendDir, link))
				p.FullsendDir = link
			case "traversal":
				p.Files["../outside"] = strings.Repeat("a", 64)
			case "invalid-digest":
				p.Files["config.yaml"] = "not-a-digest"
			case "missing":
				require.NoError(t, os.Remove(path))
			case "linked":
				target := filepath.Join(t.TempDir(), "config")
				require.NoError(t, os.WriteFile(target, []byte("other"), 0600))
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(target, path))
			case "changed":
				require.NoError(t, os.WriteFile(path, []byte("mutated"), 0600))
			case "directory":
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Mkdir(path, 0700))
			case "too-large":
				require.NoError(t, os.Truncate(path, (16<<20)+1))
			}
			require.Error(t, p.CheckPins())
		})
	}
}
func TestVerifyActualSourceAndExplicitRef(t *testing.T) {
	dir, sha := localSource(t)
	r := trackerflow.Request{Repository: "https://github.com/example/repo", Branch: "release/1", SourceSHA: sha}
	require.NoError(t, VerifySource(context.Background(), dir, r))
	wrong := r
	wrong.Repository = "https://github.com/other/repo"
	require.Error(t, VerifySource(context.Background(), dir, wrong))
	wrong = r
	wrong.SourceSHA = strings.Repeat("0", 40)
	require.Error(t, VerifySource(context.Background(), dir, wrong))
	wrong = r
	wrong.Branch = "missing"
	require.Error(t, VerifySource(context.Background(), dir, wrong))
	wrong.Branch = "../main"
	require.Error(t, VerifySource(context.Background(), dir, wrong))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "untracked"), []byte("dirty"), 0600))
	require.Error(t, VerifySource(context.Background(), dir, r))
	require.NoError(t, os.Remove(filepath.Join(dir, "untracked")))
	gitFor(t, dir, "checkout", "-b", "main")
	require.Error(t, VerifySource(context.Background(), dir, r))
	gitFor(t, dir, "checkout", "--detach", sha)
	require.NoError(t, VerifySource(context.Background(), dir, r))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, VerifySource(ctx, dir, r))
	require.Error(t, VerifySource(context.Background(), t.TempDir(), r))
}
