// Package trackerworker admits one tracker-first attempt before ordinary Fullsend execution.
package trackerworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/trackerflow"
)

const ProfileEnv = "FULLSEND_TRACKER_WORKER_PROFILE"

// Profile is protected host configuration. Its canonical hash binds the dispatch.
type Profile struct {
	Agent          string            `json:"agent"`
	FullsendDir    string            `json:"fullsend_dir"`
	RunnerRevision string            `json:"runner_revision"`
	Image          string            `json:"image"`
	Model          string            `json:"model"`
	Effort         string            `json:"effort"`
	Files          map[string]string `json:"files"`
	AssessmentFile string            `json:"assessment_file"`
	ValidatorFile  string            `json:"validator_file"`
}

func (p Profile) Digest() string { return trackerflow.Hash(p) }
func Decode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("bounded structured input required")
	}
	return trackerflow.DecodeStrict(raw, v)
}

func Load(getenv func(string) string) (Profile, error) {
	var p Profile
	if err := Decode([]byte(getenv(ProfileEnv)), &p); err != nil {
		return p, err
	}
	if p.Agent == "" || strings.ContainsAny(p.Agent, "/\\\x00") || !filepath.IsAbs(p.FullsendDir) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(p.RunnerRevision) || !regexp.MustCompile(`^.+@sha256:[a-f0-9]{64}$`).MatchString(p.Image) || p.Model == "" || len(p.Files) < 3 || p.ValidatorFile == "" || p.Files[p.ValidatorFile] == "" || p.AssessmentFile == "" || filepath.Base(p.AssessmentFile) != p.AssessmentFile {
		return Profile{}, errors.New("invalid pinned worker profile")
	}
	for _, name := range []string{"config.yaml", "lock.yaml", "harness/" + p.Agent + ".yaml"} {
		if p.Files[name] == "" {
			return Profile{}, errors.New("worker configuration pins required")
		}
	}
	return p, nil
}
func (p Profile) CheckPins() error {
	root, e := filepath.EvalSymlinks(p.FullsendDir)
	if e != nil || root != filepath.Clean(p.FullsendDir) {
		return errors.New("worker configuration root must be real directory")
	}
	for name, want := range p.Files {
		if filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(want) {
			return errors.New("invalid worker file pin")
		}
		path := filepath.Join(root, name)
		actual, e := filepath.EvalSymlinks(path)
		if e != nil || actual != path {
			return errors.New("worker pinned resource missing or linked")
		}
		f, e := os.Open(path)
		if e != nil {
			return errors.New("worker pinned resource unavailable")
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, (16<<20)+1))
		_ = f.Close()
		if e != nil || n > 16<<20 || hex.EncodeToString(h.Sum(nil)) != want {
			return errors.New("worker resource integrity mismatch")
		}
	}
	return nil
}

// VerifySource compares actual origin, explicit remote branch, HEAD and clean state.
func VerifySource(ctx context.Context, dir string, r trackerflow.Request) error {
	git := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		b, e := cmd.Output()
		if e != nil {
			return "", errors.New("worker source verification failed")
		}
		return strings.TrimSpace(string(b)), nil
	}
	if _, e := git("check-ref-format", "--branch", r.Branch); e != nil {
		return e
	}
	origin, e := git("remote", "get-url", "origin")
	if e != nil {
		return e
	}
	if strings.TrimSuffix(origin, ".git") != strings.TrimSuffix(r.Repository, ".git") {
		return errors.New("worker source origin mismatch")
	}
	head, e := git("rev-parse", "--verify", "HEAD")
	if e != nil || head != r.SourceSHA {
		return errors.New("worker source revision mismatch")
	}
	branch, e := git("rev-parse", "--verify", "refs/remotes/origin/"+r.Branch)
	if e != nil || branch != r.SourceSHA {
		return errors.New("worker explicit branch mismatch")
	}
	// A named checkout must be the requested branch even when two branches
	// currently point at the same commit. Detached jobs bind through the exact
	// admitted remote ref and SHA above.
	currentBranch, branchErr := git("symbolic-ref", "--quiet", "--short", "HEAD")
	if branchErr == nil && currentBranch != r.Branch {
		return errors.New("worker checked-out branch mismatch")
	}
	if branchErr != nil {
		if _, err := git("rev-parse", "--verify", "HEAD"); err != nil {
			return err
		}
	}
	dirty, e := git("status", "--porcelain", "--untracked-files=all")
	if e != nil || dirty != "" {
		return errors.New("worker source must be clean")
	}
	return nil
}
