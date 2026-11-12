// Package journalhost binds storage to administrator-controlled host policy.
package journalhost

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/forge"
	gl "github.com/fullsend-ai/fullsend/internal/forge/gitlab"
	"github.com/fullsend-ai/fullsend/internal/gitlabroles"
	"github.com/fullsend-ai/fullsend/internal/journal"
)

const ProfileEnv = "FULLSEND_JOURNAL_PROFILE"

// Profile is protected host installation state, never source or tracker content.
type Profile struct {
	Forge   string `json:"forge"`
	BaseURL string `json:"base_url"`
	Owner   string `json:"owner"`
	Repo    string `json:"repo"`
	Branch  string `json:"branch"`
	Path    string `json:"path"`
	Role    string `json:"role"`
}

func Load(getenv func(string) string) (Profile, error) {
	var p Profile
	if getenv == nil {
		getenv = os.Getenv
	}
	raw := getenv(ProfileEnv)
	if len(raw) == 0 || len(raw) > 16384 {
		return p, errors.New("protected journal profile required")
	}
	// All profile members are scalars. Reject duplicate keys before typed
	// decoding, rather than silently accepting the last security scope.
	keys := json.NewDecoder(strings.NewReader(raw))
	token, err := keys.Token()
	if err != nil || token != json.Delim('{') {
		return p, errors.New("invalid protected journal profile")
	}
	seen := map[string]bool{}
	for keys.More() {
		key, err := keys.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return p, errors.New("invalid protected journal profile")
		}
		seen[name] = true
		var value json.RawMessage
		if err = keys.Decode(&value); err != nil {
			return p, errors.New("invalid protected journal profile")
		}
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Profile{}, errors.New("invalid protected journal profile")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Profile{}, errors.New("invalid protected journal profile")
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || p.Forge != "gitlab" || p.Owner == "" || p.Repo == "" || p.Branch == "" || p.Path == "" || p.Role == "" {
		return Profile{}, errors.New("invalid protected journal profile")
	}
	if strings.Contains(p.Repo, "/") || path.Clean(p.Path) != p.Path || strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "../") || !strings.HasSuffix(p.Path, ".json") || strings.ContainsAny(p.Path, "\\%?#\r\n") || strings.ContainsAny(p.Branch, " \\%?#\r\n~^:*") || strings.Contains(p.Branch, "..") || strings.HasPrefix(p.Branch, "/") || strings.HasSuffix(p.Branch, "/") || strings.Contains(p.Branch, "@{") {
		return Profile{}, errors.New("invalid protected journal scope")
	}
	for _, part := range strings.Split(p.Owner+"/"+p.Repo, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\%?#\r\n") {
			return Profile{}, errors.New("invalid protected journal scope")
		}
	}
	return p, nil
}
func (p Profile) Location() journal.Location {
	return journal.Location{Owner: p.Owner, Repo: p.Repo, Branch: p.Branch, Path: p.Path}
}

// Credential refuses built-in roles: journal writes do not widen Analyst or Poller.
func (p Profile) Credential(getenv func(string) string) (string, error) {
	sel, err := gitlabroles.SelectAgent(p.Role, p.Role, getenv)
	if err != nil {
		return "", err
	}
	if string(sel.Registration.Name) != p.Role || sel.Registration.Kind != gitlabroles.RoleKindCustom || !sel.Registration.Has(gitlabroles.CapWriteRepository) {
		return "", errors.New("registered journal writer role required")
	}
	return sel.Token(getenv)
}
func (p Profile) Authorizer(client forge.Client, getenv func(string) string, authenticatingToken string) journal.AuthorizeFunc {
	return func(ctx context.Context, loc journal.Location, action string) error {
		if loc != p.Location() || (action != "read" && action != "write" && action != "initialize") {
			return errors.New("journal scope denied")
		}
		currentProfile, err := Load(getenv)
		if err != nil || currentProfile != p {
			return errors.New("journal host profile changed")
		}
		current, err := p.Credential(getenv)
		if err != nil {
			return err
		}
		if client == nil || authenticatingToken == "" || subtle.ConstantTimeCompare([]byte(current), []byte(authenticatingToken)) != 1 {
			return gitlabroles.ErrIdentityMismatch
		}
		protected, err := client.IsProtectedBranch(ctx, p.Owner, p.Repo, p.Branch)
		if err != nil {
			return errors.New("journal branch protection could not be verified")
		}
		if !protected {
			return errors.New("journal requires protected control branch")
		}
		return nil
	}
}

// Open never falls back to an ambient GITLAB_TOKEN or local-only backend.
func Open(getenv func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
	p, err := Load(getenv)
	if err != nil {
		return nil, nil, err
	}
	token, err := p.Credential(getenv)
	if err != nil {
		return nil, nil, err
	}
	client, err := gl.New(token, gl.WithBaseURL(p.BaseURL))
	if err != nil {
		return nil, nil, errors.New("journal connection unavailable")
	}
	backend, err := journal.NewForgeBackend(client, p.Location(), p.Authorizer(client, getenv, token))
	if err != nil {
		return nil, nil, errors.New("journal profile rejected")
	}
	return journal.New(backend, nil), backend, nil
}
