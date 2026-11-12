package trackerflow

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/fullsend-ai/fullsend/internal/gitlabroles"
)

const ProfileEnv = "FULLSEND_TRACKERFLOW_PROFILE"

// Profile is protected administrator-controlled installation state. It must not
// be loaded from a target checkout, manifest, model output or editable Jira issue.
type Profile struct {
	PolicyDigest     string         `json:"policy_digest"`
	ProfileDigest    string         `json:"profile_digest"`
	Agent            string         `json:"agent"`
	AllowedTargetIDs []string       `json:"allowed_target_ids"`
	Jira             JiraProfile    `json:"jira"`
	Control          ControlProfile `json:"control"`
}
type JiraProfile struct {
	BaseURL           string `json:"base_url"`
	APIURL            string `json:"api_url,omitempty"`
	Project           string `json:"project"`
	IssueTypeID       string `json:"issue_type_id"`
	AssigneeAccountID string `json:"assignee_account_id"`
	ActorAccountID    string `json:"actor_account_id"`
}
type ControlProfile struct {
	BaseURL      string    `json:"base_url"`
	Owner        string    `json:"owner"`
	Repository   string    `json:"repo"`
	WorkerRef    string    `json:"worker_ref"`
	DispatchRole string    `json:"dispatch_role"`
	LookupSince  time.Time `json:"lookup_since"`
}

func strictJSON(raw []byte, out any) error { return DecodeStrict(raw, out) }
func validOrigin(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/")
}
func LoadProfile(getenv func(string) string) (Profile, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	var p Profile
	raw := getenv(ProfileEnv)
	if len(raw) == 0 || len(raw) > 32768 || strictJSON([]byte(raw), &p) != nil {
		return p, errors.New("protected trackerflow profile required")
	}
	if !digest.MatchString(p.PolicyDigest) || !digest.MatchString(p.ProfileDigest) || !safeID.MatchString(p.Agent) || len(p.AllowedTargetIDs) == 0 || len(p.AllowedTargetIDs) > 100 || !validOrigin(p.Control.BaseURL) || p.Control.Owner == "" || p.Control.Repository == "" || p.Control.WorkerRef == "" || p.Control.DispatchRole == "" || p.Control.LookupSince.IsZero() || p.Jira.Project == "" || p.Jira.IssueTypeID == "" || p.Jira.AssigneeAccountID == "" || p.Jira.ActorAccountID == "" || !validOrigin(p.Jira.BaseURL) || (p.Jira.APIURL != "" && !validOrigin(p.Jira.APIURL)) {
		return Profile{}, errors.New("invalid protected trackerflow profile")
	}
	seen := map[string]bool{}
	for _, id := range p.AllowedTargetIDs {
		if !strings.HasPrefix(id, "target-") || !digest.MatchString(strings.TrimPrefix(id, "target-")) || seen[id] {
			return Profile{}, errors.New("invalid target allowlist")
		}
		seen[id] = true
	}
	return p, nil
}
func (p Profile) Credential(getenv func(string) string) (string, error) {
	s, e := gitlabroles.SelectAgent(p.Control.DispatchRole, p.Control.DispatchRole, getenv)
	if e != nil {
		return "", e
	}
	if string(s.Registration.Name) != p.Control.DispatchRole || !s.Registration.Has(gitlabroles.CapDispatchPipeline) {
		return "", errors.New("registered dispatch role required")
	}
	return s.Token(getenv)
}

// ProfileAuthority revalidates the protected profile, credential selection, Jira
// account and protected worker ref before each action. No human actor is synthesized.
type ProfileAuthority struct {
	Profile Profile
	Control forge.Client
	Jira    interface {
		GetMyself(context.Context) (*jira.User, error)
	}
	Getenv func(string) string
	Token  string
}

func (a ProfileAuthority) Authorize(ctx context.Context, m Manifest, t Target, action string) error {
	if action != "admit" && action != "publish" && action != "dispatch" {
		return ErrAuthorization
	}
	p, e := LoadProfile(a.Getenv)
	if e != nil || Hash(p) != Hash(a.Profile) || p.PolicyDigest != m.PolicyDigest || p.ProfileDigest != m.ProfileDigest || p.Agent != m.Agent || p.Jira.Project != m.Jira.Project || p.Jira.IssueTypeID != m.Jira.IssueTypeID || p.Jira.AssigneeAccountID != m.Jira.AssigneeAccountID {
		return ErrAuthorization
	}
	found := false
	for _, id := range p.AllowedTargetIDs {
		if id == TargetID(m.CaseID, t) {
			found = true
		}
	}
	if !found {
		return ErrAuthorization
	}
	token, e := p.Credential(a.Getenv)
	if e != nil || token == "" || token != a.Token {
		return ErrAuthorization
	}
	if a.Control == nil || a.Jira == nil {
		return ErrAuthorization
	}
	protected, e := a.Control.IsProtectedBranch(ctx, p.Control.Owner, p.Control.Repository, p.Control.WorkerRef)
	if e != nil || !protected {
		return ErrAuthorization
	}
	me, e := a.Jira.GetMyself(ctx)
	if e != nil || me == nil || me.AccountID != p.Jira.ActorAccountID {
		return ErrAuthorization
	}
	return nil
}
