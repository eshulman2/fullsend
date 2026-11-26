// Package trackerflow is a tracker-first domain adapter. It keeps Fullsend's
// worker interface single-target and uses the journal for admission and recovery.
package trackerflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var ErrAmbiguous = errors.New("external acceptance unresolved")
var ErrAuthorization = errors.New("target action not authorized")
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var sha = regexp.MustCompile(`^[a-f0-9]{40}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var jiraKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*-[1-9][0-9]*$`)

// Receipt references may bind a retained artifact to its canonical SHA256.
// Keep the legacy reference alphabet; admit only the structured hash fragment.
var receiptReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/+-]*(?:#sha256=[a-f0-9]{64})?$`)

// Manifest is reviewed host input, never worker or Jira-authored configuration.
type Manifest struct {
	SchemaVersion int         `json:"schema_version"`
	CaseID        string      `json:"case_id"`
	Revision      string      `json:"revision"`
	Public        bool        `json:"public"`
	Advisory      string      `json:"advisory"`
	AdvisoryID    string      `json:"advisory_id,omitempty"`
	PolicyDigest  string      `json:"policy_digest"`
	ProfileDigest string      `json:"profile_digest"`
	Agent         string      `json:"agent"`
	Jira          Destination `json:"jira"`
	Limits        Limits      `json:"limits"`
	Targets       []Target    `json:"targets"`
}
type Destination struct {
	Project           string `json:"project"`
	IssueTypeID       string `json:"issue_type_id"`
	AssigneeAccountID string `json:"assignee_account_id"`
}
type Limits struct {
	MaxTargets    int `json:"max_targets"`
	MaxConcurrent int `json:"max_concurrent"`
	MaxAttempts   int `json:"max_attempts"`
}
type Target struct {
	// DomainContext is reviewed mapping/policy input, never Jira or model output.
	DomainContext json.RawMessage   `json:"domain_context,omitempty"`
	Repository    string            `json:"repository"`
	Branch        string            `json:"branch"`
	SourceSHA     string            `json:"source_sha"`
	Component     string            `json:"component"`
	Product       string            `json:"product"`
	Release       string            `json:"release"`
	Stream        string            `json:"stream"`
	Owner         string            `json:"owner"`
	BlockedReason string            `json:"blocked_reason,omitempty"`
	Intake        map[string]string `json:"intake,omitempty"`
}

// TargetID excludes source SHA: a new source revision is an attempt on the same tracker.
func TargetID(caseID string, t Target) string {
	return "target-" + Hash([]string{caseID, t.Repository, t.Branch, t.Component, t.Product, t.Release, t.Stream})
}
func Hash(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (m Manifest) Digest() string { return Hash(m) }
func (m Manifest) Validate() error {
	if m.SchemaVersion != 1 || !safeID.MatchString(m.CaseID) || m.Revision == "" || !m.Public || m.Advisory == "" || !digest.MatchString(m.PolicyDigest) || !digest.MatchString(m.ProfileDigest) || !safeID.MatchString(m.Agent) {
		return errors.New("invalid trusted manifest identity or public disclosure")
	}
	if m.AdvisoryID != "" && !regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`).MatchString(m.AdvisoryID) {
		return errors.New("invalid canonical advisory identity")
	}
	if !regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(m.Jira.Project) || !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(m.Jira.IssueTypeID) || m.Jira.AssigneeAccountID == "" {
		return errors.New("invalid Jira destination")
	}
	if m.Limits.MaxTargets < 1 || m.Limits.MaxTargets > 100 || len(m.Targets) == 0 || len(m.Targets) > m.Limits.MaxTargets || m.Limits.MaxConcurrent < 1 || m.Limits.MaxConcurrent > m.Limits.MaxTargets || m.Limits.MaxAttempts < 1 || m.Limits.MaxAttempts > 20 {
		return errors.New("invalid persistent work bounds")
	}
	seen := map[string]bool{}
	for _, t := range m.Targets {
		if !validBranch(t.Branch) || t.Product == "" || t.Release == "" || t.Component == "" || t.Stream == "" || t.Owner == "" {
			return errors.New("invalid explicit target mapping")
		}
		if !validRepository(t.Repository) {
			return errors.New("target repository must be canonical credential-free HTTPS")
		}
		if t.BlockedReason == "" && !sha.MatchString(t.SourceSHA) {
			return errors.New("target source revision must be pinned")
		}
		id := TargetID(m.CaseID, t)
		if seen[id] {
			return errors.New("duplicate target identity")
		}
		seen[id] = true
	}
	return nil
}

type Request struct {
	OperationID    string `json:"operation_id"`
	CaseID         string `json:"case_id"`
	TargetID       string `json:"target_id"`
	JiraKey        string `json:"jira_key"`
	Repository     string `json:"repository"`
	Branch         string `json:"branch"`
	SourceSHA      string `json:"source_sha"`
	Agent          string `json:"agent"`
	ProfileDigest  string `json:"profile_digest"`
	PolicyDigest   string `json:"policy_digest"`
	ManifestDigest string `json:"manifest_digest"`
}

func (r Request) Digest() string { return Hash(r) }
func (r Request) Validate() error {
	if !safeID.MatchString(r.OperationID) || !safeID.MatchString(r.CaseID) || (!strings.HasPrefix(r.TargetID, "target-") || !digest.MatchString(strings.TrimPrefix(r.TargetID, "target-"))) || !jiraKey.MatchString(r.JiraKey) || !sha.MatchString(r.SourceSHA) || !digest.MatchString(r.ProfileDigest) || !digest.MatchString(r.PolicyDigest) || !digest.MatchString(r.ManifestDigest) || !validBranch(r.Branch) || !validRepository(r.Repository) || !safeID.MatchString(r.Agent) {
		return errors.New("invalid dispatch request")
	}
	return nil
}

type RunReceipt struct {
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
	RunID         string `json:"run_id"`
	RunURL        string `json:"run_url"`
	State         string `json:"state"`
}
type Assessment struct {
	RequestDigest string `json:"request_digest"`
	Outcome       string `json:"outcome"`
	ReceiptRef    string `json:"receipt_ref"`
}

func (a Assessment) Validate(r Request) error {
	if a.RequestDigest != r.Digest() || len(a.ReceiptRef) > 2048 || !receiptReference.MatchString(a.ReceiptRef) {
		return errors.New("assessment input binding mismatch")
	}
	switch a.Outcome {
	case "affected", "not_affected", "uncertain", "failed":
		return nil
	}
	return errors.New("unsupported assessment outcome")
}

type TrackerReceipt struct {
	Key     string `json:"key"`
	ID      string `json:"id"`
	Binding string `json:"binding"`
}

// Authorizer rechecks current host policy before each external effect. A manifest
// string, editable tracker or successful authentication is not this capability.
type Authorizer interface {
	Authorize(context.Context, Manifest, Target, string) error
}

// Tracker must verify typed case/target/destination provenance on every candidate.
type Tracker interface {
	Find(context.Context, Manifest, Target) ([]TrackerReceipt, error)
	Create(context.Context, Manifest, Target) (TrackerReceipt, error)
	Verify(context.Context, Manifest, Target, TrackerReceipt) error
}

// Scheduler submits ordinary authorized single-target runs and separately returns
// assessment receipts. Empty lookup after a possible submission is always ambiguous.
type Scheduler interface {
	Submit(context.Context, Request) (RunReceipt, error)
	Reconcile(context.Context, Request, *RunReceipt) (RunReceipt, *Assessment, error)
}

type Attempt struct {
	Request     Request                       `json:"request"`
	Receipt     *RunReceipt                   `json:"receipt,omitempty"`
	Assessment  *Assessment                   `json:"assessment,omitempty"`
	Publication *AssessmentPublicationReceipt `json:"publication,omitempty"`
	State       string                        `json:"state"`
}
type TargetState struct {
	Target   Target          `json:"target"`
	Tracker  *TrackerReceipt `json:"tracker,omitempty"`
	Attempts []Attempt       `json:"attempts"`
	Status   string          `json:"status"`
	Blocker  string          `json:"blocker,omitempty"`
}
type CaseState struct {
	ManifestDigest string                 `json:"manifest_digest"`
	Required       []string               `json:"required"`
	Targets        map[string]TargetState `json:"targets"`
}
type Report struct {
	CaseID   string                 `json:"case_id"`
	Complete bool                   `json:"complete"`
	Targets  map[string]TargetState `json:"targets"`
	Pending  int                    `json:"pending"`
	Assessed int                    `json:"assessed"`
}

func terminal(s string) bool { return s == "assessed" || s == "failed" || s == "cancelled" }
func active(s CaseState) int {
	n := 0
	for _, t := range s.Targets {
		for _, a := range t.Attempts {
			if !terminal(a.State) {
				n++
			}
		}
	}
	return n
}
func receiptValid(r Request, v RunReceipt) error {
	if v.OperationID != r.OperationID || v.RequestDigest != r.Digest() || v.RunID == "" || v.RunURL == "" {
		return fmt.Errorf("scheduler receipt identity mismatch")
	}
	switch v.State {
	case "accepted", "running", "failed", "cancelled", "completed":
		return nil
	}
	return errors.New("invalid scheduler state")
}

// WorkerState is the separately admitted journal record keyed by OperationID.
// The worker claims this record, while the controller owns the parent case.
// State progresses admitted -> running -> assessed/failed. Receipt is scheduling
// identity; Assessment is separately validated evidence, never inferred from CI success.
type WorkerState struct {
	Request    Request     `json:"request"`
	State      string      `json:"state"`
	RunReceipt *RunReceipt `json:"run_receipt,omitempty"`
	Assessment *Assessment `json:"assessment,omitempty"`
}

func validRepository(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(u.Path, "/") || u.String() != raw {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "." || part == ".." || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(part) {
			return false
		}
	}
	return true
}
func validBranch(branch string) bool {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./@+-]{0,254}$`).MatchString(branch) || strings.Contains(branch, "..") || strings.Contains(branch, "@{") {
		return false
	}
	for _, part := range strings.Split(branch, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
