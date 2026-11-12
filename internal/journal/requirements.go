package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// Requirement binds a mutation to another record's currently admitted inputs
// and exact state. The same document CAS protects both records against races.
type Requirement struct {
	ID         string
	Binding    string
	DataDigest string
}

type requiredBackend struct {
	Backend
	requirement Requirement
}

// RequireRecord returns an engine whose mutations require the observed parent
// admission. Reads remain available for recovery when the parent has changed.
func (e *Engine) RequireRecord(r Requirement) (*Engine, error) {
	if e == nil || e.backend == nil || !identity.MatchString(r.ID) || r.Binding == "" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.DataDigest) {
		return nil, ErrBinding
	}
	return New(&requiredBackend{Backend: e.backend, requirement: r}, e.clock), nil
}

func (b *requiredBackend) CompareAndSwap(ctx context.Context, rev string, d Document) (string, error) {
	r, ok := d.Records[b.requirement.ID]
	if !ok || r.Binding != b.requirement.Binding {
		return "", ErrBinding
	}
	sum := sha256.Sum256(r.Data)
	if hex.EncodeToString(sum[:]) != b.requirement.DataDigest {
		return "", ErrBinding
	}
	return b.Backend.CompareAndSwap(ctx, rev, d)
}
