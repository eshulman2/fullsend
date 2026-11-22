package journal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/forge"
)

type Location struct{ Owner, Repo, Branch, Path string }

// AuthorizeFunc checks independently configured trusted host identity and scope.
// Journal contents are never proof of authorization. Assessment sandboxes do not receive this capability.
type AuthorizeFunc func(context.Context, Location, string) error

type ForgeBackend struct {
	client    forge.Client
	location  Location
	authorize AuthorizeFunc
}

func NewForgeBackend(client forge.Client, location Location, authorize AuthorizeFunc) (*ForgeBackend, error) {
	if client == nil || authorize == nil || location.Owner == "" || location.Repo == "" || location.Branch == "" || location.Path == "" || strings.HasPrefix(location.Path, "/") || path.Clean(location.Path) != location.Path || strings.HasPrefix(location.Path, "../") || !strings.HasSuffix(location.Path, ".json") {
		return nil, ErrIntegrity
	}
	return &ForgeBackend{client: client, location: location, authorize: authorize}, nil
}
func (b *ForgeBackend) Initialize(ctx context.Context) error {
	if err := b.authorize(ctx, b.location, "initialize"); err != nil {
		return err
	}
	// Requiring an existing branch avoids silently constructing a control boundary.
	if _, err := b.client.GetBranchRef(ctx, b.location.Owner, b.location.Repo, b.location.Branch); err != nil {
		return err
	}
	content, err := Encode(Empty())
	if err != nil {
		return err
	}
	err = b.client.WriteFileIfRevision(ctx, b.location.Owner, b.location.Repo, b.location.Branch, b.location.Path, "", "Initialize Fullsend journal [skip ci]", content)
	if errors.Is(err, forge.ErrConflict) {
		return ErrConflict
	}
	return conflict(err)
}
func (b *ForgeBackend) Load(ctx context.Context) (Document, string, error) {
	if err := b.authorize(ctx, b.location, "read"); err != nil {
		return Document{}, "", nonretryableReadError(err)
	}
	data, rev, err := b.client.ReadVersionedFile(ctx, b.location.Owner, b.location.Repo, b.location.Branch, b.location.Path)
	if err != nil {
		return Document{}, "", conflict(nonretryableReadError(err))
	}
	if rev == "" {
		return Document{}, "", ErrIntegrity
	}
	d, err := Decode(data)
	return d, rev, err
}
func (b *ForgeBackend) CompareAndSwap(ctx context.Context, rev string, d Document) (string, error) {
	if rev == "" {
		return "", ErrConflict
	}
	if err := b.authorize(ctx, b.location, "write"); err != nil {
		// Only the conditional write may supply a retryable revision conflict.
		if errors.Is(err, ErrConflict) {
			return "", fmt.Errorf("journal write authorization rejected: %v", err)
		}
		return "", err
	}
	data, err := Encode(d)
	if err != nil {
		return "", err
	}
	err = b.client.WriteFileIfRevision(ctx, b.location.Owner, b.location.Repo, b.location.Branch, b.location.Path, rev, "Checkpoint Fullsend journal [skip ci]", data)
	if definitiveWriteConflict(err) {
		return "", ErrConflict
	}
	if err != nil {
		return "", fmt.Errorf("%w: write acknowledgement failed: %v", ErrUncertain, err)
	}
	// Verification failure is deliberately an uncertain write, never a blind retry.
	current, newRev, err := b.client.ReadVersionedFile(ctx, b.location.Owner, b.location.Repo, b.location.Branch, b.location.Path)
	if err != nil {
		// Do not wrap the underlying error: even a read-side conflict cannot
		// make this possibly committed write safe to retry.
		return "", fmt.Errorf("%w: readback failed: %v", ErrUncertain, err)
	}
	observed, err := Decode(current)
	if err != nil || newRev == "" {
		return "", fmt.Errorf("%w: invalid checkpoint readback", ErrUncertain)
	}
	if id, ok := ctx.Value(checkpointRecordKey{}).(string); ok {
		intended, exists := d.Records[id]
		actual, found := observed.Records[id]
		// The full parent revision still guards the write above. Only the
		// subsequent proof is record-specific. Any target change, including
		// lease renewal or release, remains uncertain; it cannot grant authority.
		if !exists || !found || !sameJSON(intended, actual) {
			return "", fmt.Errorf("%w: checkpoint record changed before verification", ErrUncertain)
		}
	} else if !bytes.Equal(current, data) {
		// Direct backend users supply no single-record transaction proof.
		return "", fmt.Errorf("%w: checkpoint changed before verification", ErrUncertain)
	}
	return newRev, nil
}

// definitiveWriteConflict requires every leaf to be the forge's conditional
// rejection sentinel. errors.Is alone also accepts mixed lost-ACK/conflict joins.
// Unknown wrappers with custom Is methods cannot prove non-commitment.
func definitiveWriteConflict(err error) bool {
	if err == forge.ErrConflict {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !definitiveWriteConflict(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return definitiveWriteConflict(wrapped.Unwrap())
	default:
		return false
	}
}

// A read or authorization failure says nothing about conditional-write rejection.
func nonretryableReadError(err error) error {
	if errors.Is(err, ErrConflict) {
		return fmt.Errorf("journal pre-write failure: %v", err)
	}
	return err
}
