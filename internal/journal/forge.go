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
		return Document{}, "", err
	}
	data, rev, err := b.client.ReadVersionedFile(ctx, b.location.Owner, b.location.Repo, b.location.Branch, b.location.Path)
	if err != nil {
		return Document{}, "", conflict(err)
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
		return "", err
	}
	data, err := Encode(d)
	if err != nil {
		return "", err
	}
	err = b.client.WriteFileIfRevision(ctx, b.location.Owner, b.location.Repo, b.location.Branch, b.location.Path, rev, "Checkpoint Fullsend journal [skip ci]", data)
	if errors.Is(err, forge.ErrConflict) {
		return "", ErrConflict
	}
	if err != nil {
		return "", conflict(err)
	}
	// Verification failure is deliberately an uncertain write, never a blind retry.
	current, newRev, err := b.client.ReadVersionedFile(ctx, b.location.Owner, b.location.Repo, b.location.Branch, b.location.Path)
	if err != nil {
		return "", conflict(err)
	}
	if !bytes.Equal(current, data) {
		return "", fmt.Errorf("%w: checkpoint changed before verification", ErrConflict)
	}
	return newRev, nil
}
