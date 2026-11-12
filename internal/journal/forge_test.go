package journal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/stretchr/testify/require"
)

func TestForgeBackendAuthorityAndInitialization(t *testing.T) {
	ctx := context.Background()
	fc := forge.NewFakeClient()
	location := Location{"o", "r", "state", "journal.json"}
	denied := errors.New("denied")
	_, err := NewForgeBackend(fc, location, nil)
	require.Error(t, err)
	for _, path := range []string{"", "../journal.json", "/journal.json", "dir/../journal.json", "file.txt"} {
		bad := location
		bad.Path = path
		_, err = NewForgeBackend(fc, bad, func(context.Context, Location, string) error { return nil })
		require.Error(t, err)
	}
	b, err := NewForgeBackend(fc, location, func(context.Context, Location, string) error { return denied })
	require.NoError(t, err)
	require.ErrorIs(t, b.Initialize(ctx), denied)
	_, _, err = b.Load(ctx)
	require.ErrorIs(t, err, denied)
	_, err = b.CompareAndSwap(ctx, "rev", Empty())
	require.ErrorIs(t, err, denied)
	b.authorize = func(context.Context, Location, string) error { return nil }
	require.ErrorIs(t, b.Initialize(ctx), forge.ErrNotFound)
	fc.BranchRefs["o/r/state"] = "tip"
	require.NoError(t, b.Initialize(ctx))
	require.ErrorIs(t, b.Initialize(ctx), ErrConflict)
	d, rev, err := b.Load(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, d.SchemaVersion)
	require.NotEmpty(t, rev)
	_, err = b.CompareAndSwap(ctx, "stale", d)
	require.ErrorIs(t, err, ErrConflict)
	_, err = b.CompareAndSwap(ctx, "", d)
	require.ErrorIs(t, err, ErrConflict)
	fc.FileContentsRef["o/r/journal.json@state"] = []byte(`bad`)
	_, _, err = b.Load(ctx)
	require.ErrorIs(t, err, ErrIntegrity)
}

type lostAck struct {
	Backend
	failed bool
}

func (b *lostAck) CompareAndSwap(ctx context.Context, rev string, d Document) (string, error) {
	newRev, err := b.Backend.CompareAndSwap(ctx, rev, d)
	if err != nil {
		return newRev, err
	}
	if b.failed {
		return newRev, nil
	}
	b.failed = true
	return "", errors.New("response lost")
}
func TestLostCheckpointAcknowledgementRetainsIntent(t *testing.T) {
	ctx := context.Background()
	e, b, _, now := fixture(t)
	l := admitted(t, e)
	_, err := e.Intent(ctx, "case-1", l, Effect{ID: "create", Kind: "tracker", Binding: "sha"})
	require.NoError(t, err)
	broken := New(&lostAck{Backend: b}, func() time.Time { return *now })
	_, err = broken.Effect(ctx, "case-1", l, "create", EffectInFlight, nil)
	require.Error(t, err)
	r, err := New(b, nil).Read(ctx, "case-1")
	require.NoError(t, err)
	require.Equal(t, EffectInFlight, r.Effects["create"].Status)
}
