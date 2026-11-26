package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type hookCAS struct {
	Backend
	hook func()
}

func (b *hookCAS) CompareAndSwap(ctx context.Context, rev string, d Document) (string, error) {
	if b.hook != nil {
		f := b.hook
		b.hook = nil
		f()
	}
	return b.Backend.CompareAndSwap(ctx, rev, d)
}
func dataHash(raw json.RawMessage) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }

func TestRequiredParentStateFencesChildEffects(t *testing.T) {
	ctx := context.Background()
	e, b, _, _ := fixture(t)
	parentLease := admitted(t, e)
	parent, err := e.Read(ctx, "case-1")
	require.NoError(t, err)
	_, err = e.Admit(ctx, "child", "code-inputs", json.RawMessage(`{}`))
	require.NoError(t, err)
	req := Requirement{ID: parent.ID, Binding: parent.Binding, DataDigest: dataHash(parent.Data)}
	guarded, err := e.RequireRecord(req)
	require.NoError(t, err)
	lease, err := guarded.Claim(ctx, "child", "code-host", time.Minute)
	require.NoError(t, err)
	_, err = guarded.Intent(ctx, "child", lease, Effect{ID: "first", Kind: "code", Binding: "approved-plan"})
	require.NoError(t, err)
	// Parent changes after a child read but before its conditional write.
	racing, err := New(&hookCAS{Backend: b, hook: func() {
		_, updateErr := e.Update(ctx, parent.ID, parentLease, func(r *Record) error { r.Data = json.RawMessage(`{"revoked":true}`); return nil })
		require.NoError(t, updateErr)
	}}, e.clock).RequireRecord(req)
	require.NoError(t, err)
	_, err = racing.Intent(ctx, "child", lease, Effect{ID: "stale", Kind: "publish", Binding: "approved-plan"})
	require.ErrorIs(t, err, ErrConflict)
	// Reload cannot silently accept the stale admission either.
	_, err = guarded.Intent(ctx, "child", lease, Effect{ID: "stale", Kind: "publish", Binding: "approved-plan"})
	require.ErrorIs(t, err, ErrBinding)
	child, err := guarded.Read(ctx, "child")
	require.NoError(t, err)
	require.NotContains(t, child.Effects, "stale")
	require.Contains(t, child.Effects, "first")
	fresh, err := e.Read(ctx, parent.ID)
	require.NoError(t, err)
	req.DataDigest = dataHash(fresh.Data)
	guarded, err = e.RequireRecord(req)
	require.NoError(t, err)
	_, err = guarded.Spend(ctx, "child", lease, "code-attempts", 1)
	require.NoError(t, err)
	req.Binding = "superseded"
	guarded, err = e.RequireRecord(req)
	require.NoError(t, err)
	_, err = guarded.Spend(ctx, "child", lease, "code-attempts", 2)
	require.ErrorIs(t, err, ErrBinding)
	req.ID = "missing"
	guarded, err = e.RequireRecord(req)
	require.NoError(t, err)
	_, err = guarded.Spend(ctx, "child", lease, "code-attempts", 2)
	require.ErrorIs(t, err, ErrBinding)
	for _, invalid := range []Requirement{{}, {ID: "parent", Binding: "binding", DataDigest: "bad"}, {ID: "bad space", Binding: "binding", DataDigest: req.DataDigest}, {ID: "parent", DataDigest: req.DataDigest}} {
		_, err = e.RequireRecord(invalid)
		require.ErrorIs(t, err, ErrBinding)
	}
	var nilEngine *Engine
	_, err = nilEngine.RequireRecord(req)
	require.ErrorIs(t, err, ErrBinding)
	_, err = New(nil, nil).RequireRecord(req)
	require.ErrorIs(t, err, ErrBinding)
}

func TestRequiredParentFencesNoOpMutationsAndNestedRequirements(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := fixture(t)
	parentLease := admitted(t, e)
	parent, err := e.Read(ctx, "case-1")
	require.NoError(t, err)
	_, err = e.Admit(ctx, "child", "child-binding", json.RawMessage(`{}`))
	require.NoError(t, err)
	lease, err := e.Claim(ctx, "child", "worker", time.Minute)
	require.NoError(t, err)
	effect := Effect{ID: "publish", Kind: "tracker", Binding: "inputs"}
	_, err = e.Intent(ctx, "child", lease, effect)
	require.NoError(t, err)
	stale := Requirement{ID: parent.ID, Binding: parent.Binding, DataDigest: dataHash(parent.Data)}
	guarded, err := e.RequireRecord(stale)
	require.NoError(t, err)
	_, err = e.Update(ctx, parent.ID, parentLease, func(r *Record) error { r.Data = json.RawMessage(`{"changed":true}`); return nil })
	require.NoError(t, err)
	child, err := e.Read(ctx, "child")
	require.NoError(t, err)
	nested, err := guarded.RequireRecord(Requirement{ID: child.ID, Binding: child.Binding, DataDigest: dataHash(child.Data)})
	require.NoError(t, err)
	for _, g := range []*Engine{guarded, nested} {
		_, err = g.Admit(ctx, "child", "child-binding", json.RawMessage(`{}`))
		require.ErrorIs(t, err, ErrBinding)
		_, err = g.Update(ctx, "child", lease, func(*Record) error { return nil })
		require.ErrorIs(t, err, ErrBinding)
		_, err = g.Intent(ctx, "child", lease, effect)
		require.ErrorIs(t, err, ErrBinding)
		_, err = g.Effect(ctx, "child", lease, "publish", EffectIntended, nil)
		require.ErrorIs(t, err, ErrBinding)
		_, err = g.Claim(ctx, "child", "new-worker", time.Minute)
		require.ErrorIs(t, err, ErrBinding)
		_, err = g.Rebind(ctx, "child", lease, "new-binding", json.RawMessage(`{}`))
		require.ErrorIs(t, err, ErrBinding)
		_, err = g.Renew(ctx, "child", lease, time.Minute)
		require.ErrorIs(t, err, ErrBinding)
		require.ErrorIs(t, g.Release(ctx, "child", lease), ErrBinding)
		_, err = g.Read(ctx, "child")
		require.NoError(t, err)
	}
}

func TestRequiredParentStillChecksFinalCAS(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := fixture(t)
	admitted(t, e)
	guarded, err := e.RequireRecord(Requirement{ID: "case-1", Binding: "superseded", DataDigest: dataHash(json.RawMessage(`{}`))})
	require.NoError(t, err)
	d, rev, err := guarded.backend.Load(ctx)
	require.NoError(t, err)
	_, err = guarded.backend.CompareAndSwap(ctx, rev, d)
	require.ErrorIs(t, err, ErrBinding)
	_, err = New(nil, nil).Admit(ctx, "child", "binding", json.RawMessage(`{}`))
	require.ErrorIs(t, err, ErrIntegrity)
}
