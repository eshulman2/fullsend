package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*Engine, *ForgeBackend, *forge.FakeClient, *time.Time) {
	t.Helper()
	fc := forge.NewFakeClient()
	fc.BranchRefs["o/r/state"] = "head"
	b, err := NewForgeBackend(fc, Location{"o", "r", "state", "journal.json"}, func(context.Context, Location, string) error { return nil })
	require.NoError(t, err)
	require.NoError(t, b.Initialize(context.Background()))
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	return New(b, func() time.Time { return now }), b, fc, &now
}
func admitted(t *testing.T, e *Engine) Lease {
	t.Helper()
	_, err := e.Admit(context.Background(), "case-1", "binding-1", json.RawMessage(`{"required":["a","b"]}`))
	require.NoError(t, err)
	l, err := e.Claim(context.Background(), "case-1", "host-1", time.Minute)
	require.NoError(t, err)
	return l
}

func TestAdmissionOwnershipAndRestart(t *testing.T) {
	ctx := context.Background()
	e, b, _, now := fixture(t)
	l := admitted(t, e)
	r, err := e.Admit(ctx, "case-1", "binding-1", json.RawMessage(`{}`))
	require.NoError(t, err)
	require.Contains(t, string(r.Data), "required")
	_, err = e.Admit(ctx, "case-1", "different", json.RawMessage(`{}`))
	require.ErrorIs(t, err, ErrBinding)
	_, err = e.Claim(ctx, "case-1", "host-2", time.Minute)
	require.ErrorIs(t, err, ErrOwnership)
	_, err = e.Spend(ctx, "case-1", l, "attempts-a", 2)
	require.NoError(t, err)
	*now = now.Add(2 * time.Minute)
	replacement := New(b, func() time.Time { return *now })
	l2, err := replacement.Claim(ctx, "case-1", "host-2", time.Minute)
	require.NoError(t, err)
	require.Greater(t, l2.Generation, l.Generation)
	_, err = e.Spend(ctx, "case-1", l, "attempts-a", 2)
	require.ErrorIs(t, err, ErrOwnership)
	r, err = replacement.Rebind(ctx, "case-1", l2, "binding-2", json.RawMessage(`{"required":["a","b","c"]}`))
	require.NoError(t, err)
	require.Equal(t, uint64(1), r.Counters["attempts-a"])
	_, err = replacement.Spend(ctx, "case-1", l2, "attempts-a", 2)
	require.NoError(t, err)
	_, err = replacement.Spend(ctx, "case-1", l2, "attempts-a", 2)
	require.ErrorIs(t, err, ErrBudget)
	renewed, err := replacement.Renew(ctx, "case-1", l2, time.Hour)
	require.NoError(t, err)
	require.True(t, renewed.ExpiresAt.After(l2.ExpiresAt))
	require.NoError(t, replacement.Release(ctx, "case-1", renewed))
	require.ErrorIs(t, replacement.Release(ctx, "case-1", renewed), ErrOwnership)
	l3, err := replacement.Claim(ctx, "case-1", "host-3", time.Minute)
	require.NoError(t, err)
	require.Greater(t, l3.Generation, l2.Generation)
}
func TestEffectRecoveryAndImmutableReceipts(t *testing.T) {
	ctx := context.Background()
	e, b, _, _ := fixture(t)
	l := admitted(t, e)
	effect := Effect{ID: "create-a", Kind: "jira-create", Binding: "request-sha"}
	_, err := e.Intent(ctx, "case-1", l, effect)
	require.NoError(t, err)
	_, err = e.Intent(ctx, "case-1", l, effect)
	require.NoError(t, err)
	_, err = e.Intent(ctx, "case-1", l, Effect{ID: effect.ID, Kind: effect.Kind, Binding: "other"})
	require.ErrorIs(t, err, ErrBinding)
	_, err = e.Effect(ctx, "case-1", l, effect.ID, EffectInFlight, nil)
	require.NoError(t, err)
	_, err = e.Effect(ctx, "case-1", l, effect.ID, EffectInFlight, nil)
	require.ErrorIs(t, err, ErrTransition)
	// New host process reads the durable pre-write checkpoint even without cleanup.
	restarted := New(b, nil)
	r, err := restarted.Read(ctx, "case-1")
	require.NoError(t, err)
	require.Equal(t, EffectInFlight, r.Effects[effect.ID].Status)
	_, err = e.Effect(ctx, "case-1", l, effect.ID, EffectAmbiguous, nil)
	require.NoError(t, err)
	_, err = e.Effect(ctx, "case-1", l, effect.ID, EffectIntended, nil)
	require.ErrorIs(t, err, ErrTransition)
	_, err = e.Effect(ctx, "case-1", l, effect.ID, EffectConfirmed, json.RawMessage(`{"issue":"TEST-1"}`))
	require.NoError(t, err)
	_, err = e.Effect(ctx, "case-1", l, effect.ID, EffectConfirmed, json.RawMessage(`{"issue":"TEST-2"}`))
	require.ErrorIs(t, err, ErrTransition)
	_, err = e.Rebind(ctx, "case-1", l, "binding-2", json.RawMessage(`{}`))
	require.NoError(t, err)
	r, err = e.Read(ctx, "case-1")
	require.NoError(t, err)
	require.Equal(t, EffectConfirmed, r.Effects[effect.ID].Status)
}
func TestVerifiedReuseMayConfirmWithoutPost(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := fixture(t)
	l := admitted(t, e)
	_, err := e.Intent(ctx, "case-1", l, Effect{ID: "reuse", Kind: "tracker", Binding: "sha"})
	require.NoError(t, err)
	_, err = e.Effect(ctx, "case-1", l, "reuse", EffectConfirmed, json.RawMessage(`{"issue":"TEST-1"}`))
	require.NoError(t, err)
}
func TestIllegalTransactions(t *testing.T) {
	ctx := context.Background()
	e, _, _, now := fixture(t)
	l := admitted(t, e)
	_, err := e.Spend(ctx, "case-1", l, "attempts", 1)
	require.NoError(t, err)
	tests := []func(*Record) error{
		func(r *Record) error { r.ID = "other"; return nil }, func(r *Record) error { r.Binding = "other"; return nil }, func(r *Record) error { r.Generation++; return nil }, func(r *Record) error { r.Lease.Owner = "other"; return nil }, func(r *Record) error { r.Counters["attempts"] = 0; return nil }, func(r *Record) error {
			r.Effects["x"] = Effect{ID: "x", Kind: "create", Binding: "sha", Status: EffectConfirmed, Receipt: json.RawMessage(`{}`)}
			return nil
		}, func(r *Record) error { r.Data = json.RawMessage(`bad`); return nil },
	}
	for _, change := range tests {
		_, err = e.Update(ctx, "case-1", l, change)
		require.Error(t, err)
	}
	_, err = e.Update(ctx, "case-1", l, nil)
	require.ErrorIs(t, err, ErrTransition)
	_, err = e.Update(ctx, "case-1", l, func(*Record) error { return ErrBudget })
	require.ErrorIs(t, err, ErrBudget)
	_, err = e.Update(ctx, "case-1", l, func(*Record) error { *now = now.Add(time.Hour); return nil })
	require.ErrorIs(t, err, ErrOwnership)
}
func TestCASOnlyOneConcurrentTransitionWins(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := fixture(t)
	l := admitted(t, e)
	var arrived atomic.Int32
	ready := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, err := e.Update(ctx, "case-1", l, func(r *Record) error {
				if arrived.Add(1) == 2 {
					close(ready)
				}
				<-ready
				r.Counters["attempts"]++
				return nil
			})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, conflicts)
	r, err := e.Read(ctx, "case-1")
	require.NoError(t, err)
	require.Equal(t, uint64(1), r.Counters["attempts"])
}
func TestStrictDocumentIntegrity(t *testing.T) {
	original, err := Encode(Empty())
	require.NoError(t, err)
	_, err = Decode(original)
	require.NoError(t, err)
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`null`), []byte(`{"schema_version":1,"schema_version":1,"records":{},"checksum":"x"}`), append(append([]byte{}, original...), []byte(` {}`)...), []byte(strings.Replace(string(original), `"schema_version": 1`, `"schema_version": 2`, 1)), []byte(strings.Replace(string(original), `"records": {}`, `"unknown":{},"records": {}`, 1)), []byte(strings.Repeat("x", MaxDocumentBytes+1))} {
		_, err = Decode(raw)
		require.ErrorIs(t, err, ErrIntegrity)
	}
	_, err = Encode(Document{SchemaVersion: 1})
	require.ErrorIs(t, err, ErrIntegrity)
	d := Empty()
	d.Records["a"] = Record{ID: "a", Binding: "x", Data: json.RawMessage(`{}`), Counters: map[string]uint64{}, Effects: map[string]Effect{"e": {ID: "e", Kind: "k", Binding: "x", Status: EffectConfirmed}}}
	_, err = Encode(d)
	require.ErrorIs(t, err, ErrIntegrity)
}
func TestInvalidArgumentsAndMissingRecords(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := fixture(t)
	_, err := e.Read(ctx, "missing")
	require.ErrorIs(t, err, ErrNotFound)
	for _, id := range []string{"", "../x"} {
		_, err = e.Admit(ctx, id, "b", json.RawMessage(`{}`))
		require.Error(t, err)
	}
	_, err = e.Admit(ctx, "case", "", json.RawMessage(`{}`))
	require.Error(t, err)
	_, err = e.Claim(ctx, "missing", "host", time.Minute)
	require.ErrorIs(t, err, ErrNotFound)
	for _, ttl := range []time.Duration{0, 25 * time.Hour} {
		_, err = e.Claim(ctx, "missing", "host", ttl)
		require.ErrorIs(t, err, ErrOwnership)
		_, err = e.Renew(ctx, "missing", Lease{}, ttl)
		require.ErrorIs(t, err, ErrOwnership)
	}
	_, err = e.Update(ctx, "missing", Lease{}, func(*Record) error { return nil })
	require.ErrorIs(t, err, ErrNotFound)
	_, err = e.Rebind(ctx, "missing", Lease{}, "new", json.RawMessage(`{}`))
	require.ErrorIs(t, err, ErrNotFound)
	_, err = e.Rebind(ctx, "missing", Lease{}, "", nil)
	require.ErrorIs(t, err, ErrBinding)
	require.ErrorIs(t, e.Release(ctx, "missing", Lease{}), ErrNotFound)
	_, err = e.Renew(ctx, "missing", Lease{}, time.Minute)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = New(nil, nil).Read(ctx, "missing")
	require.ErrorIs(t, err, ErrIntegrity)
}

func TestDuplicatePayloadKeysRejectedBeforeWriting(t *testing.T) {
	ctx := context.Background()
	engine, _, _, _ := fixture(t)
	_, err := engine.Admit(ctx, "bad", "binding", json.RawMessage(`{"owner":"a","owner":"b"}`))
	require.ErrorIs(t, err, ErrIntegrity)
	_, err = engine.Admit(ctx, "good", "binding", json.RawMessage(`{"nested":{"a":1}}`))
	require.NoError(t, err)
	_, err = engine.Read(ctx, "good")
	require.NoError(t, err)
}
