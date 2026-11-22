package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/stretchr/testify/require"
)

func TestJournalTransactionRetriesOnlyDefiniteConflicts(t *testing.T) {
	unknown := errors.New("secret storage failure")
	for _, tc := range []struct {
		name  string
		err   error
		calls int
	}{
		{"conflict", fmt.Errorf("wrapped: %w", journal.ErrConflict), 3},
		{"joined conflicts", errors.Join(journal.ErrConflict, journal.ErrConflict), 3},
		{"unknown", unknown, 1},
		{"uncertain", journal.ErrUncertain, 1},
		{"uncertain conflict", errors.Join(journal.ErrConflict, journal.ErrUncertain), 1},
		{"unknown conflict", errors.Join(journal.ErrConflict, unknown), 1},
		{"budget conflict", errors.Join(journal.ErrConflict, journal.ErrBudget), 1},
		{"ownership conflict", errors.Join(journal.ErrConflict, journal.ErrOwnership), 1},
		{"binding conflict", errors.Join(journal.ErrConflict, journal.ErrBinding), 1},
		{"integrity conflict", errors.Join(journal.ErrConflict, journal.ErrIntegrity), 1},
		{"transition conflict", errors.Join(journal.ErrConflict, journal.ErrTransition), 1},
		{"not found conflict", errors.Join(journal.ErrConflict, journal.ErrNotFound), 1},
		{"canceled conflict", errors.Join(journal.ErrConflict, context.Canceled), 1},
		{"timeout conflict", errors.Join(journal.ErrConflict, context.DeadlineExceeded), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, err := retryJournalTransaction(context.Background(), func() (any, error) { calls++; return nil, tc.err })
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.calls, calls)
		})
	}
	calls := 0
	result, err := retryJournalTransaction(context.Background(), func() (any, error) {
		calls++
		if calls == 1 {
			return nil, journal.ErrConflict
		}
		return "ok", nil
	})
	require.NoError(t, err)
	require.Equal(t, "ok", result)
	require.Equal(t, 2, calls)
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, err = retryJournalTransaction(ctx, func() (any, error) { calls++; cancel(); return nil, journal.ErrConflict })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
	require.Equal(t, "journal checkpoint outcome uncertain", sanitizeJournalError(errors.Join(journal.ErrConflict, fmt.Errorf("secret: %w", journal.ErrUncertain))).Error())
}

type retryJournalBackend struct {
	doc           journal.Document
	uncertain     bool
	loads, writes int
	concurrent    func(*journal.Document)
}

func (b *retryJournalBackend) Load(context.Context) (journal.Document, string, error) {
	b.loads++
	raw, err := journal.Encode(b.doc)
	if err != nil {
		return journal.Document{}, "", err
	}
	d, err := journal.Decode(raw)
	return d, "revision", err
}
func (b *retryJournalBackend) CompareAndSwap(_ context.Context, _ string, d journal.Document) (string, error) {
	b.writes++
	if b.uncertain {
		b.doc = d
		return "", errors.Join(journal.ErrConflict, fmt.Errorf("secret: %w", journal.ErrUncertain))
	}
	if b.writes == 1 {
		if b.concurrent != nil {
			b.concurrent(&b.doc)
		}
		return "", journal.ErrConflict
	}
	b.doc = d
	return "next", nil
}
func TestJournalCLIConflictReloadsAuthorityAndReusesInput(t *testing.T) {
	for _, change := range []string{"unrelated", "budget", "ownership", "binding", "parent"} {
		t.Run(change, func(t *testing.T) {
			lease := journal.Lease{Owner: "worker", Generation: 1, ExpiresAt: time.Now().Add(time.Hour)}
			record := journal.Record{ID: "case", Binding: "sha", Generation: 1, Lease: lease, Data: json.RawMessage(`{}`), Counters: map[string]uint64{}, Effects: map[string]journal.Effect{}}
			parent := record
			parent.ID = "parent"
			parent.Binding = "parent-sha"
			b := &retryJournalBackend{doc: journal.Empty()}
			b.doc.Records["case"] = record
			b.doc.Records["parent"] = parent
			b.concurrent = func(d *journal.Document) {
				r := d.Records["case"]
				switch change {
				case "budget":
					r.Counters["attempts"] = 1
				case "ownership":
					r.Lease.Owner = "other"
				case "binding":
					r.Binding = "changed"
				case "parent":
					p := d.Records["parent"]
					p.Binding = "changed"
					d.Records["parent"] = p
				case "unrelated":
					p := d.Records["parent"]
					p.Data = json.RawMessage(`{"concurrent":true}`)
					d.Records["parent"] = p
				}
				d.Records["case"] = r
			}
			old := openJournalHost
			openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
				return journal.New(b, nil), nil, nil
			}
			t.Cleanup(func() { openJournalHost = old })
			args := []string{"update", "--id", "case", "--owner", "worker", "--generation", "1"}
			var want error
			switch change {
			case "budget":
				args[0] = "spend"
				args = append(args, "--counter", "attempts", "--limit", "1")
				want = journal.ErrBudget
			case "ownership":
				want = journal.ErrOwnership
			case "binding":
				args = []string{"admit", "--id", "case", "--binding", "sha"}
				want = journal.ErrBinding
			case "parent":
				sum := sha256.Sum256(parent.Data)
				args = append(args, "--require-record", "parent", "--require-binding", "parent-sha", "--require-data-digest", hex.EncodeToString(sum[:]))
				want = journal.ErrBinding
			}
			// Admit needs an absent record to write before the concurrent binding change.
			if change == "binding" {
				delete(b.doc.Records, "case")
				b.concurrent = func(d *journal.Document) { r := record; r.Binding = "changed"; d.Records["case"] = r }
			}
			output, err := runJournal(t, `{"payload":"read once"}`, args...)
			if want != nil {
				require.ErrorIs(t, err, want)
				require.NotContains(t, output, `"payload":"read once"`)
				require.Equal(t, 1, b.writes)
			} else {
				require.NoError(t, err)
				require.Contains(t, output, `"payload":"read once"`)
				require.JSONEq(t, `{"concurrent":true}`, string(b.doc.Records["parent"].Data))
				require.Equal(t, 2, b.writes)
			}
			require.Equal(t, 2, b.loads)
		})
	}
}

func TestJournalCLILostAcknowledgementDoesNotRepeatSpendOrClaim(t *testing.T) {
	for _, action := range []string{"spend", "claim"} {
		t.Run(action, func(t *testing.T) {
			lease := journal.Lease{Owner: "worker", Generation: 1, ExpiresAt: time.Now().Add(time.Hour)}
			r := journal.Record{ID: "case", Binding: "sha", Generation: 1, Lease: lease, Data: json.RawMessage(`{}`), Counters: map[string]uint64{}, Effects: map[string]journal.Effect{}}
			if action == "claim" {
				r.Lease = journal.Lease{}
			}
			b := &retryJournalBackend{doc: journal.Empty(), uncertain: true}
			b.doc.Records["case"] = r
			old := openJournalHost
			openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
				return journal.New(b, nil), nil, nil
			}
			t.Cleanup(func() { openJournalHost = old })
			args := []string{action, "--id", "case", "--owner", "worker"}
			if action == "spend" {
				args = append(args, "--generation", "1", "--counter", "attempts", "--limit", "3")
			}
			_, err := runJournal(t, "", args...)
			require.Equal(t, journal.ErrUncertain, err)
			require.Equal(t, 1, b.loads)
			require.Equal(t, 1, b.writes)
			if action == "spend" {
				require.Equal(t, uint64(1), b.doc.Records["case"].Counters["attempts"])
			} else {
				require.Equal(t, uint64(2), b.doc.Records["case"].Generation)
			}
		})
	}
}

func TestJournalCLIInitializeDoesNotRetryConflict(t *testing.T) {
	calls := 0
	backend, err := journal.NewForgeBackend(forge.NewFakeClient(), journal.Location{Owner: "o", Repo: "r", Branch: "journal", Path: "state.json"}, func(context.Context, journal.Location, string) error { calls++; return journal.ErrConflict })
	require.NoError(t, err)
	old := openJournalHost
	openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
		return journal.New(backend, nil), backend, nil
	}
	t.Cleanup(func() { openJournalHost = old })
	_, err = runJournal(t, "", "initialize")
	require.ErrorIs(t, err, journal.ErrConflict)
	require.Equal(t, 1, calls)
}

func TestJournalTransactionCanceledBeforeAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := retryJournalTransaction(ctx, func() (any, error) { calls++; return nil, nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, calls)
}

func TestJournalCLIRetryRejectsStaleParentEvenWhenMutationBecomesNoop(t *testing.T) {
	for _, action := range []string{"admit", "update", "intent"} {
		t.Run(action, func(t *testing.T) {
			lease := journal.Lease{Owner: "worker", Generation: 1, ExpiresAt: time.Now().Add(time.Hour)}
			child := journal.Record{ID: "case", Binding: "sha", Generation: 1, Lease: lease, Data: json.RawMessage(`{}`), Counters: map[string]uint64{}, Effects: map[string]journal.Effect{}}
			parent := child
			parent.ID = "parent"
			parent.Binding = "parent-sha"
			b := &retryJournalBackend{doc: journal.Empty()}
			b.doc.Records["parent"] = parent
			if action != "admit" {
				b.doc.Records["case"] = child
			}
			b.concurrent = func(d *journal.Document) {
				p := d.Records["parent"]
				p.Data = json.RawMessage(`{"revoked":true}`)
				d.Records["parent"] = p
				switch action {
				case "admit", "update":
					child.Data = json.RawMessage(`{"desired":true}`)
				case "intent":
					child.Effects = map[string]journal.Effect{"publish": {ID: "publish", Kind: "pr", Binding: "approved", Status: journal.EffectIntended}}
				}
				d.Records["case"] = child
			}
			old := openJournalHost
			openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
				return journal.New(b, nil), nil, nil
			}
			t.Cleanup(func() { openJournalHost = old })
			sum := sha256.Sum256(parent.Data)
			args := []string{action, "--id", "case", "--require-record", "parent", "--require-binding", "parent-sha", "--require-data-digest", hex.EncodeToString(sum[:])}
			if action == "admit" {
				args = append(args, "--binding", "sha")
			} else {
				args = append(args, "--owner", "worker", "--generation", "1")
			}
			if action == "intent" {
				args = append(args, "--effect-id", "publish", "--kind", "pr", "--binding", "approved")
			}
			output, err := runJournal(t, `{"desired":true}`, args...)
			require.ErrorIs(t, err, journal.ErrBinding)
			require.NotContains(t, output, `"desired":true`)
			require.Equal(t, 2, b.loads)
			require.Equal(t, 1, b.writes)
		})
	}
}

func TestJournalCLIReadAuthorizationConflictIsNotRetried(t *testing.T) {
	calls := 0
	backend, err := journal.NewForgeBackend(forge.NewFakeClient(), journal.Location{Owner: "o", Repo: "r", Branch: "journal", Path: "state.json"}, func(context.Context, journal.Location, string) error {
		calls++
		return fmt.Errorf("secret authorization failure: %w", journal.ErrConflict)
	})
	require.NoError(t, err)
	old := openJournalHost
	openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
		return journal.New(backend, nil), backend, nil
	}
	t.Cleanup(func() { openJournalHost = old })
	_, err = runJournal(t, "", "spend", "--id", "case", "--owner", "worker", "--generation", "1", "--counter", "attempts", "--limit", "1")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret")
	require.NotErrorIs(t, err, journal.ErrConflict)
	require.Equal(t, 1, calls)
}
