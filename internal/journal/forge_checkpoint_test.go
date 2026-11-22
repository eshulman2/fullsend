package journal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/stretchr/testify/require"
)

// checkpointClient injects a second writer strictly after the conditional write.
type checkpointClient struct {
	forge.Client
	afterWrite    func()
	writeError    error
	readError     error
	emptyRevision bool
}

func (c *checkpointClient) WriteFileIfRevision(ctx context.Context, owner, repo, branch, path, revision, message string, content []byte) error {
	if err := c.Client.WriteFileIfRevision(ctx, owner, repo, branch, path, revision, message, content); err != nil {
		return err
	}
	if c.afterWrite != nil {
		c.afterWrite()
	}
	return c.writeError
}
func (c *checkpointClient) ReadVersionedFile(ctx context.Context, owner, repo, branch, path string) ([]byte, string, error) {
	data, rev, err := c.Client.ReadVersionedFile(ctx, owner, repo, branch, path)
	if c.readError != nil {
		return nil, "", c.readError
	}
	if c.emptyRevision {
		rev = ""
	}
	return data, rev, err
}
func checkpointFixture(t *testing.T) (*Engine, *ForgeBackend, *checkpointClient, *forge.FakeClient) {
	t.Helper()
	fc := forge.NewFakeClient()
	fc.BranchRefs["o/r/state"] = "tip"
	client := &checkpointClient{Client: fc}
	b, err := NewForgeBackend(client, Location{"o", "r", "state", "journal.json"}, func(context.Context, Location, string) error { return nil })
	require.NoError(t, err)
	require.NoError(t, b.Initialize(context.Background()))
	return New(b, nil), b, client, fc
}
func mutateCheckpoint(t *testing.T, fc *forge.FakeClient, mutate func(*Document)) {
	t.Helper()
	raw, rev, err := fc.ReadVersionedFile(context.Background(), "o", "r", "state", "journal.json")
	require.NoError(t, err)
	d, err := Decode(raw)
	require.NoError(t, err)
	mutate(&d)
	data, err := Encode(d)
	require.NoError(t, err)
	require.NoError(t, fc.WriteFileIfRevision(context.Background(), "o", "r", "state", "journal.json", rev, "concurrent checkpoint", data))
}
func TestCheckpointUnrelatedRecordAdvance(t *testing.T) {
	e, _, client, fc := checkpointFixture(t)
	client.afterWrite = func() {
		mutateCheckpoint(t, fc, func(d *Document) {
			d.Records["other"] = Record{ID: "other", Binding: "other-binding", Data: []byte(`{}`), Counters: map[string]uint64{}, Effects: map[string]Effect{}}
		})
	}
	_, err := e.Admit(context.Background(), "target", "binding", []byte(`{}`))
	require.NoError(t, err)
}
func TestCheckpointUncertainOutcomes(t *testing.T) {
	for _, scenario := range []string{"lost-ack", "read-error", "read-conflict", "empty-revision", "checksum", "removed", "owner", "binding", "counter", "effect", "data", "renewal"} {
		t.Run(scenario, func(t *testing.T) {
			e, _, client, fc := checkpointFixture(t)
			switch scenario {
			case "lost-ack":
				client.writeError = errors.New("response lost")
			case "read-error":
				client.afterWrite = func() { client.readError = errors.New("response lost") }
			case "read-conflict":
				client.afterWrite = func() { client.readError = forge.ErrConflict }
			case "empty-revision":
				client.afterWrite = func() { client.emptyRevision = true }
			case "checksum":
				client.afterWrite = func() {
					fc.FileContentsRef["o/r/journal.json@state"] = bytes.Replace(fc.FileContentsRef["o/r/journal.json@state"], []byte(`"binding": "binding"`), []byte(`"binding": "tampered"`), 1)
				}
			default:
				client.afterWrite = func() {
					mutateCheckpoint(t, fc, func(d *Document) {
						r := d.Records["target"]
						switch scenario {
						case "removed":
							delete(d.Records, "target")
							return
						case "owner":
							r.Generation++
							r.Lease = Lease{Owner: "other", Generation: r.Generation}
						case "binding":
							r.Binding = "different"
						case "counter":
							r.Counters["writes"]++
						case "effect":
							r.Effects["effect"] = Effect{ID: "effect", Kind: "tracker", Binding: "x", Status: EffectIntended}
						case "data":
							r.Data = []byte(`{"changed":true}`)
						case "renewal":
							r.Lease.ExpiresAt = r.Lease.ExpiresAt.Add(1)
						}
						d.Records["target"] = r
					})
				}
			}
			_, err := e.Admit(context.Background(), "target", "binding", []byte(`{}`))
			require.ErrorIs(t, err, ErrUncertain)
			require.NotErrorIs(t, err, ErrConflict)
		})
	}
}
func TestCheckpointDirectBackendRequiresExactDocument(t *testing.T) {
	_, b, client, fc := checkpointFixture(t)
	d, rev, err := b.Load(context.Background())
	require.NoError(t, err)
	client.afterWrite = func() {
		mutateCheckpoint(t, fc, func(d *Document) {
			d.Records["other"] = Record{ID: "other", Binding: "b", Data: []byte(`{}`), Counters: map[string]uint64{}, Effects: map[string]Effect{}}
		})
	}
	_, err = b.CompareAndSwap(context.Background(), rev, d)
	require.ErrorIs(t, err, ErrUncertain)
	require.NotErrorIs(t, err, ErrConflict)
}

func TestCheckpointAllEngineTransactionsTolerateUnrelatedAdvance(t *testing.T) {
	for _, operation := range []string{"claim", "update", "rebind", "renew", "release"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			e, _, client, fc := checkpointFixture(t)
			_, err := e.Admit(ctx, "target", "binding", []byte(`{}`))
			require.NoError(t, err)
			var lease Lease
			if operation != "claim" {
				lease, err = e.Claim(ctx, "target", "owner", time.Hour)
				require.NoError(t, err)
			}
			client.afterWrite = func() {
				mutateCheckpoint(t, fc, func(d *Document) {
					d.Records["other"] = Record{ID: "other", Binding: "b", Data: []byte(`{}`), Counters: map[string]uint64{}, Effects: map[string]Effect{}}
				})
			}
			switch operation {
			case "claim":
				_, err = e.Claim(ctx, "target", "owner", time.Hour)
			case "update":
				_, err = e.Spend(ctx, "target", lease, "writes", 1)
			case "rebind":
				_, err = e.Rebind(ctx, "target", lease, "new-binding", []byte(`{"new":true}`))
			case "renew":
				_, err = e.Renew(ctx, "target", lease, 2*time.Hour)
			case "release":
				err = e.Release(ctx, "target", lease)
			}
			require.NoError(t, err)
		})
	}
}

func TestCheckpointDefinitiveRejectionIsOnlyConflict(t *testing.T) {
	_, b, client, _ := checkpointFixture(t)
	client.afterWrite = func() { t.Fatal("stale revision must not write") }
	_, err := b.CompareAndSwap(context.Background(), "stale", Empty())
	require.ErrorIs(t, err, ErrConflict)
	require.NotErrorIs(t, err, ErrUncertain)
}

func TestCheckpointMixedWriteConflictIsUncertain(t *testing.T) {
	e, _, client, _ := checkpointFixture(t)
	client.writeError = errors.Join(forge.ErrConflict, errors.New("lost acknowledgement"))
	_, err := e.Admit(context.Background(), "target", "binding", []byte(`{}`))
	require.ErrorIs(t, err, ErrUncertain)
	require.NotErrorIs(t, err, ErrConflict)
}

func TestCheckpointAuthorizationCannotSupplyRetryableConflict(t *testing.T) {
	_, b, _, _ := checkpointFixture(t)
	b.authorize = func(context.Context, Location, string) error { return ErrConflict }
	_, err := b.CompareAndSwap(context.Background(), "revision", Empty())
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrConflict)
}

func TestDefinitiveWriteConflict(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		definite bool
	}{
		{"nil", nil, false},
		{"plain", forge.ErrConflict, true},
		{"wrapped", fmt.Errorf("write: %w", forge.ErrConflict), true},
		{"joined-conflicts", errors.Join(forge.ErrConflict, fmt.Errorf("write: %w", forge.ErrConflict)), true},
		{"mixed", errors.Join(forge.ErrConflict, errors.New("unknown")), false},
		{"empty-join", emptyConflictJoin{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.definite, definitiveWriteConflict(tc.err)) })
	}
}

type emptyConflictJoin struct{}

func (emptyConflictJoin) Error() string   { return "empty" }
func (emptyConflictJoin) Unwrap() []error { return nil }

func TestCheckpointLoadCannotSupplyRetryableConflict(t *testing.T) {
	for _, source := range []string{"authorization", "storage"} {
		t.Run(source, func(t *testing.T) {
			_, b, client, _ := checkpointFixture(t)
			if source == "authorization" {
				b.authorize = func(context.Context, Location, string) error { return ErrConflict }
			} else {
				client.readError = fmt.Errorf("read: %w", ErrConflict)
			}
			_, _, err := b.Load(context.Background())
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrConflict)
		})
	}
}
