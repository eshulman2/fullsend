package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/stretchr/testify/require"
)

func journalCommandFixture(t *testing.T) (*journal.Engine, *journal.ForgeBackend) {
	t.Helper()
	fc := forge.NewFakeClient()
	fc.BranchRefs["o/r/journal"] = "head"
	backend, err := journal.NewForgeBackend(fc, journal.Location{Owner: "o", Repo: "r", Branch: "journal", Path: "state.json"}, func(context.Context, journal.Location, string) error { return nil })
	require.NoError(t, err)
	engine := journal.New(backend, nil)
	old := openJournalHost
	openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) { return engine, backend, nil }
	t.Cleanup(func() { openJournalHost = old })
	return engine, backend
}
func runJournal(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	cmd := newJournalCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return output.String(), err
}
func TestJournalCLIDurableLifecycle(t *testing.T) {
	engine, _ := journalCommandFixture(t)
	output, err := runJournal(t, "", "initialize")
	require.NoError(t, err)
	require.Contains(t, output, `"initialized":true`)
	_, err = runJournal(t, `{"targets":["main","release"]}`, "admit", "--id", "case", "--binding", "source-sha")
	require.NoError(t, err)
	output, err = runJournal(t, "", "claim", "--id", "case", "--owner", "host")
	require.NoError(t, err)
	var lease journal.Lease
	require.NoError(t, json.Unmarshal([]byte(output), &lease))
	require.Equal(t, "host", lease.Owner)
	flags := []string{"--id", "case", "--owner", lease.Owner, "--generation", fmt.Sprint(lease.Generation)}
	call := func(input, action string, extra ...string) (string, error) {
		args := append([]string{action}, flags...)
		return runJournal(t, input, append(args, extra...)...)
	}
	_, err = call("", "intent", "--effect-id", "dispatch-1", "--kind", "dispatch", "--binding", "request-sha")
	require.NoError(t, err)
	_, err = call("", "effect", "--effect-id", "dispatch-1", "--status", "in_flight")
	require.NoError(t, err)
	_, err = call("", "effect", "--effect-id", "dispatch-1", "--status", "ambiguous")
	require.NoError(t, err)
	_, err = call(`{"run":"run-1"}`, "effect", "--effect-id", "dispatch-1", "--status", "confirmed")
	require.NoError(t, err)
	_, err = call("", "spend", "--counter", "attempts", "--limit", "1")
	require.NoError(t, err)
	_, err = call("", "spend", "--counter", "attempts", "--limit", "1")
	require.ErrorIs(t, err, journal.ErrBudget)
	_, err = call(`{"targets":["main","release"],"checked":true}`, "update")
	require.NoError(t, err)
	_, err = call(`{"targets":["main","release"],"checked":true}`, "rebind", "--binding", "source-sha-2")
	require.NoError(t, err)
	_, err = call("", "renew", "--ttl", "10m")
	require.NoError(t, err)
	output, err = runJournal(t, "", "read", "--id", "case")
	require.NoError(t, err)
	require.Contains(t, output, `"confirmed"`)
	require.Contains(t, output, `"checked":true`)
	_, err = call("", "release")
	require.NoError(t, err)
	record, err := engine.Read(context.Background(), "case")
	require.NoError(t, err)
	require.Empty(t, record.Lease.Owner)
	require.Equal(t, uint64(1), record.Counters["attempts"])
	require.Equal(t, "source-sha-2", record.Binding)
	require.Equal(t, "confirmed", record.Effects["dispatch-1"].Status)
}
func TestJournalCLIRejectsMalformedAndUnownedOperations(t *testing.T) {
	_, backend := journalCommandFixture(t)
	require.NoError(t, backend.Initialize(context.Background()))
	for _, args := range [][]string{{"unknown"}, {"read"}, {"rebind", "--id", "case", "--binding", "sha-2"}, {"admit", "--id", "case", "--binding", "sha"}, {"effect", "--id", "case", "--status", "confirmed"}} {
		_, err := runJournal(t, "bad json", args...)
		require.Error(t, err)
	}
	_, err := runJournal(t, `{}`, "admit", "--id", "case", "--binding", "sha")
	require.NoError(t, err)
	_, err = runJournal(t, "", "spend", "--id", "case", "--owner", "wrong", "--generation", "1", "--counter", "attempts", "--limit", "1")
	require.ErrorIs(t, err, journal.ErrOwnership)
	old := openJournalHost
	openJournalHost = func(func(string) string) (*journal.Engine, *journal.ForgeBackend, error) {
		return nil, nil, errors.New("transport leaked token-secret")
	}
	t.Cleanup(func() { openJournalHost = old })
	_, err = runJournal(t, "", "read", "--id", "case")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "token-secret")
}

type journalBrokenReader struct{}

func (journalBrokenReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func TestJournalJSONBoundsAndSanitizedErrors(t *testing.T) {
	for _, r := range []io.Reader{strings.NewReader("{"), strings.NewReader(strings.Repeat("x", journal.MaxDocumentBytes+1)), journalBrokenReader{}} {
		_, err := readJournalJSON(r)
		require.Error(t, err)
	}
	valid, err := readJournalJSON(strings.NewReader(`{"a":1}`))
	require.NoError(t, err)
	require.JSONEq(t, `{"a":1}`, string(valid))
	for _, sentinel := range []error{journal.ErrConflict, journal.ErrIntegrity, journal.ErrOwnership, journal.ErrBinding, journal.ErrNotFound, journal.ErrTransition, journal.ErrBudget, context.Canceled, context.DeadlineExceeded} {
		require.ErrorIs(t, sanitizeJournalError(fmt.Errorf("token-secret: %w", sentinel)), sentinel)
	}
	require.NotContains(t, sanitizeJournalError(errors.New("token-secret")).Error(), "token-secret")
}

func TestJournalCLIParentPredicatesRejectStaleEffect(t *testing.T) {
	e, b := journalCommandFixture(t)
	ctx := context.Background()
	require.NoError(t, b.Initialize(ctx))
	parent, err := e.Admit(ctx, "parent", "manifest", json.RawMessage(`{"state":"admitted"}`))
	require.NoError(t, err)
	parent, err = e.Read(ctx, "parent")
	require.NoError(t, err)
	sum := sha256.Sum256(parent.Data)
	flags := []string{"--require-record", "parent", "--require-binding", "manifest", "--require-data-digest", hex.EncodeToString(sum[:])}
	_, err = runJournal(t, `{}`, append([]string{"admit", "--id", "child", "--binding", "plan"}, flags...)...)
	require.NoError(t, err)
	lease, err := e.Claim(ctx, "child", "worker", time.Minute)
	require.NoError(t, err)
	args := append([]string{"intent", "--id", "child", "--owner", "worker", "--generation", fmt.Sprint(lease.Generation), "--effect-id", "publish", "--kind", "pr", "--binding", "approved"}, flags...)
	_, err = runJournal(t, "", args...)
	require.NoError(t, err)
	parentLease, err := e.Claim(ctx, "parent", "controller", time.Minute)
	require.NoError(t, err)
	_, err = e.Update(ctx, "parent", parentLease, func(r *journal.Record) error { r.Data = json.RawMessage(`{"state":"revoked"}`); return nil })
	require.NoError(t, err)
	_, err = runJournal(t, "", append([]string{"effect", "--id", "child", "--owner", "worker", "--generation", fmt.Sprint(lease.Generation), "--effect-id", "publish", "--status", "in_flight"}, flags...)...)
	require.ErrorIs(t, err, journal.ErrBinding)
	child, err := e.Read(ctx, "child")
	require.NoError(t, err)
	require.Equal(t, "intended", child.Effects["publish"].Status)
	// Read remains available, while malformed/partial/self requirements fail closed.
	_, err = runJournal(t, "", append([]string{"read", "--id", "child"}, flags...)...)
	require.NoError(t, err)
	for _, a := range [][]string{{"initialize", "--require-record", "parent"}, {"read", "--id", "parent", "--require-record", "parent"}, {"read", "--id", "child", "--require-binding", "manifest"}} {
		_, err = runJournal(t, "", a...)
		require.ErrorIs(t, err, journal.ErrBinding)
	}
}
