package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/fullsend-ai/fullsend/internal/journal"
	"github.com/fullsend-ai/fullsend/internal/journalhost"
	"github.com/spf13/cobra"
)

var openJournalHost = journalhost.Open

func newJournalCmd() *cobra.Command {
	var id, binding, owner, kind, effectID, status, counter string
	var generation, limit uint64
	var ttl time.Duration
	cmd := &cobra.Command{Use: "journal <initialize|read|admit|claim|renew|release|update|rebind|intent|effect|spend>", Short: "Checkpoint a saga in the protected GitLab control repository", Args: cobra.ExactArgs(1)}
	cmd.Long = "Read and conditionally update the journal selected by protected FULLSEND_JOURNAL_PROFILE installation state. JSON payloads and leases use standard input/output; journal credentials remain host-side. No model is invoked."
	cmd.Flags().StringVar(&id, "id", "", "stable admitted operation identity")
	cmd.Flags().StringVar(&binding, "binding", "", "immutable input digest for admission or effect")
	cmd.Flags().StringVar(&owner, "owner", "", "lease owner identity")
	cmd.Flags().Uint64Var(&generation, "generation", 0, "ownership generation returned by claim")
	cmd.Flags().DurationVar(&ttl, "ttl", 5*time.Minute, "lease lifetime (maximum 24h)")
	cmd.Flags().StringVar(&kind, "kind", "", "effect kind")
	cmd.Flags().StringVar(&effectID, "effect-id", "", "stable external operation identity")
	cmd.Flags().StringVar(&status, "status", "", "effect state: in_flight, ambiguous or confirmed")
	cmd.Flags().StringVar(&counter, "counter", "", "durable budget counter")
	cmd.Flags().Uint64Var(&limit, "limit", 0, "maximum budget consumption")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		action := args[0]
		allowed := map[string]bool{"initialize": true, "read": true, "admit": true, "claim": true, "renew": true, "release": true, "update": true, "rebind": true, "intent": true, "effect": true, "spend": true}
		if !allowed[action] {
			return errors.New("unknown journal operation")
		}
		if action != "initialize" && id == "" {
			return errors.New("--id required")
		}
		engine, backend, err := openJournalHost(os.Getenv)
		if err != nil {
			return sanitizeJournalError(err)
		}
		lease := journal.Lease{Owner: owner, Generation: generation}
		var result any
		ctx := cmd.Context()
		switch action {
		case "initialize":
			err = backend.Initialize(ctx)
			result = map[string]bool{"initialized": err == nil}
		case "read":
			result, err = engine.Read(ctx, id)
		case "admit":
			var data json.RawMessage
			data, err = readJournalJSON(cmd.InOrStdin())
			if err == nil {
				result, err = engine.Admit(ctx, id, binding, data)
			}
		case "claim":
			result, err = engine.Claim(ctx, id, owner, ttl)
		case "renew":
			result, err = engine.Renew(ctx, id, lease, ttl)
		case "release":
			err = engine.Release(ctx, id, lease)
			result = map[string]bool{"released": err == nil}
		case "update":
			var data json.RawMessage
			data, err = readJournalJSON(cmd.InOrStdin())
			if err == nil {
				result, err = engine.Update(ctx, id, lease, func(r *journal.Record) error { r.Data = data; return nil })
			}
		case "rebind":
			var data json.RawMessage
			data, err = readJournalJSON(cmd.InOrStdin())
			if err == nil {
				result, err = engine.Rebind(ctx, id, lease, binding, data)
			}

		case "intent":
			result, err = engine.Intent(ctx, id, lease, journal.Effect{ID: effectID, Kind: kind, Binding: binding, Status: "intended"})
		case "effect":
			var data json.RawMessage
			if status == "confirmed" {
				data, err = readJournalJSON(cmd.InOrStdin())
			}
			if err == nil {
				result, err = engine.Effect(ctx, id, lease, effectID, status, data)
			}
		case "spend":
			result, err = engine.Spend(ctx, id, lease, counter, limit)
		}
		if err != nil {
			return sanitizeJournalError(err)
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}
	return cmd
}
func readJournalJSON(r io.Reader) (json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(r, journal.MaxDocumentBytes+1))
	if err != nil || len(data) > journal.MaxDocumentBytes || !json.Valid(data) {
		return nil, errors.New("bounded JSON input required")
	}
	return json.RawMessage(data), nil
}
func sanitizeJournalError(err error) error {
	for _, known := range []error{journal.ErrConflict, journal.ErrIntegrity, journal.ErrOwnership, journal.ErrBinding, journal.ErrNotFound, journal.ErrTransition, journal.ErrBudget, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("journal operation failed; inspect control repository and connection permissions")
}
