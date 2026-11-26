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
	var required journal.Requirement
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
	cmd.Flags().StringVar(&required.ID, "require-record", "", "parent record required in the same conditional journal write")
	cmd.Flags().StringVar(&required.Binding, "require-binding", "", "required parent input binding")
	cmd.Flags().StringVar(&required.DataDigest, "require-data-digest", "", "SHA256 of exact observed parent data bytes")
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
		if required.ID != "" || required.Binding != "" || required.DataDigest != "" {
			if action == "initialize" || required.ID == id {
				return journal.ErrBinding
			}
			engine, err = engine.RequireRecord(required)
			if err != nil {
				return sanitizeJournalError(err)
			}
		}
		lease := journal.Lease{Owner: owner, Generation: generation}
		ctx := cmd.Context()
		var data json.RawMessage
		if action == "admit" || action == "update" || action == "rebind" || (action == "effect" && status == "confirmed") {
			data, err = readJournalJSON(cmd.InOrStdin())
			if err != nil {
				return sanitizeJournalError(err)
			}
		}
		operation := func() (any, error) {
			// Invoke the engine afresh: each transaction reloads and rechecks
			// parent predicates, lease ownership, transitions and budgets.
			switch action {
			case "initialize":
				err := backend.Initialize(ctx)
				return map[string]bool{"initialized": err == nil}, err
			case "read":
				return engine.Read(ctx, id)
			case "admit":
				return engine.Admit(ctx, id, binding, data)
			case "claim":
				return engine.Claim(ctx, id, owner, ttl)
			case "renew":
				return engine.Renew(ctx, id, lease, ttl)
			case "release":
				err := engine.Release(ctx, id, lease)
				return map[string]bool{"released": err == nil}, err
			case "update":
				return engine.Update(ctx, id, lease, func(r *journal.Record) error { r.Data = data; return nil })
			case "rebind":
				return engine.Rebind(ctx, id, lease, binding, data)
			case "intent":
				return engine.Intent(ctx, id, lease, journal.Effect{ID: effectID, Kind: kind, Binding: binding, Status: "intended"})
			case "effect":
				return engine.Effect(ctx, id, lease, effectID, status, data)
			case "spend":
				return engine.Spend(ctx, id, lease, counter, limit)
			}
			return nil, journal.ErrIntegrity
		}
		var result any
		if action == "initialize" || action == "read" {
			result, err = operation()
		} else {
			result, err = retryJournalTransaction(ctx, operation)
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
	for _, known := range []error{journal.ErrUncertain, journal.ErrConflict, journal.ErrIntegrity, journal.ErrOwnership, journal.ErrBinding, journal.ErrNotFound, journal.ErrTransition, journal.ErrBudget, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("journal operation failed; inspect control repository and connection permissions")
}

// retryJournalTransaction replays only definitively rejected writes. Never
// replay a saved document: the operation must execute a fresh engine transaction.
func retryJournalTransaction(ctx context.Context, operation func() (any, error)) (any, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := operation()
		if err == nil || attempt == 2 || !journalConflictOnly(err) {
			return result, err
		}
		timer := time.NewTimer(time.Duration(20*(attempt+1)) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// A joined unknown failure can indicate an uncertain outcome even when another
// branch is a conflict. Require every leaf to be the definite-conflict sentinel.
func journalConflictOnly(err error) bool {
	if !errors.Is(err, journal.ErrConflict) || errors.Is(err, journal.ErrUncertain) {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !journalConflictOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return journalConflictOnly(wrapped.Unwrap())
	}
	return err == journal.ErrConflict
}
