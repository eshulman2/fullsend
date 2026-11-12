// tracker-context exports trusted planning/promotion context; no external writes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	gl "github.com/fullsend-ai/fullsend/internal/forge/gitlab"
	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/fullsend-ai/fullsend/internal/journalhost"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
	"github.com/fullsend-ai/fullsend/internal/trackerpromotion"
)

// Seams keep CLI wiring testable without granting an offline fake exporter in
// production. The defaults always open the protected backend and verify live state.
var openJournal = journalhost.Open
var exportContext = func(ctx context.Context, e trackerpromotion.Exporter, m trackerflow.Manifest, target, source string) (map[string]any, error) {
	return e.Export(ctx, m, target, source)
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tracker context rejected; inspect protected policy and current journal state")
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("tracker-context", flag.ContinueOnError)
	f.SetOutput(out)
	path := f.String("manifest", "", "reviewed protected manifest")
	target := f.String("target-id", "", "exact current target")
	source := f.String("target-repo", "", "already admitted exact source checkout")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *path == "" || *target == "" || *source == "" || f.NArg() != 0 {
		return errors.New("manifest, target and source required")
	}
	file, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("bounded manifest required")
	}
	var m trackerflow.Manifest
	if err = trackerflow.DecodeStrict(raw, &m); err != nil {
		return err
	}
	if err = m.Validate(); err != nil {
		return err
	}
	p, err := trackerflow.LoadProfile(os.Getenv)
	if err != nil {
		return err
	}
	if p.Jira.IssueControls == nil {
		return errors.New("live Jira controls required for promotion")
	}
	token, err := p.Credential(os.Getenv)
	if err != nil {
		return err
	}
	control, err := gl.New(token, gl.WithBaseURL(p.Control.BaseURL))
	if err != nil {
		return err
	}
	creds, err := jira.CredentialsFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	jc, err := jira.NewScoped(jira.ScopedConfig{BaseURL: p.Jira.BaseURL, APIURL: p.Jira.APIURL}, creds)
	if err != nil {
		return err
	}
	engine, _, err := openJournal(os.Getenv)
	if err != nil {
		return err
	}
	authority := trackerflow.ProfileAuthority{Profile: p, Control: control, Jira: jc, Getenv: os.Getenv, Token: token}
	tracker := trackerflow.JiraTracker{Client: jc, Controls: p.Jira.IssueControls, AssigneeAccountID: p.Jira.AssigneeAccountID}
	exporter := trackerpromotion.Exporter{Journal: engine, Authorize: func(ctx context.Context, m trackerflow.Manifest, t trackerflow.Target) error {
		return authority.Authorize(ctx, m, t, "admit")
	}, CheckIssue: func(ctx context.Context, key string) error { return p.CheckIssue(ctx, jc, key) }, VerifyTracker: tracker.Verify, VerifyPublication: tracker.VerifyAssessment}
	result, err := exportContext(ctx, exporter, m, *target, *source)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
