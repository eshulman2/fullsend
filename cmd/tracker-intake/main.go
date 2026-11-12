// tracker-intake is a domain adapter over ordinary single-target Fullsend runs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	gl "github.com/fullsend-ai/fullsend/internal/forge/gitlab"
	"github.com/fullsend-ai/fullsend/internal/forge/jira"
	"github.com/fullsend-ai/fullsend/internal/journalhost"
	"github.com/fullsend-ai/fullsend/internal/trackerflow"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tracker intake failed; inspect protected configuration and journal state")
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("tracker-intake", flag.ContinueOnError)
	flags.SetOutput(out)
	manifestPath := flags.String("manifest", "", "reviewed bounded target manifest")
	owner := flags.String("owner", "", "unique controller invocation identity")
	check := flags.Bool("check", false, "validate manifest and print target IDs without remote access")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *manifestPath == "" {
		return errors.New("manifest required")
	}
	stream, err := os.Open(*manifestPath)
	if err != nil {
		return errors.New("manifest unavailable")
	}
	defer stream.Close()
	raw, err := io.ReadAll(io.LimitReader(stream, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("manifest too large")
	}
	var manifest trackerflow.Manifest
	if err = trackerflow.DecodeStrict(raw, &manifest); err != nil {
		return errors.New("invalid manifest")
	}
	if err = manifest.Validate(); err != nil {
		return err
	}
	if *check {
		ids := []string{}
		for _, target := range manifest.Targets {
			ids = append(ids, trackerflow.TargetID(manifest.CaseID, target))
		}
		return json.NewEncoder(out).Encode(map[string]any{"manifest_digest": manifest.Digest(), "target_ids": ids})
	}
	profile, err := trackerflow.LoadProfile(os.Getenv)
	if err != nil {
		return err
	}
	token, err := profile.Credential(os.Getenv)
	if err != nil {
		return err
	}
	control, err := gl.New(token, gl.WithBaseURL(profile.Control.BaseURL))
	if err != nil {
		return err
	}
	creds, err := jira.CredentialsFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	jc, err := jira.NewScoped(jira.ScopedConfig{BaseURL: profile.Jira.BaseURL, APIURL: profile.Jira.APIURL}, creds)
	if err != nil {
		return err
	}
	engine, _, err := journalhost.Open(os.Getenv)
	if err != nil {
		return err
	}
	controller := trackerflow.Controller{Journal: engine, Tracker: trackerflow.JiraTracker{Client: jc}, Scheduler: trackerflow.GitLabScheduler{Client: control, Owner: profile.Control.Owner, Repository: profile.Control.Repository, Ref: profile.Control.WorkerRef, Since: profile.Control.LookupSince}, Authorizer: trackerflow.ProfileAuthority{Profile: profile, Control: control, Jira: jc, Getenv: os.Getenv, Token: token}, Owner: *owner, LeaseTTL: 10 * time.Minute}
	report, err := controller.Cycle(ctx, manifest)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
