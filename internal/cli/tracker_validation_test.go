package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrackerEvidenceValidatorIsPinnedAndCredentialFree(t *testing.T) {
	_, request, p, _ := trackerCLISetup(t)
	t.Setenv("FULLSEND_JIRA_TOKEN", "must-not-reach-validator")
	t.Setenv("GITLAB_TOKEN", "must-not-reach-validator")
	script := fmt.Sprintf("#!/bin/sh\n[ -z \"${FULLSEND_JIRA_TOKEN:-}${GITLAB_TOKEN:-}\" ] || exit 9\nprintf '%%s' '{\"request_digest\":\"%s\",\"outcome\":\"uncertain\",\"receipt_ref\":\"validated:fixture\"}'\n", request.Digest())
	path := filepath.Join(p.FullsendDir, p.ValidatorFile)
	require.NoError(t, os.WriteFile(path, []byte(script), 0700))
	require.NoError(t, os.Chmod(path, 0700))
	h := sha256.Sum256([]byte(script))
	p.Files[p.ValidatorFile] = hex.EncodeToString(h[:])
	result, e := executeTrackerValidation(context.Background(), request, p, t.TempDir(), t.TempDir())
	require.NoError(t, e)
	require.Equal(t, "uncertain", result.Outcome)
	p.Files[p.ValidatorFile] = strings.Repeat("f", 64)
	_, e = executeTrackerValidation(context.Background(), request, p, "source", "out")
	require.Error(t, e)
	p.ValidatorFile = ""
	_, e = executeTrackerValidation(context.Background(), request, p, "source", "out")
	require.Error(t, e)
}
func TestTrackerEvidenceValidatorCannotReturnArbitraryOutput(t *testing.T) {
	for _, script := range []string{"#!/bin/sh\nprintf secret >&2\nexit 1\n", "#!/bin/sh\nprintf not-json\n", "#!/bin/sh\nprintf '{}'\n", "#!/bin/sh\nhead -c 1048577 /dev/zero\n"} {
		t.Run(fmt.Sprint(len(script)), func(t *testing.T) {
			_, r, p, _ := trackerCLISetup(t)
			path := filepath.Join(p.FullsendDir, p.ValidatorFile)
			require.NoError(t, os.WriteFile(path, []byte(script), 0700))
			require.NoError(t, os.Chmod(path, 0700))
			h := sha256.Sum256([]byte(script))
			p.Files[p.ValidatorFile] = hex.EncodeToString(h[:])
			_, e := executeTrackerValidation(context.Background(), r, p, "source", "out")
			require.Error(t, e)
			require.NotContains(t, e.Error(), "secret")
		})
	}
}
func TestBoundedWorkerOutput(t *testing.T) {
	var b boundedWorkerOutput
	n, e := b.Write([]byte("ok"))
	require.NoError(t, e)
	require.Equal(t, 2, n)
	_, e = b.Write(make([]byte, 1<<20))
	require.Error(t, e)
	require.Equal(t, "ok", b.String())
}
