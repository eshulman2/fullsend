package gitlab

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSagaWritesNeverReplayTransportFailuresOrRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusTemporaryRedirect} {
		for _, kind := range []string{"journal", "pipeline"} {
			t.Run(http.StatusText(status)+kind, func(t *testing.T) {
				client, mux := setupTest(t)
				var calls, redirects atomic.Int32
				path := "/api/v4/projects/o%2Fr/pipeline"
				method := "POST"
				if kind == "journal" {
					path = "/api/v4/projects/o%2Fr/repository/files/journal.json"
					method = "PUT"
				}
				mux.HandleFunc(method+" "+path, func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.Header().Set("Location", "/unexpected")
					w.WriteHeader(status)
				})
				mux.HandleFunc("/unexpected", func(w http.ResponseWriter, r *http.Request) { redirects.Add(1); w.WriteHeader(201) })
				var err error
				if kind == "journal" {
					err = client.WriteFileIfRevision(context.Background(), "o", "r", "state", "journal.json", "old", "checkpoint", []byte(`{}`))
				} else {
					_, err = client.CreatePipelineWithInputs(context.Background(), "o", "r", "worker", nil)
				}
				require.Error(t, err)
				require.EqualValues(t, 1, calls.Load())
				require.Zero(t, redirects.Load())
			})
		}
	}
}
