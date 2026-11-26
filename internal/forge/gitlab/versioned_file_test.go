package gitlab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/stretchr/testify/require"
)

func TestReadVersionedFileRequiresLastCommit(t *testing.T) {
	for _, body := range []string{`{"encoding":"base64","content":"eA==","last_commit_id":"file-revision"}`, `{"encoding":"base64","content":"eA=="}`, `{"encoding":"text","content":"x","last_commit_id":"r"}`, `{"encoding":"base64","content":"!","last_commit_id":"r"}`, `bad`} {
		t.Run(body, func(t *testing.T) {
			c, mux := setupTest(t)
			mux.HandleFunc("GET /api/v4/projects/o%2Fr/repository/files/journal.json", func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "state", r.URL.Query().Get("ref"))
				fmt.Fprint(w, body)
			})
			data, rev, err := c.ReadVersionedFile(context.Background(), "o", "r", "state", "journal.json")
			if body == `{"encoding":"base64","content":"eA==","last_commit_id":"file-revision"}` {
				require.NoError(t, err)
				require.Equal(t, "x", string(data))
				require.Equal(t, "file-revision", rev)
			} else {
				require.Error(t, err)
			}
		})
	}
}
func TestWriteVersionedFileUsesAtomicLastCommitGuard(t *testing.T) {
	c, mux := setupTest(t)
	var put atomic.Int32
	mux.HandleFunc("PUT /api/v4/projects/o%2Fr/repository/files/journal.json", func(w http.ResponseWriter, r *http.Request) {
		put.Add(1)
		var payload map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, "file-revision", payload["last_commit_id"])
		require.Equal(t, "state", payload["branch"])
		require.Equal(t, base64.StdEncoding.EncodeToString([]byte("next")), payload["content"])
		fmt.Fprint(w, `{"file_path":"journal.json"}`)
	})
	require.NoError(t, c.WriteFileIfRevision(context.Background(), "o", "r", "state", "journal.json", "file-revision", "checkpoint [skip ci]", []byte("next")))
	require.Equal(t, int32(1), put.Load())
}
func TestVersionedWriteConflictAndNoRetry(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusNotFound, http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusForbidden} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, mux := setupTest(t)
			var calls atomic.Int32
			mux.HandleFunc("PUT /api/v4/projects/o%2Fr/repository/files/journal.json", func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				fmt.Fprint(w, `{"message":"file has changed"}`)
			})
			err := c.WriteFileIfRevision(context.Background(), "o", "r", "state", "journal.json", "old", "checkpoint", []byte("x"))
			require.Error(t, err)
			if status == 400 || status == 404 || status == 409 {
				require.ErrorIs(t, err, forge.ErrConflict)
			}
			require.Equal(t, int32(1), calls.Load())
		})
	}
}
func TestVersionedCreateNeverUpserts(t *testing.T) {
	c, mux := setupTest(t)
	mux.HandleFunc("POST /api/v4/projects/o%2Fr/repository/files/journal.json", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.NotContains(t, payload, "last_commit_id")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"message":"A file with this name already exists"}`)
	})
	require.ErrorIs(t, c.WriteFileIfRevision(context.Background(), "o", "r", "state", "journal.json", "", "initialize", []byte("x")), forge.ErrConflict)
}

func TestVersionedWriteRecognizesOnlyExactReferenceRaceRejection(t *testing.T) {
	const rejection = "9:reference update: reference does not point to expected object."
	for _, tc := range []struct {
		name     string
		status   int
		message  string
		conflict bool
	}{
		{"reference CAS rejected", http.StatusBadRequest, rejection, true},
		{"unknown bad request", http.StatusBadRequest, "reference update failed", false},
		{"same text in server failure", http.StatusInternalServerError, rejection, false},
		{"same text in permission failure", http.StatusForbidden, rejection, false},
		{"same text in rate limit", http.StatusTooManyRequests, rejection, false},
		{"extra suffix is not proof", http.StatusBadRequest, rejection + " Response acknowledgement lost.", false},
		{"extra prefix is not proof", http.StatusBadRequest, "Unknown failure: " + rejection, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, mux := setupTest(t)
			var calls atomic.Int32
			mux.HandleFunc("PUT /api/v4/projects/o%2Fr/repository/files/journal.json", func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"message": tc.message}))
			})
			err := c.WriteFileIfRevision(context.Background(), "o", "r", "state", "journal.json", "old", "checkpoint", []byte("next"))
			require.Error(t, err)
			if tc.conflict {
				require.ErrorIs(t, err, forge.ErrConflict)
			} else {
				require.NotErrorIs(t, err, forge.ErrConflict)
			}
			require.Equal(t, int32(1), calls.Load(), "the transport must never replay a conditional write")
		})
	}
}
