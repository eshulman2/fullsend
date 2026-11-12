package jira

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestJournalCommentDoesNotReplayOnRedirect(t *testing.T) {
	client, mux := setupTest(t)
	var calls, replayed atomic.Int32
	mux.HandleFunc("POST /rest/api/3/issue/TEST-1/comment", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/replayed")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/replayed", func(w http.ResponseWriter, r *http.Request) { replayed.Add(1); w.WriteHeader(201) })
	_, err := client.CreateJournalComment(context.Background(), "TEST-1", "Evidence", nil)
	require.Error(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.Zero(t, replayed.Load())
}
