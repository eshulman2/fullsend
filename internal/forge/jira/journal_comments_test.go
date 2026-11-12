package jira

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateJournalCommentNeverReplaysPossibleWrites(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusUnauthorized} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			client, mux := setupTest(t)
			calls := 0
			mux.HandleFunc("/rest/api/3/issue/PROJ-1/comment", func(w http.ResponseWriter, r *http.Request) {
				calls++
				writeJSON(t, w, status, map[string]any{"errorMessages": []string{"unresolved"}})
			})
			_, err := client.CreateJournalComment(context.Background(), "PROJ-1", "evidence", nil)
			require.Error(t, err)
			require.Equal(t, 1, calls)
		})
	}
}
func TestJournalCommentOriginalRequestAndDirectVerification(t *testing.T) {
	client, mux := setupTest(t)
	mux.HandleFunc("/rest/api/3/issue/PROJ-1/comment", func(w http.ResponseWriter, r *http.Request) {
		var got commentRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		require.Len(t, got.Properties, 1)
		require.Equal(t, "bound", got.Properties[0].Key)
		writeJSON(t, w, http.StatusCreated, Comment{ID: "100", Body: got.Body, Properties: got.Properties})
	})
	comment, err := client.CreateJournalComment(context.Background(), "PROJ-1", "Validated result", []CommentProperty{{Key: "bound", Value: json.RawMessage(`{"source":"sha"}`)}})
	require.NoError(t, err)
	require.Equal(t, "100", comment.ID)
	mux.HandleFunc("/rest/api/3/issue/PROJ-1/comment/100", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "properties", r.URL.Query().Get("expand"))
		writeJSON(t, w, http.StatusOK, *comment)
	})
	got, err := client.GetCommentWithProperties(context.Background(), "PROJ-1", "100")
	require.NoError(t, err)
	require.Equal(t, comment.ID, got.ID)
	_, err = client.CreateJournalComment(context.Background(), "PROJ-1", "result", []CommentProperty{{Key: "invalid", Value: json.RawMessage(`invalid`)}})
	require.Error(t, err)
}
func TestCompleteCommentListingRejectsTruncation(t *testing.T) {
	for _, scenario := range []string{"complete", "too_many", "wrong_offset", "empty_page"} {
		t.Run(scenario, func(t *testing.T) {
			client, mux := setupTest(t)
			mux.HandleFunc("/rest/api/3/issue/PROJ-1/comment", func(w http.ResponseWriter, r *http.Request) {
				start, _ := strconv.Atoi(r.URL.Query().Get("startAt"))
				page := CommentPage{StartAt: start, Total: 2, MaxResults: 1, Comments: []Comment{{ID: strconv.Itoa(start + 1)}}}
				switch scenario {
				case "too_many":
					page.Total = 1001
				case "wrong_offset":
					page.StartAt = start + 1
				case "empty_page":
					page.Comments = nil
				}
				writeJSON(t, w, http.StatusOK, page)
			})
			comments, err := client.ListCommentsComplete(context.Background(), "PROJ-1", 1000)
			if scenario == "complete" {
				require.NoError(t, err)
				require.Len(t, comments, 2)
			} else {
				require.Error(t, err)
			}
		})
	}
	client, _ := setupTest(t)
	_, err := client.ListCommentsComplete(context.Background(), "PROJ-1", 0)
	require.Error(t, err)
}
func TestJournalCommentRejectsMalformedResponse(t *testing.T) {
	for _, body := range []string{`null`, `{"id":""}`, `invalid`, strings.Repeat("x", (1<<20)+1)} {
		t.Run(strconv.Itoa(len(body)), func(t *testing.T) {
			client, mux := setupTest(t)
			calls := 0
			mux.HandleFunc("/rest/api/3/issue/PROJ-1/comment", func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(body))
			})
			_, err := client.CreateJournalComment(context.Background(), "PROJ-1", "evidence", nil)
			require.Error(t, err)
			require.Equal(t, 1, calls)
		})
	}
}

func TestDirectJournalCommentLookupRejectsWrongIdentityAndMissingComment(t *testing.T) {
	client, mux := setupTest(t)
	mux.HandleFunc("/rest/api/3/issue/PROJ-1/comment/100", func(w http.ResponseWriter, r *http.Request) { writeJSON(t, w, http.StatusOK, Comment{ID: "different"}) })
	_, err := client.GetCommentWithProperties(context.Background(), "PROJ-1", "100")
	require.Error(t, err)
	_, err = client.GetCommentWithProperties(context.Background(), "PROJ-1", "missing")
	require.Error(t, err)
}
