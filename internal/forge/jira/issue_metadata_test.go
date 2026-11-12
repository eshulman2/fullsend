package jira

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetadataReadsBoundFieldsAndPreserveDisclosurePresence(t *testing.T) {
	client, mux := setupTest(t)
	mux.HandleFunc("/rest/api/3/issue/PROJ-1", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "security,labels,status,assignee,project,issuetype", r.URL.Query().Get("fields"))
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"key":"PROJ-1","fields":{"security":null,"labels":["public"]}}`))
		require.NoError(t, err)
	})
	issue, err := client.GetIssueMetadata(context.Background(), "PROJ-1")
	require.NoError(t, err)
	require.JSONEq(t, "null", string(issue.Fields.Security))
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		var body searchRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, issueMetadataFields, body.Fields)
		writeJSON(t, w, http.StatusOK, SearchResult{Issues: []Issue{*issue}, IsLast: true})
	})
	got, err := client.SearchIssueMetadata(context.Background(), "project = PROJ", 2)
	require.NoError(t, err)
	require.Len(t, got, 1)
	var missing Issue
	require.NoError(t, json.Unmarshal([]byte(`{"fields":{}}`), &missing))
	require.Nil(t, missing.Fields.Security)
	mux.HandleFunc("/rest/api/3/issue/PROJ-2", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	_, err = client.GetIssueMetadata(context.Background(), "PROJ-2")
	require.Error(t, err)
}
