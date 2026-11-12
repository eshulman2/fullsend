package trackerflow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStrictJSONRejectsDuplicateKeysAtEveryLevel(t *testing.T) {
	for _, raw := range []string{`{"case_id":"first","case_id":"second"}`, `{"intake":{"branch":"a","branch":"b"}}`, `{"targets":[{"branch":"a","branch":"b"}]}`, `{"branch":"first","\u0062ranch":"second"}`, `{} {}`, `{"a":NaN}`, strings.Repeat("[", 66) + strings.Repeat("]", 66)} {
		var value any
		require.Error(t, DecodeStrict([]byte(raw), &value), raw)
	}
	var request Request
	require.Error(t, DecodeStrict([]byte(`{"unknown":true}`), &request))
	var value any
	require.NoError(t, DecodeStrict([]byte(`{"nested":[{"branch":"release/1"},true,null,1]}`), &value))
	m := manifest()
	p := protectedProfile(m)
	env := string(marshal(p))
	env = strings.Replace(env, `"agent":"triage"`, `"agent":"triage","agent":"code"`, 1)
	_, err := LoadProfile(func(string) string { return env })
	require.Error(t, err)
}
func TestRequestAndManifestShareCanonicalSourceValidation(t *testing.T) {
	for _, origin := range []string{"http://github.com/example/repo", "https://user:secret@github.com/example/repo", "https://github.com/example/repo?token=secret", "https://github.com/example/repo#fragment", "https://github.com/example/repo/", "https://github.com/example/../repo", "https://github.com/example/%72epo", "https://github.com//example/repo", "https://GitHub.com/example/repo"} {
		r := request()
		r.Repository = origin
		require.Error(t, r.Validate(), origin)
		m := manifest()
		m.Targets[0].Repository = origin
		require.Error(t, m.Validate(), origin)
	}
	for _, branch := range []string{"-main", "../main", "release//1", "release/", "release/.hidden", "release/topic.lock", "main.", "main name", "main\ncode", "main@{1}", "main:code", "refs/heads/a\\b"} {
		r := request()
		r.Branch = branch
		require.Error(t, r.Validate(), branch)
		m := manifest()
		m.Targets[0].Branch = branch
		require.Error(t, m.Validate(), branch)
	}
	for _, branch := range []string{"main", "release/4.18", "topic-fix_1", "trial+1", "feature@release"} {
		r := request()
		r.Branch = branch
		require.NoError(t, r.Validate())
	}
}
