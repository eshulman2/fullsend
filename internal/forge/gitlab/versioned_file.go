package gitlab

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/forge"
)

// ReadVersionedFile returns GitLab's last_commit_id, which is the precondition
// its file update API actually enforces. A branch tip is not equivalent.
func (c *LiveClient) ReadVersionedFile(ctx context.Context, owner, repo, branch, path string) ([]byte, string, error) {
	apiPath := fmt.Sprintf("/projects/%s/repository/files/%s?ref=%s", projectPath(owner, repo), url.PathEscape(path), url.QueryEscape(branch))
	resp, err := c.get(ctx, apiPath)
	if err != nil {
		return nil, "", err
	}
	var f struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Revision string `json:"last_commit_id"`
	}
	if err = decodeJSON(resp, &f); err != nil {
		return nil, "", err
	}
	if f.Revision == "" || f.Encoding != "base64" {
		return nil, "", fmt.Errorf("versioned file metadata unavailable")
	}
	data, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil, "", fmt.Errorf("decode versioned file: %w", err)
	}
	return data, f.Revision, nil
}

// WriteFileIfRevision never downgrades or retries a conditional write.
func (c *LiveClient) WriteFileIfRevision(ctx context.Context, owner, repo, branch, path, revision, message string, content []byte) error {
	payload := map[string]string{"branch": branch, "content": base64.StdEncoding.EncodeToString(content), "encoding": "base64", "commit_message": message}
	method := http.MethodPost
	if revision != "" {
		method = http.MethodPut
		payload["last_commit_id"] = revision
	}
	apiPath := fmt.Sprintf("/projects/%s/repository/files/%s", projectPath(owner, repo), url.PathEscape(path))
	resp, err := c.doOnceNoRedirect(ctx, method, apiPath, payload)
	if err == nil {
		err = checkStatus(resp, http.StatusOK, http.StatusCreated)
		if err == nil {
			resp.Body.Close()
			return nil
		}
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.Message)
		if apiErr.StatusCode == http.StatusConflict || apiErr.StatusCode == http.StatusNotFound || (apiErr.StatusCode == http.StatusBadRequest && (strings.Contains(msg, "already exists") || strings.Contains(msg, "changed") || strings.Contains(msg, "last_commit") || strings.Contains(msg, "empty"))) {
			return fmt.Errorf("%w: versioned file changed or missing", forge.ErrConflict)
		}
	}
	return err
}

// doOnceNoRedirect prevents HTTP redirects from silently replaying a journal or
// scheduler write, even when the destination is on the same server.
func (c *LiveClient) doOnceNoRedirect(ctx context.Context, method, path string, body any) (*http.Response, error) {
	single := *c
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	single.http = &client
	return single.doAttempts(ctx, method, path, body, 1)
}
