package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// CreateJournalComment makes exactly one comment POST. The journal owner, not
// HTTP retry logic, reconciles every uncertain response including rate limits.
func (c *LiveClient) CreateJournalComment(ctx context.Context, key, body string, properties []CommentProperty) (*Comment, error) {
	adf, err := MarkdownToADF(body)
	if err != nil {
		return nil, errors.New("invalid journal comment body")
	}
	data, err := json.Marshal(commentRequest{Body: adf, Properties: properties})
	if err != nil {
		return nil, errors.New("invalid journal comment")
	}
	endpoint, err := c.apiURL(ctx, "/issue/"+url.PathEscape(key)+"/comment")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("invalid journal comment request")
	}
	if _, err = c.authorize(ctx, req, ""); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	single := *c.httpClient
	single.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := single.Do(req)
	if err != nil {
		return nil, errors.New("journal comment acceptance unknown")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("journal comment acceptance unresolved")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("invalid journal comment response")
	}
	var comment Comment
	if json.Unmarshal(raw, &comment) != nil || comment.ID == "" {
		return nil, errors.New("invalid journal comment response")
	}
	return &comment, nil
}

// ListCommentsComplete returns bounded complete history or an error, never a
// silently truncated prefix that could be mistaken for proof of absence.
func (c *LiveClient) ListCommentsComplete(ctx context.Context, key string, limit int) ([]Comment, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("invalid comment reconciliation limit")
	}
	var comments []Comment
	start := 0
	for page := 0; page < 10; page++ {
		path := fmt.Sprintf("/issue/%s/comment?orderBy=created&maxResults=100&startAt=%d&expand=properties", url.PathEscape(key), start)
		var result CommentPage
		if err := c.do(ctx, http.MethodGet, path, nil, &result); err != nil {
			return nil, err
		}
		if result.StartAt != start || result.Total < start+len(result.Comments) || result.Total > limit || len(comments)+len(result.Comments) > limit {
			return nil, errors.New("comment history incomplete")
		}
		comments = append(comments, result.Comments...)
		start += len(result.Comments)
		if start == result.Total {
			return comments, nil
		}
		if len(result.Comments) == 0 {
			return nil, errors.New("comment history incomplete")
		}
	}
	return nil, errors.New("comment history incomplete")
}
func (c *LiveClient) GetCommentWithProperties(ctx context.Context, key, id string) (*Comment, error) {
	var comment Comment
	path := "/issue/" + url.PathEscape(key) + "/comment/" + url.PathEscape(id) + "?expand=properties"
	if err := c.do(ctx, http.MethodGet, path, nil, &comment); err != nil {
		return nil, err
	}
	if comment.ID != id {
		return nil, errors.New("comment identity mismatch")
	}
	return &comment, nil
}
