package github

import (
	"context"
	"github.com/fullsend-ai/fullsend/internal/forge"
)

// GitHub control-journal storage is not enabled before backend conformance.
func (c *LiveClient) ReadVersionedFile(context.Context, string, string, string, string) ([]byte, string, error) {
	return nil, "", forge.ErrNotSupported
}
func (c *LiveClient) WriteFileIfRevision(context.Context, string, string, string, string, string, string, []byte) error {
	return forge.ErrNotSupported
}
