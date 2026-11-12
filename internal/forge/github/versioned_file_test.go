package github

import (
	"context"
	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestJournalFileStorageNotEnabled(t *testing.T) {
	c := &LiveClient{}
	_, _, err := c.ReadVersionedFile(context.Background(), "o", "r", "b", "p")
	require.ErrorIs(t, err, forge.ErrNotSupported)
	require.ErrorIs(t, c.WriteFileIfRevision(context.Background(), "o", "r", "b", "p", "r", "m", nil), forge.ErrNotSupported)
}
