package forge

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeVersionedFileCASAndABA(t *testing.T) {
	ctx := context.Background()
	f := NewFakeClient()
	require.NoError(t, f.WriteFileIfRevision(ctx, "o", "r", "state", "j.json", "", "create", []byte("a")))
	content, old, err := f.ReadVersionedFile(ctx, "o", "r", "state", "j.json")
	require.NoError(t, err)
	content[0] = 'z'
	_, unchanged, err := f.ReadVersionedFile(ctx, "o", "r", "state", "j.json")
	require.NoError(t, err)
	require.Equal(t, old, unchanged)
	require.NoError(t, f.WriteFileIfRevision(ctx, "o", "r", "state", "j.json", old, "to b", []byte("b")))
	_, next, err := f.ReadVersionedFile(ctx, "o", "r", "state", "j.json")
	require.NoError(t, err)
	require.NoError(t, f.WriteFileIfRevision(ctx, "o", "r", "state", "j.json", next, "back to a", []byte("a")))
	require.ErrorIs(t, f.WriteFileIfRevision(ctx, "o", "r", "state", "j.json", old, "stale", []byte("c")), ErrConflict)
	require.ErrorIs(t, f.WriteFileIfRevision(ctx, "o", "r", "state", "j.json", "", "create", []byte("x")), ErrConflict)
}

func TestFakeVersionedFileSeededRevisionAndCopies(t *testing.T) {
	ctx := context.Background()
	f := &FakeClient{FileContentsRef: map[string][]byte{"o/r/j.json@b": []byte("seed")}}
	data, revision, err := f.ReadVersionedFile(ctx, "o", "r", "b", "j.json")
	require.NoError(t, err)
	require.NotEmpty(t, revision)
	data[0] = 'x'
	again, _, err := f.ReadVersionedFile(ctx, "o", "r", "b", "j.json")
	require.NoError(t, err)
	require.Equal(t, "seed", string(again))
	empty := &FakeClient{}
	require.NoError(t, empty.WriteFileIfRevision(ctx, "o", "r", "b", "j.json", "", "create", []byte("content")))
}
