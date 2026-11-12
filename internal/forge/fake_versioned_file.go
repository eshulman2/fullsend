package forge

import (
	"context"
	"fmt"
	"slices"
)

// Fake revisions bind the complete stored file. Only tests use this backend.
func (f *FakeClient) ReadVersionedFile(_ context.Context, owner, repo, branch, path string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err("ReadVersionedFile"); err != nil {
		return nil, "", err
	}
	key := fmt.Sprintf("%s/%s/%s@%s", owner, repo, path, branch)
	content, ok := f.FileContentsRef[key]
	if !ok {
		return nil, "", ErrNotFound
	}
	if f.versionedFileRevisions == nil {
		f.versionedFileRevisions = map[string]string{}
	}
	if f.versionedFileRevisions[key] == "" {
		f.versionedFileSequence++
		f.versionedFileRevisions[key] = fmt.Sprintf("versioned-%d", f.versionedFileSequence)
	}
	return slices.Clone(content), f.versionedFileRevisions[key], nil
}
func (f *FakeClient) WriteFileIfRevision(_ context.Context, owner, repo, branch, path, revision, message string, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err("WriteFileIfRevision"); err != nil {
		return err
	}
	key := fmt.Sprintf("%s/%s/%s@%s", owner, repo, path, branch)
	_, exists := f.FileContentsRef[key]
	if revision == "" && exists || revision != "" && (!exists || revision != f.versionedFileRevisions[key]) {
		return ErrConflict
	}
	if f.FileContentsRef == nil {
		f.FileContentsRef = map[string][]byte{}
	}
	if f.versionedFileRevisions == nil {
		f.versionedFileRevisions = map[string]string{}
	}
	f.versionedFileSequence++
	f.versionedFileRevisions[key] = fmt.Sprintf("versioned-%d", f.versionedFileSequence)
	f.FileContentsRef[key] = slices.Clone(content)
	return nil
}
