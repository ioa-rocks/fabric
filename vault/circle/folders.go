package circle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FolderDecl is one declared folder replica: this device's commitment to
// keep a bucket as a real directory (file-sync-fuse memo "folder-replica").
// Like mounts, declarations persist and the daemon owns their lifecycle.
type FolderDecl struct {
	Bucket string `json:"bucket"` // bucket ID
}

func (c *Circle) foldersPath() string { return filepath.Join(c.Path, "folders.json") }

// FolderStateDir is where a folder replica keeps its scan database and
// shadow store: <state>/folders/<bucket-id>.
func (c *Circle) FolderStateDir(bucketID string) string {
	return filepath.Join(c.Path, "folders", bucketID)
}

// Folders returns directory → declaration. One bucket may be declared at
// one directory per device.
func (c *Circle) Folders() (map[string]FolderDecl, error) {
	raw, err := os.ReadFile(c.foldersPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]FolderDecl{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out map[string]FolderDecl
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("reading folders: %w", err)
	}
	return out, nil
}

// SetFolder declares a folder replica at dir.
func (c *Circle) SetFolder(dir string, f FolderDecl) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("folder must be an absolute path")
	}
	folders, err := c.Folders()
	if err != nil {
		return err
	}
	for d, cur := range folders {
		if cur.Bucket == f.Bucket && d != dir {
			return fmt.Errorf("bucket %.12s is already a folder at %s", f.Bucket, d)
		}
	}
	folders[dir] = f
	return c.writeFolders(folders)
}

// RemoveFolder drops the declaration for dir; the directory is left as is.
func (c *Circle) RemoveFolder(dir string) error {
	folders, err := c.Folders()
	if err != nil {
		return err
	}
	if _, ok := folders[dir]; !ok {
		return fmt.Errorf("no folder declared at %s", dir)
	}
	delete(folders, dir)
	return c.writeFolders(folders)
}

func (c *Circle) writeFolders(folders map[string]FolderDecl) error {
	raw, err := json.MarshalIndent(folders, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.foldersPath(), raw, 0o600)
}
