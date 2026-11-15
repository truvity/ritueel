package ceremonytest

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Copy copies the plain files and folders of the bundle src to dst, with their modes. A link, a
// FIFO or any other special file in src fails the test: a copy that left it out would be a copy that
// is not what it says. dst must not exist, or be an empty folder; its parent must exist.
func Copy(t testing.TB, src, dst string) {
	t.Helper()
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle to copy cannot be looked at: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("ceremonytest: %s is not a folder", src)
	}
	if ents, err := os.ReadDir(dst); err == nil && len(ents) > 0 {
		t.Fatalf("ceremonytest: the folder to copy to is not empty: %s", dst)
	}
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if rel == "." {
				if err := os.Mkdir(to, info.Mode().Perm()); err != nil && !os.IsExist(err) {
					return err
				}
				return nil
			}
			return os.Mkdir(to, info.Mode().Perm())
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(to, data, info.Mode().Perm())
		}
		t.Fatalf("ceremonytest: %s is neither a plain file nor a folder, and a copy does not take it", rel)
		return nil
	})
	if err != nil {
		t.Fatalf("ceremonytest: the copy failed: %v", err)
	}
}
