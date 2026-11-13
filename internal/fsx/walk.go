package fsx

import "strings"

// folder is an open folder that an operation works in, and what the operation owes it: the walk
// opened it, so the operation closes it (release). The root is the writer's, and release leaves
// it open.
type folder struct {
	fs    FS
	owned bool
}

// release closes the folder if the walk opened it. It is safe to call twice. The error of the
// close is dropped: the handle was opened to read or to enter, nothing is written through it,
// and what the writer needs flushed it flushed with Sync, whose error it keeps.
func (f *folder) release() {
	if f != nil && f.owned {
		f.owned = false
		_ = f.fs.Close()
	}
}

// openFolder walks from root down the elements, one OpenDir at a time, and returns the last
// folder. An element that is a link, is not a folder or is not there makes OpenDir fail, and
// the walk returns that error with the path up to the failed element. No handle is left open on
// any path: each folder is closed as soon as the next one is open, and the last one is closed by
// the caller's release. With no element the folder is the root itself.
func openFolder(root FS, elems []string) (*folder, string, error) {
	cur := &folder{fs: root}
	for i, e := range elems {
		next, err := cur.fs.OpenDir(e)
		cur.release()
		if err != nil {
			return nil, strings.Join(elems[:i+1], "/"), err
		}
		cur = &folder{fs: next, owned: true}
	}
	return cur, "", nil
}

// dirPath is the path of the folder that holds the last element: "." for the root.
func dirPath(dir []string) string {
	if len(dir) == 0 {
		return "."
	}
	return strings.Join(dir, "/")
}

// joinPath is the path of name in the folder dir (as dirPath gives it).
func joinPath(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}
