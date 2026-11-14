//go:build linux || darwin

package history

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// The walk inside the trust sets and the folders of copies reads folders, and a folder that cannot
// be read is not "nothing in it": the check is not done.

func TestFolderInsideATrustSetOrOfCopiesThatCannotBeListedStopsTheCheck(t *testing.T) {
	build := func(t *testing.T) (*mnode, *rec) {
		b := newBundle(t)
		r := b.apply()
		b.put("trust/"+r.set+"/sub/x.pem", []byte("x"))
		b.put("history/"+r.folder+"/wanted/sub/y.yaml", []byte("x"))
		return loadMem(t, b.dir), r
	}
	for _, which := range []string{"the set", "a folder in the set", "the copies", "a folder of the copies"} {
		t.Run(which, func(t *testing.T) {
			m, r := build(t)
			target := map[string]string{
				"the set":                "trust/" + r.set,
				"a folder in the set":    "trust/" + r.set + "/sub",
				"the copies":             "history/" + r.folder + "/wanted",
				"a folder of the copies": "history/" + r.folder + "/wanted/sub",
			}[which]
			m.get(target).readErr = fs.ErrPermission
			rep, err := runMem(t, m)
			if !errors.Is(err, fs.ErrPermission) || rep != nil {
				t.Errorf("Check = %v, %v; want a refused permission", rep, err)
			}
		})
	}
}

// The limit on the names that the walk looks at holds in a folder below the first level too.
func TestWalkLimitHoldsInAFolderBelowTheFirstLevel(t *testing.T) {
	b := newBundle(t)
	r := b.apply()
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		b.put("trust/"+r.set+"/sub/"+n+".pem", []byte("x"))
	}
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	// The ceremony folder and the set (one each), the five names of the ceremony folder, the set's
	// two files and the folder (three names), the five files of the folder, the one copy.
	const names = 1 + 1 + 5 + 3 + 5 + 1
	lim := limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode, walkEntries: names}
	rep, err := runFS(t, root, &lim)
	if err != nil {
		t.Fatalf("a limit of %d names: %v", names, err)
	}
	if got := len(findingsOf(rep)); got != 5 {
		t.Errorf("%d findings, want 5 unlisted files", got)
	}
	lim.walkEntries = names - 1
	if _, err := runFS(t, root, &lim); !errors.Is(err, ErrTooMuch) {
		t.Errorf("a limit of %d names: err = %v, want ErrTooMuch", names-1, err)
	}
}

// The depth of the copies is the depth of a listed path: a file at the deepest level is a notice, and
// a folder at the deepest level is reported as the folder.
func TestFileInTheCopiesIsFoundDownToTheDepthOfAListedPath(t *testing.T) {
	chain := func(n int) string { return strings.TrimSuffix(strings.Repeat("d/", n), "/") }
	levels := files.MaxPathElements
	t.Run("a file at the deepest level", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		p := "history/" + r.folder + "/wanted/" + chain(levels-1) + "/f"
		b.put(p, []byte("x"))
		wantFindings(t, b.run(), []wf{{UnexpectedFile, p}})
	})
	t.Run("a folder at the deepest level", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		folder := "history/" + r.folder + "/wanted/" + chain(levels)
		b.put(folder+"/inside", []byte("x"))
		wantFindings(t, b.run(), []wf{{UnexpectedFile, folder}})
	})
}
