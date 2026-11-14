//go:build linux || darwin

package history

import (
	"slices"
	"strings"
	"testing"
)

// FuzzNameInATrustSet puts one entry with any name into a trust set that a record lists, in a bundle
// that was clean before, as a file, a folder, a link or a FIFO, at the top of the set or in a folder
// of it. Whatever the name is: no panic, the run ends, nothing is changed, and the history is not clean,
// because nothing in the set may be there that no record lists. Only the two failing codes for the
// inside of a set are given, and never the notice: a name that a desktop system writes gets no
// exception.
func FuzzNameInATrustSet(f *testing.F) {
	for _, h := range hostileNames() {
		f.Add(h.name, uint8(0), false)
	}
	for _, name := range desktopNames {
		for kind := uint8(0); kind < 4; kind++ {
			f.Add(name, kind, kind%2 == 0)
		}
	}
	f.Add(".rt-abcdefghijk", uint8(1), true)
	f.Add("._\xff", uint8(0), false)
	f.Add(strings.Repeat("a", 256), uint8(0), true)

	b := newBundle(f)
	var recs [3]*rec
	for i := range recs {
		recs[i] = b.apply()
	}
	base := loadMem(f, b.dir)
	set := "trust/" + recs[1].set
	end := recs[2].digest[:8]

	f.Fuzz(func(t *testing.T, name string, pick uint8, deeper bool) {
		if name == "" || strings.Contains(name, "/") {
			t.Skip("not one name")
		}
		dir := set
		if deeper {
			dir += "/keyring"
		}
		kind := []string{"file", "dir", "link", "fifo"}[int(pick)%4]
		n := &mnode{kind: kind, data: []byte("EVIL")}
		if kind == "dir" {
			n.kids = map[string]*mnode{"evil.pem": {kind: "file", data: []byte("EVIL")}}
		}
		base.put(dir+"/"+name, n)
		defer func() {
			base.remove(dir + "/" + name)
			if deeper {
				base.remove(dir)
			}
		}()
		spy, log := newSpy(memFS{base})
		rep, err := runFS(t, spy, nil)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(log.changes) != 0 {
			t.Fatalf("calls that change the bundle: %v", log.changes)
		}
		checkReport(t, rep)
		if rep.Clean() {
			t.Fatalf("the history is clean with %q in a trust set", name)
		}
		for _, c := range rep.Reasons() {
			if c != FileUnlisted && c != UnexpectedName {
				t.Fatalf("the reason %s for an entry inside a trust set", c)
			}
		}
		if slices.Contains(rep.Warnings(), UnexpectedFile) {
			t.Fatalf("a notice for %q inside a trust set", name)
		}
		if eight, _, ok := rep.End(); !ok || eight != end {
			t.Fatalf("End() = %q, %v; want the end of the untouched history", eight, ok)
		}
	})
}
