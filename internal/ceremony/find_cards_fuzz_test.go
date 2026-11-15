//go:build linux || darwin

package ceremony_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/wanted"
)

// FuzzFindCardFiles puts two card files of any bytes in a first-apply bundle in memory. Find gives a result
// for the bundle exactly when the reader accepts both files and they name two cards; otherwise it is a
// refusal of a wanted file with a printable text. It never panics. No target starts an outside program.
func FuzzFindCardFiles(f *testing.F) {
	for _, s := range []string{cfRootA, cfRootB, cfDayOne, cfBad, "", "---\n", "{}", "[", strings.Repeat("[", 300), "a: &x 1\nb: *x\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\nother_rows: [2]\n", "\ufeffversion: 1\n", "x: \xff\n"} {
		f.Add([]byte(s), []byte(cfRootB))
		f.Add([]byte(cfRootA), []byte(s))
	}
	f.Add([]byte(cfRootB), []byte(cfRootB))
	f.Fuzz(func(t *testing.T, one, two []byte) {
		m := pfMem(pfFiles())
		m.put("want/cards/a.yaml", &pfNode{kind: "file", data: one})
		m.put("want/cards/b.yaml", &pfNode{kind: "file", data: two})
		found, err := ceremony.Find(t.Context(), ceremony.FindInput{FS: pfFS{m}})
		a, errA := wanted.ParseCard("a", one)
		b, errB := wanted.ParseCard("b", two)
		wantOK := errA == nil && errB == nil && a.SerialKey() != b.SerialKey()
		if wantOK {
			if err != nil || found.Nothing() || len(found.Wanted) != 2 {
				t.Fatalf("Find = %+v, %v for two good files", found, err)
			}
			return
		}
		if err == nil || found != nil {
			t.Fatalf("Find accepted what the reader refuses: %+v", found)
		}
		if !pfPrintable(err.Error()) || !strings.Contains(err.Error(), "want/cards/") || !strings.Contains(err.Error(), "nothing was written") {
			t.Fatalf("error = %+q", err.Error())
		}
		if k := pfKind(err); k != "failure" {
			t.Fatalf("kind = %s", k)
		}
	})
}
