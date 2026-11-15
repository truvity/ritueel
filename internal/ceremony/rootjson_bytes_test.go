package ceremony_test

import (
	"strings"
	"testing"
)

// The root.json of a key that has an X.509 key only is the same bytes as before keys of two kinds were
// built: seven members in the order of RFC 8785, none of them about OpenPGP. The text is spelled out
// here from the page (docs/reference/bundle.md, "root.json": the first apply of an X.509 test root
// writes version, label, store, test, created_at, x509_spki_sha256 and removal_sha256).
func TestTheRootJSONOfAnX509TestRootIsTheSevenMembersOfThePageAndNoOtherByte(t *testing.T) {
	_, m := mkGood(t)
	if len(m.Roots) != 2 {
		t.Fatalf("%d roots", len(m.Roots))
	}
	for _, root := range m.Roots {
		want := `{"created_at":"2026-11-20T10:00:00Z","label":"` + root.Label + `","removal_sha256":"` + root.RemovalSHA256 +
			`","store":"software","test":true,"version":1,"x509_spki_sha256":"` + root.Pin + `"}`
		if string(root.RootJSON) != want {
			t.Errorf("root.json of %s is\n%s\nwant\n%s", root.Label, root.RootJSON, want)
		}
		for _, w := range []string{"openpgp", "revocations"} {
			if strings.Contains(string(root.RootJSON), w) {
				t.Errorf("root.json of %s holds %q", root.Label, w)
			}
		}
	}
}
