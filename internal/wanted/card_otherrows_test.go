package wanted_test

import (
	"strings"
	"testing"
)

// A row is four PIV slots (docs/reference/bundle.md), so a non-empty other_rows needs piv among the applications. An
// empty list means the same as no member. A card without piv has no rows, however they are written.
func TestOtherRowsNeedPivAndAnEmptyListDoesNot(t *testing.T) {
	head := "version: 1\nserial: \"1\"\nkind: root\n"
	refused := []struct{ name, apps, rows string }{
		{"fido2 only, one row", "[fido2]", "[3]"},
		{"openpgp only, one row", "[openpgp]", "[2]"},
		{"openpgp and fido2, all rows", "[openpgp, fido2]", "[2, 3, 4, 5, 6]"},
		{"fido2 only, one row in a block list", "[fido2]", "\n  - 6"},
		{"fido2 only, the last row", "[fido2]", "[6]"},
		{"openpgp and fido2 in the other order", "[fido2, openpgp]", "[4, 2]"},
	}
	for _, r := range refused {
		text := head + "applications: " + r.apps + "\nother_rows: " + r.rows + "\n"
		_ = refuseCard(t, text, 5, "other_rows needs piv")
		// The same file with piv in place of the applications is accepted: the one fault is the missing piv.
		c := mustCard(t, "root-a", head+"applications: [piv]\nother_rows: "+r.rows+"\n")
		if len(c.OtherRows) == 0 {
			t.Errorf("%s: the rows are lost once piv is the application", r.name)
		}
	}
	accepted := []struct{ name, apps, rows string }{
		{"fido2 only, an empty list", "[fido2]", "[]"},
		{"openpgp only, an empty list", "[openpgp]", "[]"},
		{"openpgp and fido2, an empty list", "[openpgp, fido2]", "[]"},
		{"piv, an empty list", "[piv]", "[]"},
		{"fido2 only, an empty list with spaces", "[fido2]", "[ ]"},
	}
	for _, r := range accepted {
		c := mustCard(t, "root-a", head+"applications: "+r.apps+"\nother_rows: "+r.rows+"\n")
		if c.OtherRows != nil {
			t.Errorf("%s: an empty list gives %v, want nil", r.name, c.OtherRows)
		}
	}
	// No member is the same as an empty list.
	c := mustCard(t, "root-a", head+"applications: [fido2]\n")
	if c.OtherRows != nil {
		t.Errorf("no member gives %v, want nil", c.OtherRows)
	}
	// A null, a mapping and a string are no list, and are not "empty" on a card without piv.
	for _, v := range []string{"null", "~", "{}", "\"\"", "0"} {
		e := refuseCard(t, head+"applications: [fido2]\nother_rows: "+v+"\n", 5)
		if e != nil && strings.Contains(e.Error(), "needs piv") {
			t.Errorf("other_rows: %s on a card without piv is judged as a list: %v", v, e)
		}
	}
}
