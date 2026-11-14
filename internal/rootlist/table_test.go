package rootlist_test

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/testrepo"
)

// pageChecks is the table of "How a host reads it" in docs/reference/root-list.md, as the page
// means it: the number of each check and the code its failure gives. It is written out here so
// that a change of the code or of the order fails a test.
var pageChecks = []struct {
	n      int
	reason rootlist.Reason
}{
	{1, "malformed"},
	{2, "unknown-signer"},
	{3, "signature-invalid"},
	{4, "version-unsupported"},
	{5, "malformed"},
	{6, "rollback"},
	{7, "sequence-conflict"},
	{8, "unknown-signer"},
	{9, "removal-invalid"},
	{10, "insufficient-signers"},
	{11, "expired"},
}

func TestChecksIsThePagesTable(t *testing.T) {
	got := rootlist.Checks()
	if len(got) != len(pageChecks) {
		t.Fatalf("Checks() has %d entries, the page has %d", len(got), len(pageChecks))
	}
	for i, want := range pageChecks {
		if got[i].N != want.n || got[i].Reason != want.reason {
			t.Errorf("entry %d is check %d with %q, the page says check %d with %q", i, got[i].N, got[i].Reason, want.n, want.reason)
		}
		if got[i].Name == "" || !printable(got[i].Name) {
			t.Errorf("check %d has no name or one that is not printable ASCII: %q", got[i].N, got[i].Name)
		}
	}
	names := map[string]bool{}
	for _, c := range got {
		if names[c.Name] {
			t.Errorf("two checks are named %q", c.Name)
		}
		names[c.Name] = true
	}
	// The result is a copy: a caller cannot reorder the table that Verify runs.
	got[0], got[1] = got[1], got[0]
	if again := rootlist.Checks(); again[0].N != 1 || again[1].N != 2 {
		t.Errorf("a change of the result of Checks changed the table")
	}
}

func TestTheReasonCodesAreThePages(t *testing.T) {
	for _, c := range []struct {
		got  rootlist.Reason
		want string
	}{
		{rootlist.Malformed, "malformed"},
		{rootlist.UnknownSigner, "unknown-signer"},
		{rootlist.SignatureInvalid, "signature-invalid"},
		{rootlist.VersionUnsupported, "version-unsupported"},
		{rootlist.Rollback, "rollback"},
		{rootlist.SequenceConflict, "sequence-conflict"},
		{rootlist.RemovalInvalid, "removal-invalid"},
		{rootlist.InsufficientSigners, "insufficient-signers"},
		{rootlist.Expired, "expired"},
		{rootlist.CABundleMismatch, "ca-bundle-mismatch"},
	} {
		if string(c.got) != c.want {
			t.Errorf("the code %q is spelt %q on the page", c.got, c.want)
		}
	}
	if rootlist.WarningHeldExpired != "held-expired" {
		t.Errorf("the warning is %q, the page says held-expired", rootlist.WarningHeldExpired)
	}
	if rootlist.Version != 1 {
		t.Errorf("the version is %d, the page is version 1", rootlist.Version)
	}
	if rootlist.MaxBytes != 256*1024 {
		t.Errorf("MaxBytes is %d, the page says 256 KiB", rootlist.MaxBytes)
	}
	if rootlist.TimeLayout != "2006-01-02T15:04:05Z" {
		t.Errorf("TimeLayout is %q, the page says YYYY-MM-DDThh:mm:ssZ", rootlist.TimeLayout)
	}
}

// TestChecksMatchTheTableOfThePage reads the page itself: the rows of the table under "How a host
// reads it" give the number and the code of each check, and the code must agree.
func TestChecksMatchTheTableOfThePage(t *testing.T) {
	page := string(testrepo.Read(t, "docs", "reference", "root-list.md"))
	_, rest, ok := strings.Cut(page, "\n## How a host reads it\n")
	if !ok {
		t.Fatal("the section 'How a host reads it' is not on the page")
	}
	section, _, _ := strings.Cut(rest, "\n## ")
	row := regexp.MustCompile("(?m)^\\| (\\d+) \\| .* \\| `([a-z-]+)` \\|$")
	rows := row.FindAllStringSubmatch(section, -1)
	checks := rootlist.Checks()
	if len(rows) == 0 {
		t.Fatal("the table has no row")
	}
	if len(rows) != len(checks) {
		t.Fatalf("the page has %d rows, Checks() has %d entries", len(rows), len(checks))
	}
	for i, r := range rows {
		n, err := strconv.Atoi(r[1])
		if err != nil {
			t.Fatal(err)
		}
		if n != i+1 || checks[i].N != n || string(checks[i].Reason) != r[2] {
			t.Errorf("row %d of the page is check %d with %q; Checks() has check %d with %q", i+1, n, r[2], checks[i].N, checks[i].Reason)
		}
	}
}

func TestThePageIsFoundFromTheTestDirectory(t *testing.T) {
	if _, err := os.Stat(testrepo.Path(t, "docs", "reference", "root-list.md")); err != nil {
		t.Fatal(err)
	}
}

func TestTheBaseCasesAreAccepted(t *testing.T) {
	b := newBase(t)
	t.Run("an update with the same root keys, signed by one", func(t *testing.T) {
		for _, k := range []*key{b.w.a, b.w.b} {
			accepts(t, b.verify(t, b.cand, k))
		}
	})
	t.Run("against initial pins", func(t *testing.T) {
		v := rootlist.Verify(signed(t, b.cand, b.w.a), pinsOf(t, b.w.a.pin, b.w.b.pin), now)
		accepts(t, v)
	})
	t.Run("the accepted list is the list that was read", func(t *testing.T) {
		v := b.verify(t, b.cand, b.w.a)
		accepts(t, v)
		l := v.List
		if l.Version != 1 || l.Sequence != 8 || l.SignedAt != mustTime(signedAt) || l.ExpiresAt != mustTime(expiresAt) || l.LastRecordSHA256 != defaultLast {
			t.Errorf("fields read wrongly: %+v", l)
		}
		if len(l.Roots) != 2 || l.Roots[0] != (rootlist.Root{Label: "A", X509SPKISHA256: b.w.a.pin, OpenPGPFingerprint: b.w.a.fp()}) || l.Roots[1].Label != "B" {
			t.Errorf("roots read wrongly: %+v", l.Roots)
		}
		if pins := l.Pins(); len(pins) != 2 || pins[0] != b.w.a.pin || pins[1] != b.w.b.pin {
			t.Errorf("Pins() is %v", pins)
		}
		if len(l.Removals) != 0 {
			t.Errorf("removals read from nowhere: %+v", l.Removals)
		}
	})
	t.Run("the inputs are not changed and the verdict is the same twice", func(t *testing.T) {
		cand := signed(t, b.cand, b.w.a)
		json, jws := append([]byte{}, cand.JSON...), append([]byte{}, cand.JWS...)
		trust := b.trust(t)
		v1 := rootlist.Verify(cand, trust, now)
		v2 := rootlist.Verify(cand, trust, now)
		if string(cand.JSON) != string(json) || string(cand.JWS) != string(jws) {
			t.Errorf("Verify changed its input")
		}
		if v1.Accepted != v2.Accepted || v1.Reason != v2.Reason || v1.Check != v2.Check {
			t.Errorf("two runs differ")
		}
	})
}
