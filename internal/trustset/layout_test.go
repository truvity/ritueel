package trustset_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// When the bundle page lists another file in "The layout" for a trust set, this list and the page
// change together (record 0006, rule 12 says that a trust set is one numbered folder and links to
// that row of the page).
func TestFileNamesAreThePagesThree(t *testing.T) {
	want := []string{"root-list.json", "root-list.jws", "ca-bundle.pem"}
	if got := trustset.FileNames(); !slices.Equal(got, want) {
		t.Fatalf("FileNames() = %q, want %q", got, want)
	}
	if trustset.RootListFile != "root-list.json" || trustset.RootListJWSFile != "root-list.jws" || trustset.CABundleFile != "ca-bundle.pem" {
		t.Errorf("the constants are %q %q %q", trustset.RootListFile, trustset.RootListJWSFile, trustset.CABundleFile)
	}
}

func TestFileNamesIsANewListEachTime(t *testing.T) {
	a := trustset.FileNames()
	a[0], a[1], a[2] = "x", "y", "z"
	if got := trustset.FileNames(); got[0] != "root-list.json" || got[1] != "root-list.jws" || got[2] != "ca-bundle.pem" {
		t.Fatalf("a change of the result changed the table: %q", got)
	}
	b := trustset.FileNames()
	c := trustset.FileNames()
	if &b[0] == &c[0] {
		t.Errorf("two calls share one array")
	}
}

func TestFileNamesAreNamesOfTheWriter(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range trustset.FileNames() {
		if err := fsx.CheckName(n); err != nil {
			t.Errorf("fsx.CheckName(%q): %v", n, err)
		}
		folded := strings.ToLower(n)
		if seen[folded] {
			t.Errorf("two names differ only by case: %q", n)
		}
		seen[folded] = true
	}
	if len(seen) != 3 {
		t.Errorf("there are %d distinct names, the page has three", len(seen))
	}
}

// The proposed mode: public material that a host and a person read. The owner's read bit is what
// the writer needs; the rest is one constant.
func TestFileMode(t *testing.T) {
	if trustset.FileMode != 0o644 {
		t.Errorf("FileMode = %o, want 644", trustset.FileMode)
	}
	if trustset.FileMode&0o400 == 0 {
		t.Errorf("the owner cannot read")
	}
	if trustset.FileMode&0o111 != 0 {
		t.Errorf("a file of a trust set is executable: %o", trustset.FileMode)
	}
}

func TestLimitsAreThePagesLimits(t *testing.T) {
	if trustset.MaxRoots != 26 {
		t.Errorf("MaxRoots = %d, a label is one of the 26 letters A to Z", trustset.MaxRoots)
	}
	maxBytes, reader := trustset.MaxBytes, rootlist.MaxBytes
	if maxBytes != reader {
		t.Errorf("MaxBytes = %d, the reader's limit is %d", maxBytes, reader)
	}
	if maxBytes != 256*1024 {
		t.Errorf("MaxBytes = %d, the page says 256 KiB", maxBytes)
	}
	if trustset.MaxEarlier != 4096 {
		t.Errorf("MaxEarlier = %d, want 4096", trustset.MaxEarlier)
	}
}

func TestTheTypTextsAreThePages(t *testing.T) {
	if rootlist.ListTyp != "root-list+json" {
		t.Errorf("ListTyp = %q, the page says root-list+json", rootlist.ListTyp)
	}
	if rootlist.RemovalTyp != "root-removal+json" {
		t.Errorf("RemovalTyp = %q, the page says root-removal+json", rootlist.RemovalTyp)
	}
}

func TestErrorKindsAreDistinct(t *testing.T) {
	if trustset.ErrParams == nil || trustset.ErrSign == nil {
		t.Fatal("an error kind is nil")
	}
	if errors.Is(trustset.ErrParams, trustset.ErrSign) {
		t.Fatal("ErrParams and ErrSign are one error")
	}
	if !printable(trustset.ErrParams.Error()) || !printable(trustset.ErrSign.Error()) {
		t.Errorf("the text of an error kind is not printable ASCII")
	}
	if trustset.ErrParams.Error() == trustset.ErrSign.Error() {
		t.Errorf("the two kinds have one text")
	}
}
