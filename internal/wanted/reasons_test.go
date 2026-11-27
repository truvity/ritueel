package wanted_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The wanted OpenPGP root file may list the revocation reasons to keep ready, in the member revocation_reasons
// (docs/reference/revocation-material.md, "What is made"; record 0007, rule 21): a list of at most four words of
// compromised, superseded, retired and no-reason, none twice. The first two are made for every primary whether
// the file lists them or not, so listing them is accepted and adds nothing.

const reasonsHead = "version: 1\nkind: openpgp\ntest: true\n"

func openPGPWith(member string) string { return reasonsHead + member }

func TestTheFourReasonsAreTheWordsOfThePageInThePlanOrder(t *testing.T) {
	// The table of the page: compromised (2) and superseded (1) are always made, retired (3) and no reason (0) only
	// when the file lists them. The plan makes them in this order.
	if want := []string{"compromised", "superseded", "retired", "no-reason"}; !slices.Equal(wanted.RevocationReasonWords(), want) {
		t.Errorf("RevocationReasonWords = %q, want %q", wanted.RevocationReasonWords(), want)
	}
}

func TestAnOpenPGPRootFileWithNoReasonsHasNone(t *testing.T) {
	for name, text := range map[string]string{
		"no member":  reasonsHead,
		"empty list": openPGPWith("revocation_reasons: []\n"),
		"the member in a file that has no test member": "version: 1\nkind: openpgp\nrevocation_reasons: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := mustRoot(t, "openpgp", text)
			if len(r.RevocationReasons()) != 0 {
				t.Errorf("Reasons = %q, want none", r.RevocationReasons())
			}
		})
	}
}

func TestTheReasonsOfAFileAreReadInTheOrderOfTheFile(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		want []string
	}{
		"one word":                      {"revocation_reasons: [retired]\n", []string{"retired"}},
		"the other extra":               {"revocation_reasons: [no-reason]\n", []string{"no-reason"}},
		"a word that is always made":    {"revocation_reasons: [compromised]\n", []string{"compromised"}},
		"the other that is always made": {"revocation_reasons: [superseded]\n", []string{"superseded"}},
		"all four in the plan order":    {"revocation_reasons: [compromised, superseded, retired, no-reason]\n", []string{"compromised", "superseded", "retired", "no-reason"}},
		"all four the other way":        {"revocation_reasons: [no-reason, retired, superseded, compromised]\n", []string{"no-reason", "retired", "superseded", "compromised"}},
		"a block list":                  {"revocation_reasons:\n  - retired\n  - no-reason\n", []string{"retired", "no-reason"}},
		"quoted words":                  {"revocation_reasons: [\"retired\", 'no-reason']\n", []string{"retired", "no-reason"}},
		"a comment after a word":        {"revocation_reasons:\n  - retired # when the card is retired\n", []string{"retired"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := mustRoot(t, "openpgp", openPGPWith(tc.text))
			if !slices.Equal(r.RevocationReasons(), tc.want) {
				t.Errorf("Reasons = %q, want %q", r.RevocationReasons(), tc.want)
			}
			if r.Kind != wanted.RootOpenPGP || !r.Test {
				t.Errorf("the other members are not read: %+v", r)
			}
			if r.File.Path != "want/roots/openpgp.yaml" || string(r.File.Data) != openPGPWith(tc.text) || r.File.SHA256 != sha256hex([]byte(openPGPWith(tc.text))) {
				t.Errorf("the file is not the bytes that were given: %+v", r.File)
			}
		})
	}
	// The member may stand before kind and test.
	r := mustRoot(t, "openpgp", "revocation_reasons: [retired]\nversion: 1\nkind: openpgp\n")
	if !slices.Equal(r.RevocationReasons(), []string{"retired"}) || r.Test {
		t.Errorf("%+v", r)
	}
}

func TestTheReasonsOfARootAreItsOwnCopy(t *testing.T) {
	text := openPGPWith("revocation_reasons: [retired]\n")
	a := mustRoot(t, "openpgp", text)
	a.RevocationReasons()[0] = "changed"
	if got := a.RevocationReasons(); got[0] != "retired" {
		t.Errorf("a change of the copy shows in the root: %q", got)
	}
	if b := mustRoot(t, "openpgp", text); b.RevocationReasons()[0] != "retired" {
		t.Errorf("a change of the reasons of one root shows in another: %q", b.RevocationReasons())
	}
	// The list of the four words is a copy too.
	wanted.RevocationReasonWords()[0] = "changed"
	if wanted.RevocationReasonWords()[0] != "compromised" {
		t.Error("a caller changed the words")
	}
}

func TestAListOfReasonsThatIsNotTheShapeIsRefusedAndNamesTheEntryAndTheWord(t *testing.T) {
	for name, tc := range map[string]struct {
		member string
		words  []string
	}{
		"an unknown word":           {"revocation_reasons: [expired]\n", []string{"revocation_reasons entry 1", "\"expired\"", "compromised, superseded, retired, no-reason"}},
		"an unknown second word":    {"revocation_reasons: [retired, expired]\n", []string{"entry 2", "\"expired\""}},
		"an unknown word in a list": {"revocation_reasons:\n  - retired\n  - expired\n", []string{"entry 2", "\"expired\""}},
		"a word in upper case":      {"revocation_reasons: [Retired]\n", []string{"entry 1", "\"Retired\""}},
		"a word with a space":       {"revocation_reasons: [\"retired \"]\n", []string{"entry 1", "\"retired \""}},
		"a word with an underscore": {"revocation_reasons: [no_reason]\n", []string{"entry 1", "\"no_reason\""}},
		"an empty word":             {"revocation_reasons: [\"\"]\n", []string{"entry 1", "\"\""}},
		"a word twice":              {"revocation_reasons: [retired, retired]\n", []string{"entry 2", "repeats", "\"retired\""}},
		"a word that is made twice": {"revocation_reasons: [compromised, retired, compromised]\n", []string{"entry 3", "repeats", "\"compromised\""}},
		"five words":                {"revocation_reasons: [compromised, superseded, retired, no-reason, retired]\n", []string{"more than 4 words", "only 4 reasons"}},
		"a long list":               {"revocation_reasons: [" + strings.Repeat("retired, ", 99) + "retired]\n", []string{"more than 4 words"}},
		"a string":                  {"revocation_reasons: retired\n", []string{"must be a list"}},
		"a number":                  {"revocation_reasons: 2\n", []string{"must be a list"}},
		"a boolean":                 {"revocation_reasons: true\n", []string{"must be a list"}},
		"a map":                     {"revocation_reasons: {retired: true}\n", []string{"must be a list"}},
		"null":                      {"revocation_reasons: null\n", []string{"null"}},
		"nothing":                   {"revocation_reasons:\n", []string{"null"}},
		"a tilde":                   {"revocation_reasons: ~\n", []string{"null"}},
		"a null entry":              {"revocation_reasons: [~]\n", []string{"null"}},
		"a number as an entry":      {"revocation_reasons: [2]\n", []string{"entry 1", "must be a string"}},
		"a boolean as an entry":     {"revocation_reasons: [true]\n", []string{"entry 1", "must be a string"}},
		"a list as an entry":        {"revocation_reasons: [[retired]]\n", []string{"entry 1", "must be a string"}},
		"a map as an entry":         {"revocation_reasons: [{retired: 1}]\n", []string{"entry 1", "must be a string"}},
		"a map as the second entry": {"revocation_reasons: [retired, {a: b}]\n", []string{"entry 2", "must be a string"}},
		"the member twice":          {"revocation_reasons: [retired]\nrevocation_reasons: [no-reason]\n", []string{"appears twice"}},
		"a tag":                     {"revocation_reasons: [!!str retired]\n", []string{"tag"}},
		"an anchor":                 {"revocation_reasons: [&r retired]\n", []string{"anchor"}},
		"an alias":                  {"x: &r retired\nrevocation_reasons: [*r]\n", []string{"anchor"}},
		"a merge key":               {"revocation_reasons: [<<]\n", []string{"entry 1"}},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := wanted.ParseRoot("openpgp", []byte(openPGPWith(tc.member)))
			if r != nil {
				t.Errorf("a value beside the error %v: %+v", err, r)
			}
			_ = wantFault(t, err, "want/roots/openpgp.yaml", -1, tc.words...)
		})
	}
}

func TestTheFaultOfAListIsAtTheLineOfTheMemberOrOfTheEntry(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		line int
	}{
		"a flow list, a word":       {"version: 1\nkind: openpgp\nrevocation_reasons: [retired, expired]\n", 3},
		"a block list, the second":  {"version: 1\nkind: openpgp\nrevocation_reasons:\n  - retired\n  - expired\n", 5},
		"a block list, the first":   {"version: 1\nkind: openpgp\nrevocation_reasons:\n  - expired\n", 4},
		"a number as an entry":      {"version: 1\nkind: openpgp\nrevocation_reasons:\n  - retired\n  - 7\n", 5},
		"a string in place of list": {"version: 1\nkind: openpgp\nrevocation_reasons: retired\n", 3},
		"the member after test":     {"version: 1\nkind: openpgp\ntest: true\n\n# the reasons\nrevocation_reasons: [x]\n", 6},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := wanted.ParseRoot("openpgp", []byte(tc.text))
			_ = wantFault(t, err, "want/roots/openpgp.yaml", tc.line)
		})
	}
}

func TestAWordFromTheFileIsEscapedAndCutInTheMessage(t *testing.T) {
	// A control character, a bidirectional control and a very long word are all outside the four words, so the
	// file is refused, and the message holds them escaped, in printable ASCII on one line, and cut.
	for name, word := range map[string]string{
		"a bell":                                `"retired\a"`,
		"an escape":                             `"retired\e"`,
		"a bidirectional control by its escape": `"retired\u202e"`,
		"a line break":                          `"retired\nno-reason"`,
		"a letter outside of ASCII":             `"retiré"`,
		"a very long word":                      `"` + strings.Repeat("r", 500) + `"`,
		"a word with a double quote":            `"re\"tired"`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := wanted.ParseRoot("openpgp", []byte(openPGPWith("revocation_reasons: ["+word+"]\n")))
			e := wantFault(t, err, "want/roots/openpgp.yaml", 4, "entry 1")
			if len(e.Msg) > 400 {
				t.Errorf("the message is %d bytes: %.80q...", len(e.Msg), e.Msg)
			}
			if strings.Contains(e.Msg, strings.Repeat("r", 41)) {
				t.Errorf("a word is not cut: %q", e.Msg)
			}
		})
	}
}

func TestABidirectionalControlWrittenInAWordIsRefusedByTheStrictReader(t *testing.T) {
	// Written as the character, the control is refused before the word is judged. Written as an escape it is a
	// word that is not one of the four, and the message holds it escaped.
	err := refuseOpenPGP(t, openPGPWith("revocation_reasons: [\"retired"+string(rune(0x202e))+"\"]\n"))
	_ = wantFault(t, err, "want/roots/openpgp.yaml", 4, "format character")
}

func TestTheMemberIsForTheOpenPGPRootFileOnly(t *testing.T) {
	for _, kind := range []string{"x509", "ssh"} {
		for name, member := range map[string]string{
			"a good list":    "revocation_reasons: [retired]\n",
			"an empty list":  "revocation_reasons: []\n",
			"a bad word":     "revocation_reasons: [expired]\n",
			"not a list":     "revocation_reasons: 5\n",
			"the whole four": "revocation_reasons: [compromised, superseded, retired, no-reason]\n",
		} {
			t.Run(kind+" with "+name, func(t *testing.T) {
				r, err := wanted.ParseRoot("x509", []byte("version: 1\nkind: "+kind+"\ntest: true\n"+member))
				if r != nil {
					t.Errorf("a value beside the error: %+v", r)
				}
				_ = wantFault(t, err, "want/roots/x509.yaml", 4, "revocation_reasons", "OpenPGP root file", "(kind: openpgp) only")
			})
		}
		// A file of another kind with no member has no reasons.
		if r := mustRoot(t, "x509", "version: 1\nkind: "+kind+"\ntest: true\n"); len(r.RevocationReasons()) != 0 {
			t.Errorf("%s: Reasons = %q", kind, r.RevocationReasons())
		}
	}
}

func TestAnUnknownMemberSaysWhatTheFileHoldsNow(t *testing.T) {
	_, err := wanted.ParseRoot("openpgp", []byte(openPGPWith("retire_at: 2030-01-01\n")))
	_ = wantFault(t, err, "want/roots/openpgp.yaml", 4, "retire_at", "not read yet", "version, kind, test, revocation_reasons, keys and encryption")
	// A member that is near the name is not the name.
	for _, m := range []string{"revocation_reason: [retired]\n", "revocation-reasons: [retired]\n", "Revocation_reasons: [retired]\n", "reasons: [retired]\n", "revocation_reasons : x\n"} {
		r, err := wanted.ParseRoot("openpgp", []byte(openPGPWith(m)))
		if r != nil || err == nil {
			t.Errorf("%q is accepted: %+v", m, r)
		}
	}
}

func TestTheLoadersReadTheReasonsOfAFileOnTheDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "want", "roots"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"acme-release": openPGPWith("revocation_reasons: [no-reason, retired]\n"),
		"acme-tls":     "version: 1\nkind: x509\ntest: true\n",
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, "want", "roots", name+".yaml"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	r, err := wanted.LoadRoot(fsys, "acme-release")
	if err != nil || !slices.Equal(r.RevocationReasons(), []string{"no-reason", "retired"}) {
		t.Fatalf("LoadRoot: %+v, %v", r, err)
	}
	roots, err := wanted.LoadRoots(fsys, []string{"acme-release", "acme-tls"})
	if err != nil || len(roots) != 2 || !slices.Equal(roots[0].RevocationReasons(), []string{"no-reason", "retired"}) || len(roots[1].RevocationReasons()) != 0 {
		t.Fatalf("LoadRoots: %+v, %v", roots, err)
	}
	all, err := wanted.ListRoots(fsys)
	if err != nil || len(all) != 2 || all[0].Name != "acme-release" || !slices.Equal(all[0].RevocationReasons(), []string{"no-reason", "retired"}) {
		t.Fatalf("ListRoots: %+v, %v", all, err)
	}
	// A bad list in a file on the disk names the file.
	if err := os.WriteFile(filepath.Join(dir, "want", "roots", "acme-release.yaml"), []byte(openPGPWith("revocation_reasons: [expired]\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wanted.LoadRoot(fsys, "acme-release"); err == nil || !strings.Contains(err.Error(), "want/roots/acme-release.yaml") || !strings.Contains(err.Error(), "expired") {
		t.Errorf("LoadRoot of a bad list: %v", err)
	}
}

func TestAListOfReasonsInAFileOverTheLimitOrTooDeepIsRefused(t *testing.T) {
	// The limits of a wanted file hold for this member too: size, and the depth of the nesting.
	big := openPGPWith("revocation_reasons: [retired]\n# " + strings.Repeat("x", wanted.MaxBytes) + "\n")
	r, err := wanted.ParseRoot("openpgp", []byte(big))
	if r != nil || err == nil {
		t.Fatalf("a file over the limit is accepted: %v", r)
	}
	_ = wantFault(t, err, "want/roots/openpgp.yaml", 0, "longer than")
	deep := openPGPWith("revocation_reasons: [" + strings.Repeat("[", wanted.MaxDepth+20) + strings.Repeat("]", wanted.MaxDepth+20) + "]\n")
	if r, err := wanted.ParseRoot("openpgp", []byte(deep)); r != nil || err == nil {
		t.Fatalf("a nesting over the limit is accepted: %v", r)
	}
	// A list with thousands of entries is refused, not read to its end.
	many := openPGPWith("revocation_reasons: [" + strings.Repeat("retired, ", 20000) + "retired]\n")
	_ = refuseOpenPGP(t, many)
}

func refuseOpenPGP(t testing.TB, text string) error {
	t.Helper()
	r, err := wanted.ParseRoot("openpgp", []byte(text))
	if r != nil || err == nil {
		t.Fatalf("accepted: %v", r)
	}
	return err
}

func TestTheStarterFilesOfANewBundleAreReadAsBefore(t *testing.T) {
	// The files that `new` writes have no revocation_reasons, and are read as they were: no reasons.
	for name, text := range map[string]string{
		"openpgp": "# One OpenPGP root. Its keys are made by the first apply.\nversion: 1\nkind: openpgp\ntest: true  # set at birth; a real root never becomes a test root\n",
		"x509":    "# One X.509 root. Its keys are made by the first apply.\nversion: 1\nkind: x509\ntest: false\n",
	} {
		r := mustRoot(t, name, text)
		if len(r.RevocationReasons()) != 0 || string(r.File.Data) != text {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func FuzzParseRootReasons(f *testing.F) {
	for _, s := range []string{
		reasonsHead,
		openPGPWith("revocation_reasons: []\n"),
		openPGPWith("revocation_reasons: [retired]\n"),
		openPGPWith("revocation_reasons: [no-reason, retired]\n"),
		openPGPWith("revocation_reasons: [compromised, superseded, retired, no-reason]\n"),
		openPGPWith("revocation_reasons:\n  - retired\n  - retired\n"),
		openPGPWith("revocation_reasons: [expired]\n"),
		openPGPWith("revocation_reasons: [retired, no-reason, compromised, superseded, x]\n"),
		openPGPWith("revocation_reasons: [~]\n"),
		openPGPWith("revocation_reasons: {a: b}\n"),
		openPGPWith("revocation_reasons: [\"re\\u202etired\"]\n"),
		"version: 1\nkind: x509\nrevocation_reasons: [retired]\n",
		"version: 1\nkind: ssh\nrevocation_reasons: []\n",
		"revocation_reasons: [retired]\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := wanted.ParseRoot("openpgp", data)
		var file wanted.File
		if r != nil {
			file = r.File
			if len(r.RevocationReasons()) > 4 {
				t.Fatalf("more than four reasons: %q", r.RevocationReasons())
			}
			if len(r.RevocationReasons()) > 0 && r.Kind != wanted.RootOpenPGP {
				t.Fatalf("reasons in a root of the kind %s: %q", r.Kind, r.RevocationReasons())
			}
			seen := map[string]bool{}
			for _, w := range r.RevocationReasons() {
				if !slices.Contains(wanted.RevocationReasonWords(), w) || seen[w] {
					t.Fatalf("a reason that is not one of the four, or is twice: %q", r.RevocationReasons())
				}
				seen[w] = true
			}
			// What was read is read again from the same bytes, to the same reasons.
			again, err2 := wanted.ParseRoot("openpgp", data)
			if err2 != nil || !slices.Equal(again.RevocationReasons(), r.RevocationReasons()) {
				t.Fatalf("a second reading differs: %v", err2)
			}
			if len(r.RevocationReasons()) > 0 {
				r.RevocationReasons()[0] = "changed"
				if again.RevocationReasons()[0] == "changed" {
					t.Fatal("two roots share the memory of their reasons")
				}
			}
		}
		checkResult(t, "root", data, r != nil, file, err)
	})
}
