package rootlist_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/testrepo"
)

// The vectors under testdata/root-list/v1 are regenerated with new keys by another change. Nothing
// here holds a value that comes from them: no pin, no digest, no byte string, no count of files.
// The ids of the cases and the outcomes they expect are what stays.

type manifest struct {
	Clock string `json:"clock"`
	Roots []struct {
		Label string `json:"label"`
		Pin   string `json:"x509_spki_sha256"`
	} `json:"roots"`
	InitialPins []string `json:"initial_pins"`
	Removals    []struct {
		Label string `json:"label"`
		File  string `json:"file"`
	} `json:"removals"`
	Lists []struct {
		ID    string   `json:"id"`
		Files []string `json:"files"`
		Flaw  string   `json:"flaw"`
	} `json:"lists"`
	Cases   []manifestCase `json:"cases"`
	Bundles []struct {
		ID       string   `json:"id"`
		File     string   `json:"file"`
		Sequence int      `json:"sequence"`
		Roots    []string `json:"roots"`
		Flaw     string   `json:"flaw"`
	} `json:"bundles"`
}

type manifestCase struct {
	ID        string  `json:"id"`
	Held      *string `json:"held"`
	Candidate *string `json:"candidate"`
	Clock     string  `json:"clock"`
	Expect    string  `json:"expect"`
	Reason    string  `json:"reason"`
	Warning   string  `json:"warning"`
	// Bundle names a CA bundle that is also checked against the candidate list (--ca-bundle).
	Bundle string `json:"bundle"`
	// MinSequence is the lowest sequence given with the initial pins (--min-sequence); a case that has
	// it has no held list.
	MinSequence *int64 `json:"min_sequence"`
}

const vectorDir = "testdata/root-list/v1"

func readVector(t testing.TB, rel string) []byte { return testrepo.Read(t, vectorDir, rel) }

func loadManifest(t testing.TB) *manifest {
	t.Helper()
	var m manifest
	if err := json.Unmarshal(readVector(t, "manifest.json"), &m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if len(m.Cases) == 0 || len(m.Lists) == 0 || len(m.Roots) == 0 {
		t.Fatalf("the manifest has no cases, lists or roots")
	}
	if msg := unknownMembers(readVector(t, "manifest.json")); msg != "" {
		t.Fatal(msg)
	}
	return &m
}

// knownMembers are the members of the manifest that these tests know how to run. A member that is
// not here is a kind of case, list or bundle that the tests do not know, and the run fails with a
// text that says which: a new kind of case (the same list again, the dates, a bad CA bundle, a
// lowest sequence) must come with its test, and is never skipped for being new.
var knownMembers = map[string][]string{
	"manifest": {"root_list", "clock", "roots", "initial_pins", "removals", "lists", "cases", "bundles"},
	"root":     {"label", "certificate", "openpgp", "x509_spki_sha256", "openpgp_fingerprint"},
	"removal":  {"label", "file"},
	"list":     {"id", "signers", "files", "flaw"},
	"case":     {"id", "held", "candidate", "clock", "expect", "reason", "warning", "bundle", "min_sequence"},
	"bundle":   {"id", "file", "sequence", "roots", "flaw"},
}

// unknownMembers returns "" when every member of the manifest, of its roots, removals, lists, cases
// and bundles is one that the tests know, and else a text that names the kind and the member.
func unknownMembers(data []byte) string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return "manifest.json: " + err.Error()
	}
	check := func(kind, owner string, raw json.RawMessage) string {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return ""
		}
		for name := range obj {
			if !slices.Contains(knownMembers[kind], name) {
				return fmt.Sprintf("a kind of %s this test does not know: %s has the member %q (the tests must learn it before the vectors change)", kind, owner, name)
			}
		}
		return ""
	}
	if msg := check("manifest", "the manifest", data); msg != "" {
		return msg
	}
	for member, kind := range map[string]string{"roots": "root", "removals": "removal", "lists": "list", "cases": "case", "bundles": "bundle"} {
		var items []json.RawMessage
		if err := json.Unmarshal(top[member], &items); err != nil {
			continue
		}
		for i, raw := range items {
			var id struct {
				ID    string `json:"id"`
				Label string `json:"label"`
			}
			_ = json.Unmarshal(raw, &id)
			if msg := check(kind, fmt.Sprintf("%s %d (%s%s)", kind, i, id.ID, id.Label), raw); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func TestTheVectorTestsRefuseAKindOfCaseTheyDoNotKnow(t *testing.T) {
	good := string(readVector(t, "manifest.json"))
	if msg := unknownMembers([]byte(good)); msg != "" {
		t.Fatalf("the manifest itself: %s", msg)
	}
	for name, doc := range map[string]string{
		"a member of a case":    `{"cases":[{"id":"x","expect":"accept","dates":3}]}`,
		"a member of the top":   `{"cases":[],"dates":[]}`,
		"a member of a bundle":  `{"bundles":[{"id":"b","file":"f","sequence":1,"roots":[],"expect":"refuse"}]}`,
		"a member of a list":    `{"lists":[{"id":"l","files":[],"signers":[],"note":1}]}`,
		"a member of a root":    `{"roots":[{"label":"A","x":1}]}`,
		"a member of a removal": `{"removals":[{"label":"A","file":"f","y":1}]}`,
	} {
		msg := unknownMembers([]byte(doc))
		if !strings.Contains(msg, "does not know") || !printable(msg) {
			t.Errorf("%s: the text is %q", name, msg)
		}
	}
	if msg := unknownMembers([]byte(`{"cases":[{"id":"x","dates":3}]}`)); !strings.Contains(msg, `"dates"`) || !strings.Contains(msg, "case") {
		t.Errorf("the text does not say which kind and member: %q", msg)
	}
}

// listFiles returns the two files of a list by id.
func (m *manifest) listFiles(t testing.TB, id string) rootlist.Signed {
	t.Helper()
	for _, l := range m.Lists {
		if l.ID != id {
			continue
		}
		var s rootlist.Signed
		for _, f := range l.Files {
			switch path.Ext(f) {
			case ".json":
				s.JSON = readVector(t, f)
			case ".jws":
				s.JWS = readVector(t, f)
			}
		}
		if s.JSON == nil || s.JWS == nil {
			t.Fatalf("list %q has no .json and .jws pair: %v", id, l.Files)
		}
		return s
	}
	t.Fatalf("no list %q in the manifest", id)
	return rootlist.Signed{}
}

func (m *manifest) pin(t testing.TB, label string) string {
	t.Helper()
	for _, r := range m.Roots {
		if r.Label == label {
			return r.Pin
		}
	}
	t.Fatalf("no root %q in the manifest", label)
	return ""
}

// trustOfCase is the trust of a case: the held list, or the initial pins with the lowest sequence
// the case gives. A case that has both a held list and a lowest sequence is a kind the tests do not
// know.
func (m *manifest) trustOfCase(t testing.TB, c manifestCase) rootlist.Trust {
	t.Helper()
	tr := m.trustOf(t, c.Held)
	if c.MinSequence == nil {
		return tr
	}
	if c.Held != nil {
		t.Fatalf("a kind of case this test does not know: %q has a held list and a lowest sequence", c.ID)
	}
	tr, err := tr.WithMinSequence(*c.MinSequence)
	if err != nil {
		t.Fatalf("case %q: %v", c.ID, err)
	}
	return tr
}

func (m *manifest) bundleBytes(t testing.TB, id string) []byte {
	t.Helper()
	for _, b := range m.Bundles {
		if b.ID == id {
			return readVector(t, b.File)
		}
	}
	t.Fatalf("no bundle %q in the manifest", id)
	return nil
}

// trustOf is the trust of a case: the held list by id, or the initial pins when it is null.
func (m *manifest) trustOf(t testing.TB, held *string) rootlist.Trust {
	t.Helper()
	if held == nil {
		var pins []string
		for _, label := range m.InitialPins {
			pins = append(pins, m.pin(t, label))
		}
		return pinsOf(t, pins...)
	}
	h, err := rootlist.ParseHeld(m.listFiles(t, *held).JSON)
	if err != nil {
		t.Fatalf("held list %q: %v", *held, err)
	}
	return rootlist.HeldTrust(h)
}

func (m *manifest) clockOf(t testing.TB, own string) time.Time {
	t.Helper()
	c := own
	if c == "" {
		c = m.Clock
	}
	if c == "" {
		t.Fatal("the case has no clock and the manifest has none")
	}
	return mustTime(c)
}

// checkOfCase is the number of the check that refuses each case, from the order of the page:
// a case id that is not here fails the test, so that a new case is given its check.
var checkOfCase = map[string]int{
	"signed-by-a-revoked-root":        2,
	"unknown-signer":                  2,
	"tampered":                        3,
	"version-2":                       4,
	"unknown-member":                  5,
	"rollback":                        6,
	"same-sequence-different-content": 7,
	"a-second-signer-on-no-list":      8,
	"removal-with-another-roots-authorisation": 9,
	"set-change-with-one-signature":            10,
	"removal-without-authorisation":            10,
	"addition-not-signed-by-the-new-root":      10,
	"addition-without-every-current-root":      10,
	"expired":                                  11,
	// The cases of the dates and of the small refusals of check 5 (the page: check 5), the lowest
	// sequence (check 6) and the held list again after its expiry (check 11).
	"expires-13-months-and-a-second-after-signing":  5,
	"expires-12-months-after-signing":               5,
	"signed-after-the-clock":                        5,
	"expires-by-plain-month-addition-from-the-31st": 5,
	"expires-by-plain-month-addition-from-the-30th": 5,
	"label-twice":                        5,
	"pin-twice":                          5,
	"fingerprint-in-upper-case":          5,
	"last-record-digest-one-digit-short": 5,
	"sequence-0":                         5,
	"pin-twice-in-removals":              5,
	"empty-authorisation":                5,
	"initial-pins-lowest-sequence-above": 6,
	"same-list-again-after-its-expiry":   11,
}

func TestManifestCases(t *testing.T) {
	m := loadManifest(t)
	ran := 0
	counts := map[string]int{}
	for _, c := range m.Cases {
		t.Run(c.ID, func(t *testing.T) {
			ran++
			counts[c.Expect]++
			clock := m.clockOf(t, c.Clock)
			switch c.Expect {
			case "accept":
				if c.Candidate == nil {
					t.Fatal("an accepting case has no candidate")
				}
				cand := m.listFiles(t, *c.Candidate)
				v := rootlist.Verify(cand, m.trustOfCase(t, c), clock)
				// The held list again (the same bytes as the held list) says so; a new list does not.
				if c.Held != nil && bytes.Equal(m.listFiles(t, *c.Held).JSON, cand.JSON) {
					acceptsAgain(t, v)
				} else {
					accepts(t, v)
				}
				if c.Bundle != "" {
					// The case also checks the bundle against the accepted list.
					if bv := rootlist.VerifyCABundle(m.bundleBytes(t, c.Bundle), v.List); !bv.Accepted || bv.Check != 0 || bv.Reason != "" {
						t.Errorf("the bundle %s is refused: %+v", c.Bundle, bv)
					}
				}
				want, err := rootlist.ParseList(cand.JSON)
				if err != nil {
					t.Fatalf("the accepted list does not read: %v", err)
				}
				if !reflect.DeepEqual(v.List, want) {
					t.Errorf("the accepted list is not the one that ParseList reads")
				}
			case "refuse":
				if c.Candidate == nil {
					t.Fatal("a refusing case has no candidate")
				}
				if c.Reason == "" {
					t.Fatal("a refusing case has no reason")
				}
				if c.Bundle != "" {
					// A refusal with a bundle is the bundle's: the list is accepted, and the bundle is not.
					if c.Reason != string(rootlist.CABundleMismatch) {
						t.Fatalf("a kind of case this test does not know: %q has a bundle and the reason %q", c.ID, c.Reason)
					}
					v := rootlist.Verify(m.listFiles(t, *c.Candidate), m.trustOfCase(t, c), clock)
					accepts(t, v)
					bv := rootlist.VerifyCABundle(m.bundleBytes(t, c.Bundle), v.List)
					if bv.Accepted || bv.Reason != rootlist.CABundleMismatch || bv.Check != 0 || bv.List != nil || bv.Detail == "" {
						t.Fatalf("the bundle %s: %+v", c.Bundle, bv)
					}
					mustBeASCII(t, "Detail", bv.Detail)
					return
				}
				check, known := checkOfCase[c.ID]
				if !known {
					t.Fatalf("a kind of case this test does not know: %q is refused, and the test does not know which check refuses it: add it to checkOfCase", c.ID)
				}
				v := rootlist.Verify(m.listFiles(t, *c.Candidate), m.trustOfCase(t, c), clock)
				refuses(t, v, rootlist.Reason(c.Reason), check)
				if got := rootlist.Checks()[check-1]; got.N != check || got.Reason != rootlist.Reason(c.Reason) {
					t.Errorf("check %d gives %q, the case expects %q", check, got.Reason, c.Reason)
				}
			case "warn":
				if c.Held == nil {
					t.Fatal("a warning case has no held list")
				}
				if c.Candidate != nil {
					t.Fatal("a warning case has a candidate; the test knows only the held list")
				}
				h, err := rootlist.ParseHeld(m.listFiles(t, *c.Held).JSON)
				if err != nil {
					t.Fatal(err)
				}
				got := rootlist.CheckHeld(h, clock)
				// The page names the warning held-expired, and so does the manifest.
				if len(got) != 1 || got[0] != rootlist.WarningHeldExpired || c.Warning != rootlist.WarningHeldExpired {
					t.Errorf("CheckHeld = %v for the warning %q of the manifest, want [held-expired]", got, c.Warning)
				}
			default:
				t.Fatalf("a kind of case this test does not know: case %q expects %q (known: accept, refuse, warn)", c.ID, c.Expect)
			}
		})
	}
	if ran != len(m.Cases) {
		t.Fatalf("ran %d of %d cases", ran, len(m.Cases))
	}
	for _, kind := range []string{"accept", "refuse", "warn"} {
		if counts[kind] == 0 {
			t.Errorf("the manifest has no %q case: a kind of case is not tested", kind)
		}
	}
	for id := range checkOfCase {
		if !slices.ContainsFunc(m.Cases, func(c manifestCase) bool {
			return c.ID == id
		}) {
			t.Errorf("checkOfCase names %q, which is not a case of the manifest", id)
		}
	}
}

func TestManifestCABundles(t *testing.T) {
	m := loadManifest(t)
	if len(m.Bundles) == 0 {
		t.Fatal("the manifest has no CA bundle")
	}
	for _, b := range m.Bundles {
		t.Run(b.ID, func(t *testing.T) {
			bundle := readVector(t, b.File)
			if b.Flaw != "" {
				// A bundle with a flaw is wrong for the list of the case that names it (the flaw may be that
				// it holds the roots or the sequence of another list, so it may suit a list of its own).
				// TestManifestCases runs it against that list; here the manifest must name such a case.
				named := false
				for _, c := range m.Cases {
					named = named || c.Bundle == b.ID
				}
				if !named {
					t.Fatalf("the bundle %s has the flaw %q and no case names it", b.ID, b.Flaw)
				}
				return
			}
			var wantPins []string
			for _, label := range b.Roots {
				wantPins = append(wantPins, m.pin(t, label))
			}
			matched := 0
			for _, l := range m.Lists {
				list, err := rootlist.ParseList(m.listFiles(t, l.ID).JSON)
				if err != nil {
					continue // a list that is not a list (an unknown member, version 2)
				}
				// A bundle with a flaw (a certificate that is wrong, or roots or a sequence that are not the
				// list's) is refused for every list; one without is accepted for the lists that its
				// sequence and roots name, and refused for the others.
				want := int(list.Sequence) == b.Sequence && slices.Equal(list.Pins(), wantPins)
				v := rootlist.VerifyCABundle(bundle, list)
				if want {
					matched++
					if !v.Accepted || v.Reason != "" || v.List != list {
						t.Errorf("list %s: refused: %+v", l.ID, v)
					}
					continue
				}
				if v.Accepted || v.Reason != rootlist.CABundleMismatch || v.Check != 0 || v.Detail == "" || v.List != nil {
					t.Errorf("list %s: want ca-bundle-mismatch, got %+v", l.ID, v)
				}
				mustBeASCII(t, "Detail", v.Detail)
			}
			if matched == 0 {
				t.Fatalf("no list of the manifest goes with the bundle %s: nothing was checked", b.ID)
			}
		})
	}
}

func TestManifestRemovalAuthorisations(t *testing.T) {
	m := loadManifest(t)
	if len(m.Removals) == 0 {
		t.Fatal("the manifest has no removal authorisation")
	}
	var allPins []string
	for _, r := range m.Roots {
		allPins = append(allPins, r.Pin)
	}
	without := func(pin string) *rootlist.List {
		l := &rootlist.List{Version: 1, Sequence: 99}
		for _, r := range m.Roots {
			if r.Pin != pin {
				l.Roots = append(l.Roots, rootlist.Root{Label: r.Label, X509SPKISHA256: r.Pin})
			}
		}
		return l
	}
	for _, r := range m.Removals {
		t.Run(r.Label, func(t *testing.T) {
			pin := m.pin(t, r.Label)
			auth := string(readVector(t, r.File))
			entry := rootlist.Removal{Label: r.Label, X509SPKISHA256: pin, Authorisation: auth}
			if err := rootlist.CheckRemoval(entry, without(pin), allPins); err != nil {
				t.Fatalf("the authorisation as the holder stores it is refused: %v", err)
			}
			for _, other := range m.Removals {
				if other.Label == r.Label {
					continue
				}
				wrong := rootlist.Removal{Label: r.Label, X509SPKISHA256: pin, Authorisation: string(readVector(t, other.File))}
				if err := rootlist.CheckRemoval(wrong, without(pin), allPins); err == nil {
					t.Errorf("the authorisation of %s was taken for the one of %s", other.Label, r.Label)
				}
			}
			mid := len(auth) / 2
			changed := auth[:mid] + string(otherBase64Char(auth[mid])) + auth[mid+1:]
			for name, bad := range map[string]string{
				"a line feed after it": auth + "\n",
				"cut short":            auth[:len(auth)-1],
				"a byte of it changed": changed,
				"nothing":              "",
				"its own pin":          pin,
			} {
				e := entry
				e.Authorisation = bad
				if err := rootlist.CheckRemoval(e, without(pin), allPins); err == nil {
					t.Errorf("%s: accepted", name)
				}
			}
		})
	}
}

// otherBase64Char returns a Base64url character that is not c, and not a dot.
func otherBase64Char(c byte) byte {
	if c == 'A' {
		return 'B'
	}
	return 'A'
}
