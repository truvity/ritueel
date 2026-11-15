package ceremony_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The page, "The record", says that `root` of the record is "as in the plan". The tests of this
// file hold what that says of the members that a plan's root gives and of the births: the label,
// the store, test and copyable are the plan's, and the X.509 fingerprint is the one that the
// birth journal has for the label.

// rootOfTheFlow is the root that the flow's plan gives (label A, a software key, a test key that
// is a file) with the fingerprint of the birth of A.
func rootOfTheFlow() *files.PlanRoot {
	return &files.PlanRoot{Label: "A", Store: "software", X509: rep('a'), Test: true, Copyable: true}
}

// planRoot makes the edit of a spec that gives the plan this root; nil leaves the root, and its
// reason, out of the plan.
func planRoot(root map[string]any) func(*spec) {
	return func(s *spec) {
		s.edit = func(m map[string]any) {
			if root == nil {
				delete(m, "root")
				delete(m, "root_reason")
				return
			}
			m["root"] = root
		}
	}
}

// recordWithRoot calls Record with the root as it is given.
func recordWithRoot(fl *flow, root *files.PlanRoot) ([]byte, error) {
	in := fl.recordIn()
	in.Root = root
	return fl.f.Record(in)
}

// wantRootRefused calls Record with root and requires the refusal of the page: kind
// ErrInvalidInput, a reason that holds every one of words, nothing written, the Folder not stopped,
// and, afterwards, the root of the plan taken by the same Folder.
func wantRootRefused(t *testing.T, fl *flow, root *files.PlanRoot, good *files.PlanRoot, words ...string) {
	t.Helper()
	before := tree(t, fl.b.dir)
	mark := fl.b.r.mark()
	out, err := recordWithRoot(fl, root)
	if err == nil {
		t.Fatalf("a record with the root %+v was written: %s", root, out)
	}
	if out != nil {
		t.Errorf("Record returned bytes with its error: %s", out)
	}
	wantKind(t, err, ceremony.ErrInvalidInput)
	if errors.Is(err, ceremony.ErrFolderStopped) {
		t.Error("a refusal stopped the folder")
	}
	for _, w := range words {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the reason %q does not hold %q", err, w)
		}
	}
	if got := fl.b.r.since(mark); len(got) != 0 {
		t.Errorf("a refused record reached the file system: %v", got)
	}
	sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
	noRecord(t, fl)
	if good == nil {
		return
	}
	out, err = recordWithRoot(fl, good)
	if err != nil {
		t.Fatalf("the root of the plan after the refusal: %v", err)
	}
	if _, err := files.ReadRecord(out); err != nil {
		t.Errorf("the reader refuses the record: %v", err)
	}
}

// Each member of the root that can differ from the plan's is refused, whatever the way it differs:
// the label, the store, test and copyable, the X.509 fingerprint against the birth. Nothing is
// written, the reason names the member and shows the two values escaped.
func TestRecordRefusesARootThatIsNotThePlans(t *testing.T) {
	with := func(edit func(r *files.PlanRoot)) *files.PlanRoot {
		r := rootOfTheFlow()
		edit(r)
		return r
	}
	cases := []struct {
		name  string
		plan  map[string]any // the root of the plan; nil is the plan of the flow
		root  *files.PlanRoot
		words []string
	}{
		// the label
		{"another label", nil, with(func(r *files.PlanRoot) { r.Label = "B" }), []string{"label of the root", `"B"`, `"A"`}},
		{"a label of two letters", nil, with(func(r *files.PlanRoot) { r.Label = "AB" }), []string{"label of the root", `"AB"`, "one upper-case letter"}},
		{"a label in lower case", nil, with(func(r *files.PlanRoot) { r.Label = "a" }), []string{"label of the root", `"a"`}},
		{"a label that is a digit", nil, with(func(r *files.PlanRoot) { r.Label = "1" }), []string{"label of the root", `"1"`}},
		{"a label that is a control character", nil, with(func(r *files.PlanRoot) { r.Label = "\x1b" }), []string{"label of the root", `\u001b`}},
		{"a label that is a line feed", nil, with(func(r *files.PlanRoot) { r.Label = "\n" }), []string{"label of the root", `\u000a`}},
		{"a label of a letter outside ASCII", nil, with(func(r *files.PlanRoot) { r.Label = "\u00c9" }), []string{"label of the root", `\u00c9`}},
		{"a label that is a byte that is not UTF-8", nil, with(func(r *files.PlanRoot) { r.Label = "\xff" }), []string{"label of the root", `\ufffd`}},
		{"a label of the letter before A", nil, with(func(r *files.PlanRoot) { r.Label = "@" }), []string{"label of the root", `"@"`}},
		{"a label of the letter after Z", nil, with(func(r *files.PlanRoot) { r.Label = "[" }), []string{"label of the root", `"["`}},
		{"an empty label while the plan gives one", nil, with(func(r *files.PlanRoot) { r.Label = "" }), []string{"label of the root", `""`, `"A"`}},
		{"an empty label with an X.509 fingerprint (no way past the pin)", nil, with(func(r *files.PlanRoot) { r.Label = ""; r.X509 = rep('c') }), []string{"label of the root"}},
		{"a label that is as the plan gives it and is not a letter", map[string]any{"label": "zz", "store": "software"}, &files.PlanRoot{Label: "zz", Store: "software"}, []string{"label of the root", `"zz"`}},
		// the store
		{"another store of a kind that exists", nil, with(func(r *files.PlanRoot) { r.Store = "piv" }), []string{"store of the root", `"piv"`, `"software"`}},
		{"a store that is not a kind", nil, with(func(r *files.PlanRoot) { r.Store = "card" }), []string{"store of the root", `"card"`, "piv, openpgp-card, aws-kms, software"}},
		{"a store with a space", nil, with(func(r *files.PlanRoot) { r.Store = "soft ware" }), []string{"store of the root", `"soft ware"`}},
		{"a store with an escape", nil, with(func(r *files.PlanRoot) { r.Store = "\x1b[0m" }), []string{"store of the root", `\u001b`}},
		{"a store with a line feed", nil, with(func(r *files.PlanRoot) { r.Store = "software\n" }), []string{"store of the root", `\u000a`}},
		{"a store in capitals", nil, with(func(r *files.PlanRoot) { r.Store = "SOFTWARE" }), []string{"store of the root", `"SOFTWARE"`}},
		{"a store with a letter that looks like another", nil, with(func(r *files.PlanRoot) { r.Store = "s\u043eftware" }), []string{"store of the root", `\u043e`}},
		{"a store that is a byte that is not UTF-8", nil, with(func(r *files.PlanRoot) { r.Store = "\xff" }), []string{"store of the root", `\ufffd`}},
		{"an empty store while the plan gives one", nil, with(func(r *files.PlanRoot) { r.Store = "" }), []string{"store of the root", `""`, `"software"`}},
		{"a store that is as the plan gives it and is not a kind", map[string]any{"label": "A", "store": "card"}, &files.PlanRoot{Label: "A", Store: "card"}, []string{"store of the root", `"card"`}},
		// test
		{"test flipped to false", nil, with(func(r *files.PlanRoot) { r.Test = false }), []string{"test member", "false", "true"}},
		{"test flipped to true", map[string]any{"label": "A", "store": "software", "copyable": true}, with(func(r *files.PlanRoot) {}), []string{"test member", "true", "false"}},
		{"test flipped to true, the plan says false", map[string]any{"label": "A", "store": "software", "test": false, "copyable": true}, with(func(r *files.PlanRoot) {}), []string{"test member"}},
		// copyable
		{"copyable flipped to false", nil, with(func(r *files.PlanRoot) { r.Copyable = false }), []string{"copyable member", "false", "true"}},
		{"copyable flipped to true", map[string]any{"label": "A", "store": "software", "test": true}, with(func(r *files.PlanRoot) {}), []string{"copyable member", "true", "false"}},
		{"copyable flipped to true, the plan says false", map[string]any{"label": "A", "store": "software", "test": true, "copyable": false}, with(func(r *files.PlanRoot) {}), []string{"copyable member"}},
		// the birth
		{"a fingerprint that is not the birth's", nil, with(func(r *files.PlanRoot) { r.X509 = rep('c') }), []string{"X.509 fingerprint", strings.Repeat("c", 40), strings.Repeat("a", 40), `"A"`}},
		{"a fingerprint that is the birth's with the last digit changed", nil, with(func(r *files.PlanRoot) { r.X509 = rep('a')[:63] + "b" }), []string{"X.509 fingerprint"}},
		{"a fingerprint that is the birth's with the first digit changed", nil, with(func(r *files.PlanRoot) { r.X509 = "b" + rep('a')[1:] }), []string{"X.509 fingerprint"}},
		{"a fingerprint of the form of the page that is no key's", nil, with(func(r *files.PlanRoot) { r.X509 = rep('0') }), []string{"X.509 fingerprint"}},
		{"a fingerprint in capitals that is the birth's in lower case", nil, with(func(r *files.PlanRoot) { r.X509 = strings.ToUpper(rep('a')) }), []string{"X.509 fingerprint"}},
		// the form of each member is judged before the plan: a plan that has the same wrong word does not make it right
		{"a fingerprint with an escape", nil, with(func(r *files.PlanRoot) { r.X509 = "\x1b[31m" }), []string{"X.509 fingerprint"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, func(s *spec) {
				if c.plan != nil {
					planRoot(c.plan)(s)
				}
			})
			good := rootOfTheFlow()
			if c.plan != nil {
				good = nil
			}
			wantRootRefused(t, fl, c.root, good, c.words...)
		})
	}
}

// The root that is the plan's is written as it is, with the fingerprint or without it, with the
// OpenPGP fingerprint or without it: the member root of the record is the one that the caller gave.
func TestRecordTakesTheRootThatIsThePlans(t *testing.T) {
	cases := []struct {
		name string
		root *files.PlanRoot
	}{
		{"all members", &files.PlanRoot{Label: "A", Store: "software", X509: rep('a'), OpenPGP: strings.Repeat("b", 40), Test: true, Copyable: true}},
		{"with the birth's fingerprint", rootOfTheFlow()},
		{"with no X.509 fingerprint", &files.PlanRoot{Label: "A", Store: "software", Test: true, Copyable: true}},
		{"with only the OpenPGP fingerprint", &files.PlanRoot{Label: "A", Store: "software", OpenPGP: strings.Repeat("b", 40), Test: true, Copyable: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, nil)
			out, err := recordWithRoot(fl, c.root)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			r, err := files.ReadRecord(out)
			if err != nil {
				t.Fatalf("the reader refuses the record: %v", err)
			}
			if !reflect.DeepEqual(r.Root, c.root) {
				t.Errorf("the root of the record is %+v, the caller gave %+v", r.Root, c.root)
			}
			if rep := fl.b.check(); !rep.Clean() || rep.Records != 1 {
				t.Errorf("findings %+v", rep.Findings)
			}
		})
	}
}

// The four stores of the page are taken, each when the plan gives it: a key can live on a card, in
// the cloud or in a file.
func TestRecordTakesEachStoreThatThePlanGives(t *testing.T) {
	for _, store := range []string{"piv", "openpgp-card", "aws-kms", "software"} {
		t.Run(store, func(t *testing.T) {
			fl := transcribed(t, planRoot(map[string]any{"label": "A", "store": store, "test": true, "copyable": true}))
			root := rootOfTheFlow()
			root.Store = store
			out, err := recordWithRoot(fl, root)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			r, _ := files.ReadRecord(out)
			if r.Root == nil || r.Root.Store != store {
				t.Errorf("the root of the record: %+v", r.Root)
			}
		})
	}
}

// A root that is a key file and not a test, and a root that is a test and not a file: the two
// members are the plan's either way, and each pair is taken.
func TestRecordTakesEachPairOfTestAndCopyableThatThePlanGives(t *testing.T) {
	for _, test := range []bool{false, true} {
		for _, copyable := range []bool{false, true} {
			name := "test " + map[bool]string{false: "false", true: "true"}[test] + ", copyable " + map[bool]string{false: "false", true: "true"}[copyable]
			t.Run(name, func(t *testing.T) {
				m := map[string]any{"label": "A", "store": "software"}
				if test {
					m["test"] = true
				}
				if copyable {
					m["copyable"] = true
				}
				fl := transcribed(t, planRoot(m))
				root := &files.PlanRoot{Label: "A", Store: "software", X509: rep('a'), Test: test, Copyable: copyable}
				out, err := recordWithRoot(fl, root)
				if err != nil {
					t.Fatalf("Record: %v", err)
				}
				r, _ := files.ReadRecord(out)
				if r.Root == nil || r.Root.Test != test || r.Root.Copyable != copyable {
					t.Errorf("the root of the record: %+v", r.Root)
				}
				// A caller that flips either member is refused.
				fl2 := transcribed(t, planRoot(m))
				flipped := *root
				flipped.Test = !test
				wantRootRefused(t, fl2, &flipped, nil, "test member")
				flipped = *root
				flipped.Copyable = !copyable
				wantRootRefused(t, fl2, &flipped, nil, "copyable member")
			})
		}
	}
}

// A plan that names no root has no root to follow: a caller that gives one is refused, and a caller
// that gives none gets a record with no root member.
func TestRecordOfAPlanWithNoRoot(t *testing.T) {
	t.Run("a root is given", func(t *testing.T) {
		fl := transcribed(t, planRoot(nil))
		wantRootRefused(t, fl, rootOfTheFlow(), nil, "plan", "no root")
		out, err := recordWithRoot(fl, nil)
		if err != nil {
			t.Fatalf("no root after the refusal: %v", err)
		}
		if strings.Contains(string(out), `"root"`) {
			t.Errorf("a record of a plan with no root has a root: %s", out)
		}
	})
	t.Run("an empty root is given", func(t *testing.T) {
		fl := transcribed(t, planRoot(nil))
		wantRootRefused(t, fl, &files.PlanRoot{}, nil, "no root")
	})
	t.Run("none is given", func(t *testing.T) {
		fl := transcribed(t, planRoot(nil))
		out, err := recordWithRoot(fl, nil)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		r, err := files.ReadRecord(out)
		if err != nil {
			t.Fatal(err)
		}
		if r.Root != nil || strings.Contains(string(out), `"root"`) {
			t.Errorf("the record has a root: %s", out)
		}
		if rep := fl.b.check(); !rep.Clean() {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
}

// A plan that gives a member of its root and nothing more has nothing to compare for the others:
// the label of the caller is judged by its form, and the pin is the one of the caller's label.
func TestRecordOfAPlanRootThatGivesFewMembers(t *testing.T) {
	t.Run("a plan root with no label, the caller's label is born with this pin", func(t *testing.T) {
		fl := transcribed(t, planRoot(map[string]any{"store": "software", "test": true, "copyable": true}))
		if _, err := recordWithRoot(fl, rootOfTheFlow()); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
	t.Run("a plan root with no label, the pin is still the one of the caller's label", func(t *testing.T) {
		fl := transcribed(t, planRoot(map[string]any{"store": "software", "test": true, "copyable": true}))
		root := rootOfTheFlow()
		root.X509 = rep('c')
		wantRootRefused(t, fl, root, rootOfTheFlow(), "X.509 fingerprint")
	})
	t.Run("a plan root with no label, the caller's label is still judged by its form", func(t *testing.T) {
		fl := transcribed(t, planRoot(map[string]any{"store": "software", "test": true, "copyable": true}))
		root := rootOfTheFlow()
		root.Label = "AB"
		wantRootRefused(t, fl, root, rootOfTheFlow(), "label of the root")
	})
	t.Run("a plan root with no store, the caller's store is judged by its form", func(t *testing.T) {
		fl := transcribed(t, planRoot(map[string]any{"label": "A", "test": true, "copyable": true}))
		root := rootOfTheFlow()
		root.Store = "card"
		wantRootRefused(t, fl, root, rootOfTheFlow(), "store of the root")
	})
	t.Run("a plan root with no store, a store of a kind is taken", func(t *testing.T) {
		fl := transcribed(t, planRoot(map[string]any{"label": "A", "test": true, "copyable": true}))
		root := rootOfTheFlow()
		root.Store = "aws-kms"
		if _, err := recordWithRoot(fl, root); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
}

// The fingerprint is the one of the birth that has the label of the root, and only then: a label
// that the journal of this ceremony has no line for (a key that was born in an earlier one) has no
// pin to compare, and an empty fingerprint is not compared.
func TestRecordComparesTheFingerprintOfTheRootWithTheBirthOfItsLabel(t *testing.T) {
	// Two births, A and B; the fingerprints are not the same.
	twoBirths := func(t *testing.T, rootLabel string) *flow {
		t.Helper()
		fl := transcribed(t, func(s *spec) {
			s.edit = func(m map[string]any) {
				m["births"] = []any{
					plannedBirth("A", "x509-root", "software", "A.x509.key.pem"),
					plannedBirth("B", "x509-root", "software", "B.x509.key.pem"),
				}
				m["root"] = map[string]any{"label": rootLabel, "store": "software", "test": true, "copyable": true}
			}
		})
		journal := string(birthBytes(t, "A", rep('a'))) + "\n" + string(birthBytes(t, "B", rep('b'))) + "\n"
		mustWrite(t, fl.b.path("history", name1, "births.jsonl"), journal)
		return fl
	}
	root := func(label, x509 string) *files.PlanRoot {
		return &files.PlanRoot{Label: label, Store: "software", X509: x509, Test: true, Copyable: true}
	}
	t.Run("the pin of the first birth", func(t *testing.T) {
		fl := twoBirths(t, "A")
		if _, err := recordWithRoot(fl, root("A", rep('a'))); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
	t.Run("the pin of the second birth", func(t *testing.T) {
		fl := twoBirths(t, "B")
		if _, err := recordWithRoot(fl, root("B", rep('b'))); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
	t.Run("the pin of the other birth is refused", func(t *testing.T) {
		fl := twoBirths(t, "B")
		wantRootRefused(t, fl, root("B", rep('a')), root("B", rep('b')), "X.509 fingerprint", `"B"`, strings.Repeat("a", 40), strings.Repeat("b", 40))
	})
	t.Run("the pin of the other birth is refused for the first label too", func(t *testing.T) {
		fl := twoBirths(t, "A")
		wantRootRefused(t, fl, root("A", rep('b')), root("A", rep('a')), "X.509 fingerprint", `"A"`)
	})
	t.Run("no fingerprint is taken for the second birth", func(t *testing.T) {
		fl := twoBirths(t, "B")
		if _, err := recordWithRoot(fl, root("B", "")); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
	t.Run("a label that this ceremony did not birth has no pin", func(t *testing.T) {
		fl := twoBirths(t, "C")
		if _, err := recordWithRoot(fl, root("C", rep('f'))); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if rep := fl.b.check(); !rep.Clean() {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
	t.Run("a label that this ceremony did not birth, with no fingerprint", func(t *testing.T) {
		fl := twoBirths(t, "C")
		if _, err := recordWithRoot(fl, root("C", "")); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
	t.Run("a plan with no birth at all has no pin", func(t *testing.T) {
		fl := transcribed(t, func(s *spec) {
			s.edit = func(m map[string]any) { delete(m, "births") }
		})
		mustWrite(t, fl.b.path("history", name1, "births.jsonl"), "")
		if _, err := recordWithRoot(fl, root("A", rep('c'))); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
}

// The fingerprint that is compared is the one of the file that Record read and took the digest of:
// a journal that is put right after a refusal changes the answer.
func TestRecordTakesThePinOfTheJournalAsItIsOnTheDisk(t *testing.T) {
	fl := transcribed(t, nil)
	root := rootOfTheFlow()
	root.X509 = rep('c')
	wantRootRefused(t, fl, root, nil, "X.509 fingerprint")
	mustWrite(t, fl.b.path("history", name1, "births.jsonl"), string(birthBytes(t, "A", rep('c')))+"\n")
	out, err := recordWithRoot(fl, root)
	if err != nil {
		t.Fatalf("the same root after the journal has the fingerprint: %v", err)
	}
	r, _ := files.ReadRecord(out)
	if r.BirthsSHA256 != sum(append(birthBytes(t, "A", rep('c')), '\n')) {
		t.Errorf("births_sha256 %s is not the digest of the file that holds the pin", r.BirthsSHA256)
	}
}

// The values that a refusal shows are escaped and short, whatever the caller gives, so that a root
// that is made to look like something else cannot write on the screen of the person who reads it.
func TestRecordShowsTheValuesOfARefusedRootEscaped(t *testing.T) {
	long := strings.Repeat("A", 5000)
	for name, root := range map[string]*files.PlanRoot{
		"a long label":               {Label: long, Store: "software", Test: true, Copyable: true},
		"a label of escape codes":    {Label: "\x1b[31m\x1b[2J", Store: "software", Test: true, Copyable: true},
		"a label with a quote":       {Label: `"A`, Store: "software", Test: true, Copyable: true},
		"a label with a backslash":   {Label: `\`, Store: "software", Test: true, Copyable: true},
		"a label of a right-to-left": {Label: "\u202e", Store: "software", Test: true, Copyable: true},
		"a label above U+FFFF":       {Label: "\U0001F600", Store: "software", Test: true, Copyable: true},
		"a long store":               {Label: "A", Store: strings.Repeat("s", 5000), Test: true, Copyable: true},
		"a store of escape codes":    {Label: "A", Store: "\x1b]0;x\x07", Test: true, Copyable: true},
		"a store with a NUL":         {Label: "A", Store: "soft\x00ware", Test: true, Copyable: true},
	} {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, nil)
			wantRootRefused(t, fl, root, rootOfTheFlow(), "root")
			// wantKind inside wantRootRefused has judged the text: printable ASCII, at most 1,200 bytes.
		})
	}
}

// The page says the root of the record is "as in the plan", and the root of a plan has the two key
// fingerprints as members too: a plan that gives a fingerprint is followed by the record. This test
// states the page: a fingerprint that the plan's root gives is the record's, and a different one is
// refused. (The tests of a fingerprint that the caller leaves out are in
// TestRecordRefusesAFingerprintThatThePlanGivesAndTheCallerLeavesOut.)
func TestRecordFollowsTheFingerprintsThatTheRootOfThePlanGives(t *testing.T) {
	plan := func(x509, openpgp string) map[string]any {
		m := map[string]any{"label": "A", "store": "software", "test": true, "copyable": true}
		if x509 != "" {
			m["x509"] = x509
		}
		if openpgp != "" {
			m["openpgp"] = openpgp
		}
		return m
	}
	pgp := func(c byte) string { return strings.Repeat(string(c), 40) }
	cases := []struct {
		name  string
		plan  map[string]any
		root  *files.PlanRoot
		words []string // nil is accepted
	}{
		{"an X.509 fingerprint that is the plan's", plan(rep('a'), ""), rootOfTheFlow(), nil},
		{"an OpenPGP fingerprint that is the plan's", plan("", pgp('b')), &files.PlanRoot{Label: "A", Store: "software", X509: rep('a'), OpenPGP: pgp('b'), Test: true, Copyable: true}, nil},
		{"an X.509 fingerprint that is not the plan's", plan(rep('b'), ""), rootOfTheFlow(), []string{"X.509"}},
		{"an OpenPGP fingerprint that is not the plan's", plan("", pgp('b')), &files.PlanRoot{Label: "A", Store: "software", X509: rep('a'), OpenPGP: pgp('c'), Test: true, Copyable: true}, []string{"OpenPGP"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, planRoot(c.plan))
			if c.words == nil {
				if _, err := recordWithRoot(fl, c.root); err != nil {
					t.Fatalf("Record: %v", err)
				}
				return
			}
			wantRootRefused(t, fl, c.root, nil, c.words...)
		})
	}
}

// A plan whose root is not an object of the members of the page is not a plan that is written: the
// reader of the plan refuses it before any write. The same plan put on the disk by another hand, after
// the folder was written, is refused by Record, with a root given or not, and nothing is written.
func TestRecordRefusesAPlanWhoseRootIsHostile(t *testing.T) {
	for name, root := range map[string]any{
		"a text":                      "A",
		"a number":                    5,
		"a list":                      []any{"A"},
		"a list of objects":           []any{map[string]any{"label": "A"}},
		"a true":                      true,
		"a member that is unknown":    map[string]any{"label": "A", "store": "software", "colour": "red"},
		"a label that is a number":    map[string]any{"label": 5, "store": "software"},
		"a store that is a list":      map[string]any{"label": "A", "store": []any{"software"}},
		"a test that is a text":       map[string]any{"label": "A", "store": "software", "test": "true"},
		"a copyable that is a number": map[string]any{"label": "A", "store": "software", "copyable": 1},
		"a root nested deeply":        deepRoot(2000),
	} {
		t.Run(name, func(t *testing.T) {
			s := newSpec(name1, 1, "")
			s.edit = func(m map[string]any) { m["root"] = root }
			b := newBundle(t)
			f, _ := ceremony.NewFolder(b.w, name1)
			err := f.WritePlan(s.plan(t), s.copies)
			wantKind(t, err, ceremony.ErrInvalidInput)
			if got := b.r.snapshot(); len(got) != 0 {
				t.Errorf("a refused plan reached the file system: %v", got)
			}
		})
		for _, given := range []*files.PlanRoot{nil, rootOfTheFlow()} {
			t.Run(fmt.Sprintf("%s, put on the disk, root given %v", name, given != nil), func(t *testing.T) {
				fl := transcribed(t, nil)
				hostile := newSpec(name1, 1, "")
				hostile.edit = func(m map[string]any) { m["root"] = root }
				mustWrite(t, fl.b.path("history", name1, "plan.json"), string(hostile.plan(t)))
				before := tree(t, fl.b.dir)
				out, err := recordWithRoot(fl, given)
				if err == nil {
					t.Fatalf("a record was written for a plan with a root that is %s: %s", name, out)
				}
				if errors.Is(err, ceremony.ErrFolderStopped) {
					t.Error("a refusal stopped the folder")
				}
				sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
				noRecord(t, fl)
			})
		}
	}
}

// deepRoot is a root that holds an object n levels deep.
func deepRoot(n int) any {
	var v any = "x"
	for i := 0; i < n; i++ {
		v = map[string]any{"a": v}
	}
	return map[string]any{"label": "A", "store": "software", "deep": v}
}

// The reason of a refusal says which value is the caller's and which is the plan's (or the birth's),
// in the same order for every member: the caller's first.
func TestRecordSaysWhichValueOfARootIsWhose(t *testing.T) {
	cases := []struct {
		name string
		root func(r *files.PlanRoot)
		want string
	}{
		{"label", func(r *files.PlanRoot) { r.Label = "B" }, `the label of the root is "B" and the plan's root has "A"`},
		{"store", func(r *files.PlanRoot) { r.Store = "piv" }, `the store of the root is "piv" and the plan's root has "software"`},
		{"test", func(r *files.PlanRoot) { r.Test = false }, `the test member of the root is false and the plan's root has true`},
		{"copyable", func(r *files.PlanRoot) { r.Copyable = false }, `the copyable member of the root is false and the plan's root has true`},
		{"X.509 fingerprint", func(r *files.PlanRoot) { r.X509 = rep('c') }, `the X.509 fingerprint of the root is "` + strings.Repeat("c", 40) + `..." and the line of births.jsonl for the key "A" has "` + strings.Repeat("a", 40) + `..."`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, nil)
			root := rootOfTheFlow()
			c.root(root)
			_, err := recordWithRoot(fl, root)
			wantKind(t, err, ceremony.ErrInvalidInput)
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the reason is %q, want one that holds %q", err, c.want)
			}
		})
	}
}
