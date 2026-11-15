package ceremony_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The page says that `root` of the record is "as in the plan". The tests of this file hold the two
// ends of that: a fingerprint that the plan's root gives is the record's, and a record has a root
// exactly when the plan names one.

func pgpOf(c byte) string { return strings.Repeat(string(c), 40) }

// planRootWith is the root of the flow's plan with the fingerprints that the plan gives.
func planRootWith(x509, openpgp string) map[string]any {
	m := map[string]any{"label": "A", "store": "software", "test": true, "copyable": true}
	if x509 != "" {
		m["x509"] = x509
	}
	if openpgp != "" {
		m["openpgp"] = openpgp
	}
	return m
}

// rootWith is a root that is the flow's root, with the fingerprints given and no other.
func rootWith(x509, openpgp string) *files.PlanRoot {
	return &files.PlanRoot{Label: "A", Store: "software", X509: x509, OpenPGP: openpgp, Test: true, Copyable: true}
}

// says gives the words of the refusal of one fingerprint: the caller's value comes first and the
// plan's second, each cut at its first 20 characters (the text shows 40 at most).
func says(member, caller, plan string) []string {
	cut := func(v string) string {
		if len(v) > 20 {
			return v[:20]
		}
		return v
	}
	return []string{
		"the " + member + " fingerprint of the root is \"" + cut(caller),
		"and the plan's root has \"" + cut(plan),
	}
}

// A fingerprint that the plan's root gives and the caller leaves out is a difference: the record
// would lose a member that the plan has. Each case is refused with no record.json, the Folder is
// not stopped, and the same Folder takes the root of the plan afterwards.
func TestRecordRefusesAFingerprintThatThePlanGivesAndTheCallerLeavesOut(t *testing.T) {
	x, p := rep('a'), pgpOf('b')
	cases := []struct {
		name  string
		plan  map[string]any
		root  *files.PlanRoot
		good  *files.PlanRoot
		words []string
	}{
		{"X.509, the caller gives none", planRootWith(x, ""), rootWith("", ""), rootWith(x, ""), says("X.509", "", x)},
		{"X.509, the caller gives none and an OpenPGP one", planRootWith(x, ""), rootWith("", p), rootWith(x, p), says("X.509", "", x)},
		{"OpenPGP, the caller gives none", planRootWith("", p), rootWith("", ""), rootWith("", p), says("OpenPGP", "", p)},
		{"OpenPGP, the caller gives none and an X.509 one", planRootWith("", p), rootWith(x, ""), rootWith(x, p), says("OpenPGP", "", p)},
		{"both, the caller gives none", planRootWith(x, p), rootWith("", ""), rootWith(x, p), says("X.509", "", x)},
		{"both, the caller gives the X.509 one only", planRootWith(x, p), rootWith(x, ""), rootWith(x, p), says("OpenPGP", "", p)},
		{"both, the caller gives the OpenPGP one only", planRootWith(x, p), rootWith("", p), rootWith(x, p), says("X.509", "", x)},
		{"both, the OpenPGP one is another", planRootWith(x, p), rootWith(x, pgpOf('c')), rootWith(x, p), says("OpenPGP", pgpOf('c'), p)},
		{"both, the X.509 one is another", planRootWith(x, p), rootWith(rep('b'), p), rootWith(x, p), says("X.509", rep('b'), x)},
		{"the OpenPGP one with its last digit changed", planRootWith("", p), rootWith("", p[:39]+"c"), rootWith("", p), []string{"OpenPGP fingerprint"}},
		{"the OpenPGP one with its first digit changed", planRootWith("", p), rootWith("", "c"+p[1:]), rootWith("", p), says("OpenPGP", "c"+p[1:], p)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, planRoot(c.plan))
			wantRootRefused(t, fl, c.root, c.good, c.words...)
		})
	}
}

// A fingerprint that the plan's root gives is written as it is, together with one that the plan does
// not give; the plan's X.509 fingerprint must still be the pin of the birth.
func TestRecordTakesTheFingerprintsThatThePlanGives(t *testing.T) {
	x, p := rep('a'), pgpOf('b')
	cases := []struct {
		name string
		plan map[string]any
		root *files.PlanRoot
	}{
		{"the X.509 one of the plan", planRootWith(x, ""), rootWith(x, "")},
		{"the OpenPGP one of the plan", planRootWith("", p), rootWith("", p)},
		{"both of the plan", planRootWith(x, p), rootWith(x, p)},
		{"the OpenPGP one added to the X.509 one of the plan", planRootWith(x, ""), rootWith(x, p)},
		{"the X.509 one added to the OpenPGP one of the plan", planRootWith("", p), rootWith(x, p)},
		{"none in the plan, none given", planRootWith("", ""), rootWith("", "")},
		{"none in the plan, both added", planRootWith("", ""), rootWith(x, p)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, planRoot(c.plan))
			out, err := recordWithRoot(fl, c.root)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			r, err := files.ReadRecord(out)
			if err != nil {
				t.Fatalf("the reader refuses the record: %v", err)
			}
			if !reflect.DeepEqual(r.Root, c.root) {
				t.Errorf("the record has the root %+v, the caller gave %+v", r.Root, c.root)
			}
			if rep := fl.b.check(); !rep.Clean() {
				t.Errorf("findings %+v", rep.Findings)
			}
		})
	}
}

// The X.509 fingerprint that the plan gives and the caller repeats is still the pin of the birth of
// the label: a plan that names another fingerprint than the one of the birth line cannot be
// recorded, by the caller who agrees with the plan or by the one who agrees with the birth.
func TestRecordHoldsThePlansX509FingerprintToTheBirthToo(t *testing.T) {
	other := rep('b')
	for name, c := range map[string]struct {
		root  *files.PlanRoot
		words []string
	}{
		"the caller agrees with the plan":  {rootWith(other, ""), []string{"X.509 fingerprint", "births.jsonl"}},
		"the caller agrees with the birth": {rootWith(rep('a'), ""), []string{"X.509 fingerprint", "the plan's root has"}},
	} {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, planRoot(planRootWith(other, "")))
			wantRootRefused(t, fl, c.root, nil, c.words...)
		})
	}
}

// A plan that names a root and a caller that gives none: the record would lose a member that the
// page says is as in the plan. Refused with no record.json, whatever the root of the plan gives.
func TestRecordRefusesNoRootWhenThePlanNamesOne(t *testing.T) {
	x, p := rep('a'), pgpOf('b')
	for name, c := range map[string]struct {
		plan map[string]any
		good *files.PlanRoot
	}{
		"a root with every member":    {planRootWith(x, p), rootWith(x, p)},
		"a root with the X.509 one":   {planRootWith(x, ""), rootWith(x, "")},
		"a root with the OpenPGP one": {planRootWith("", p), rootWith("", p)},
		"a root with no fingerprint":  {planRootWith("", ""), rootWith("", "")},
		"a root with only a store":    {map[string]any{"store": "software"}, &files.PlanRoot{Label: "A", Store: "software"}},
		"a root with only a label":    {map[string]any{"label": "A"}, &files.PlanRoot{Label: "A"}},
		"a root with test false":      {map[string]any{"label": "A", "store": "software", "test": false, "copyable": false}, &files.PlanRoot{Label: "A", Store: "software"}},
		"an empty root":               {map[string]any{}, &files.PlanRoot{Label: "A"}},
	} {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, planRoot(c.plan))
			wantRootRefused(t, fl, nil, c.good, "the plan names a root", "the record is given none")
		})
	}
	t.Run("a plan with no root and no root given is written with no root member", func(t *testing.T) {
		fl := transcribed(t, planRoot(nil))
		out, err := recordWithRoot(fl, nil)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if strings.Contains(string(out), `"root"`) {
			t.Errorf("the record has a root: %s", out)
		}
		if rep := fl.b.check(); !rep.Clean() {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
	t.Run("a plan with no root and a root given is refused", func(t *testing.T) {
		fl := transcribed(t, planRoot(nil))
		wantRootRefused(t, fl, rootWith("", ""), nil, "no root")
		if _, err := recordWithRoot(fl, nil); err != nil {
			t.Fatalf("no root after the refusal: %v", err)
		}
	})
	t.Run("a root that is empty is not no root", func(t *testing.T) {
		fl := transcribed(t, planRoot(planRootWith("", "")))
		wantRootRefused(t, fl, &files.PlanRoot{}, rootWith("", ""), "label of the root")
	})
}

// Record judges one copy of what its caller gave. A caller that changes its input while Record runs,
// here from the file system, at the Nth time that Record opens a folder, puts nothing into the
// record that a check did not see: the record holds the values that the caller gave at the call.
func TestRecordJudgesOneCopyOfWhatTheCallerGave(t *testing.T) {
	given := func(fl *flow) (ceremony.RecordIn, *files.PlanRoot, *files.Confirmation, []string) {
		root := rootWith(rep('a'), pgpOf('b'))
		conf := &files.Confirmation{By: "flag", At: ts}
		arts := append([]string(nil), fl.s.artifactPaths()...)
		in := fl.recordIn()
		in.Root, in.Confirmation, in.Artifacts = root, conf, arts
		return in, root, conf, arts
	}
	mutations := []struct {
		name  string
		apply func(root *files.PlanRoot, conf *files.Confirmation, arts []string)
	}{
		{"the root", func(root *files.PlanRoot, _ *files.Confirmation, _ []string) {
			*root = files.PlanRoot{Label: "B", Store: "piv", X509: rep('9'), OpenPGP: pgpOf('3'), Test: false, Copyable: false}
		}},
		{"the label of the root", func(root *files.PlanRoot, _ *files.Confirmation, _ []string) { root.Label = "B" }},
		{"the store of the root", func(root *files.PlanRoot, _ *files.Confirmation, _ []string) { root.Store = "piv" }},
		{"the X.509 fingerprint of the root", func(root *files.PlanRoot, _ *files.Confirmation, _ []string) { root.X509 = rep('9') }},
		{"the OpenPGP fingerprint of the root", func(root *files.PlanRoot, _ *files.Confirmation, _ []string) { root.OpenPGP = pgpOf('3') }},
		{"test and copyable of the root", func(root *files.PlanRoot, _ *files.Confirmation, _ []string) { root.Test, root.Copyable = false, false }},
		{"the confirmation", func(_ *files.PlanRoot, conf *files.Confirmation, _ []string) {
			*conf = files.Confirmation{By: "typed", At: "2026-11-14T10:06:00Z"}
		}},
		{"an artifact path, for another that is in the list", func(_ *files.PlanRoot, _ *files.Confirmation, arts []string) { arts[0] = arts[1] }},
		{"an artifact path, for one that is not a file", func(_ *files.PlanRoot, _ *files.Confirmation, arts []string) { arts[0] = "roots/B/root.json" }},
		{"an artifact path, for one that is not a path", func(_ *files.PlanRoot, _ *files.Confirmation, arts []string) { arts[1] = "../x" }},
		{"all of them", func(root *files.PlanRoot, conf *files.Confirmation, arts []string) {
			*root = files.PlanRoot{Label: "B", Store: "piv", X509: rep('9'), OpenPGP: pgpOf('3')}
			*conf = files.Confirmation{By: "typed", At: "2026-11-14T10:06:00Z"}
			arts[0], arts[1] = "roots/B/root.json", "../x"
		}},
	}
	// The number of the folders that Record opens, counted once: the change is made at each of them.
	opens := func() int {
		fl := transcribed(t, nil)
		in, _, _, _ := given(fl)
		n := 0
		fl.b.r.openHook = func(string) { n++ }
		if _, err := fl.f.Record(in); err != nil {
			t.Fatalf("Record: %v", err)
		}
		return n
	}()
	if opens < 3 {
		t.Fatalf("Record opened %d folders: the test cannot change the input between its reads", opens)
	}
	for _, m := range mutations {
		// The whole root and the change of everything are made at every open; the single members at
		// the first, the middle and the last.
		for at := 1; at <= opens; at++ {
			if m.name != "the root" && m.name != "all of them" && at != 1 && at != (opens+1)/2 && at != opens {
				continue
			}
			t.Run(fmt.Sprintf("%s changed at open %d of %d", m.name, at, opens), func(t *testing.T) {
				fl := transcribed(t, nil)
				in, root, conf, arts := given(fl)
				wantRoot, wantConf := *root, *conf
				wantArts := append([]string(nil), arts...)
				n, changed := 0, false
				fl.b.r.openHook = func(string) {
					n++
					if n == at {
						m.apply(root, conf, arts)
						changed = true
					}
				}
				out, err := fl.f.Record(in)
				if err != nil {
					t.Fatalf("Record: %v", err)
				}
				if !changed {
					t.Fatal("the input was not changed: the test shows nothing")
				}
				if reflect.DeepEqual(*root, wantRoot) && reflect.DeepEqual(*conf, wantConf) && reflect.DeepEqual(arts, wantArts) {
					t.Fatal("the change left the input as it was: the test shows nothing")
				}
				r, err := files.ReadRecord(out)
				if err != nil {
					t.Fatalf("the reader refuses the record: %v", err)
				}
				if r.Root == nil || *r.Root != wantRoot {
					t.Errorf("the record has the root %+v, the caller gave %+v", r.Root, wantRoot)
				}
				if r.Confirmation == nil || *r.Confirmation != wantConf {
					t.Errorf("the record has the confirmation %+v, the caller gave %+v", r.Confirmation, wantConf)
				}
				var got []string
				for _, a := range r.Artifacts {
					got = append(got, a.Path)
				}
				if len(got) != len(wantArts) {
					t.Fatalf("the record lists %v, the caller gave %v", got, wantArts)
				}
				for _, w := range wantArts {
					found := false
					for _, g := range got {
						found = found || g == w
					}
					if !found {
						t.Errorf("the record lists %v and not %q that the caller gave", got, w)
					}
				}
				if rep := fl.b.check(); !rep.Clean() {
					t.Errorf("findings %+v", rep.Findings)
				}
			})
		}
	}
}

// The same Record, with the change made after it returned: the record that was returned and the one
// on the disk do not follow the input of the caller either.
func TestRecordDoesNotKeepAHoldOfTheInputOfTheCaller(t *testing.T) {
	fl := transcribed(t, nil)
	root := rootWith(rep('a'), "")
	conf := &files.Confirmation{By: "flag", At: ts}
	in := fl.recordIn()
	in.Root, in.Confirmation = root, conf
	out, err := fl.f.Record(in)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	*root = files.PlanRoot{Label: "B", Store: "piv"}
	*conf = files.Confirmation{By: "typed", At: "x"}
	in.Artifacts[0] = "elsewhere"
	if disk := fl.b.read("history", name1, "record.json"); string(disk) != string(out) {
		t.Errorf("the record on the disk is not the record that was returned")
	}
	r, err := files.ReadRecord(out)
	if err != nil {
		t.Fatal(err)
	}
	if r.Root.Label != "A" || r.Confirmation.By != "flag" {
		t.Errorf("the record follows the input of the caller: %+v %+v", r.Root, r.Confirmation)
	}
}
