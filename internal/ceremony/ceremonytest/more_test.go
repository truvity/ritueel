package ceremonytest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// More adds ceremonies after a recorded one: the history stays whole, each record names the one
// before it, each root list is the list before with one key more and the next sequence, and the
// bundle is changed in the same folder.
func TestMoreAddsCeremoniesToTheChain(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	first := readFile(t, m.Dir, "history", m.Ceremony, "record.json")
	firstList := readFile(t, m.Dir, "trust", m.Set, "root-list.json")
	before := *m
	beforePins := slices.Clone(m.Pins)

	out := ceremonytest.More(t, m, 2)

	// m is not changed.
	if m.Ceremony != before.Ceremony || m.Set != before.Set || m.PlanSHA256 != before.PlanSHA256 || m.AttemptSHA256 != before.AttemptSHA256 || !slices.Equal(m.Pins, beforePins) {
		t.Errorf("More changed its argument: %+v, was %+v", *m, before)
	}
	if out == m || out.Dir != m.Dir || out.KeyDir != m.KeyDir {
		t.Errorf("the result %+v is not a copy of %+v with the same folders", out, m)
	}
	rep, in := check(t, m.Dir)
	if len(rep.Findings) != 0 || rep.Records != 3 {
		t.Fatalf("findings %v, %d records; want a clean history of 3", rep.Findings, rep.Records)
	}
	if want := fmt.Sprintf("history: 3 ceremony records, end %s", in.State.End[:8]); rep.EndLine() != want {
		t.Errorf("EndLine = %q, want %q", rep.EndLine(), want)
	}
	st := in.State
	if len(st.Chain) != 3 || st.Chain[0].Folder != m.Ceremony {
		t.Fatalf("Chain = %+v", st.Chain)
	}
	for i, c := range st.Chain {
		if c.Command != "apply" || c.Outcome != "completed" {
			t.Errorf("Chain[%d] = %+v", i, c)
		}
		rec, err := files.ReadRecord(readFile(t, m.Dir, "history", c.Folder, "record.json"))
		if err != nil {
			t.Fatalf("Chain[%d]: %v", i, err)
		}
		wantPrev := ""
		if i > 0 {
			wantPrev = st.Chain[i-1].SHA256
		}
		if rec.PrevRecordSHA256 != wantPrev {
			t.Errorf("Chain[%d] names %q before it, want %q", i, rec.PrevRecordSHA256, wantPrev)
		}
		plan, err := files.ReadPlan(readFile(t, m.Dir, "history", c.Folder, "plan.json"))
		if err != nil {
			t.Fatalf("Chain[%d]: %v", i, err)
		}
		if plan.LastRecordSHA256 != wantPrev || plan.Ceremony != c.Folder || *plan.TrustSequence != int64(i+1) {
			t.Errorf("Chain[%d] plan: last %q ceremony %q sequence %d", i, plan.LastRecordSHA256, plan.Ceremony, *plan.TrustSequence)
		}
	}
	// The first ceremony is as it was.
	if got := readFile(t, m.Dir, "history", m.Ceremony, "record.json"); string(got) != string(first) {
		t.Error("the record of the first ceremony changed")
	}
	if got := readFile(t, m.Dir, "trust", m.Set, "root-list.json"); string(got) != string(firstList) {
		t.Error("the root list of the first ceremony changed")
	}
	// The lists: sequence 1, 2, 3, one key more each time, with the next letter.
	if len(st.Lists) != 3 {
		t.Fatalf("Lists = %d", len(st.Lists))
	}
	for i, l := range st.Lists {
		if len(l.Keys) != i+2 {
			t.Errorf("list %d has %d keys, want %d", i, len(l.Keys), i+2)
		}
		for j, k := range l.Keys {
			if k.Label != string(rune('A'+j)) {
				t.Errorf("list %d key %d has the label %q", i, j, k.Label)
			}
		}
	}
	if st.Newest.Number != 3 || st.NewestListed.Name != st.Newest.Name || st.Newest.Name != out.Set {
		t.Errorf("Newest %+v, NewestListed %+v, Set %s", st.Newest, st.NewestListed, out.Set)
	}
	// The new roots exist and the set name is the number and the first eight characters of the list.
	for _, label := range []string{"C", "D"} {
		if _, err := os.Stat(filepath.Join(m.Dir, "roots", label, "root.json")); err != nil {
			t.Errorf("roots/%s: %v", label, err)
		}
	}
	list := readFile(t, m.Dir, "trust", out.Set, "root-list.json")
	if want := fmt.Sprintf("3-%s", files.Digest(list)[:8]); out.Set != want {
		t.Errorf("Set = %s, want %s", out.Set, want)
	}
	// The result names the newest ceremony.
	if out.Ceremony != st.Chain[2].Folder {
		t.Errorf("Ceremony = %s, want the newest %s", out.Ceremony, st.Chain[2].Folder)
	}
	if out.Ceremony != "20261120T120000Z-apply" || st.Chain[1].Folder != "20261120T110000Z-apply" {
		t.Errorf("the ceremonies are named %s and %s: each is an hour after the one before", st.Chain[1].Folder, out.Ceremony)
	}
	if out.PlanSHA256 != digestOf(t, filepath.Join(m.Dir, "history", out.Ceremony, "plan.json")) || out.AttemptSHA256 != digestOf(t, filepath.Join(m.Dir, "history", out.Ceremony, "attempt.json")) {
		t.Errorf("the digests of the result are not those of the files of %s", out.Ceremony)
	}
	if len(out.Pins) != 4 || !slices.Equal(out.Pins[:2], beforePins) || out.Pins[2] == out.Pins[3] {
		t.Errorf("Pins = %v, want the two of the bundle and two more", out.Pins)
	}
	// What a synthetic ceremony writes of the first one's wanted files: the copies are the files now.
	for _, p := range []string{"ritueel.yaml", "want/roots/x509.yaml"} {
		if string(readFile(t, m.Dir, "history", out.Ceremony, "wanted", p)) != string(readFile(t, m.Dir, p)) {
			t.Errorf("the copy of %s is not the file", p)
		}
	}
}

// Two calls of one are the same as one call of two, in names and shape.
func TestMoreOneAndOneIsTwo(t *testing.T) {
	a := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	b := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	step := ceremonytest.More(t, ceremonytest.More(t, a, 1), 1)
	both := ceremonytest.More(t, b, 2)
	if step.Ceremony != both.Ceremony || len(step.Pins) != len(both.Pins) || len(step.Pins) != 4 {
		t.Errorf("%s %v, %s %v", step.Ceremony, step.Pins, both.Ceremony, both.Pins)
	}
	if x, y := shape(treeOf(t, a.Dir)), shape(treeOf(t, b.Dir)); !slices.Equal(x, y) {
		t.Errorf("the bundles differ in their files:\n%v\n%v", x, y)
	}
	if _, in := check(t, a.Dir); in.State == nil || in.State.Records != 3 {
		t.Errorf("State %+v", in.State)
	}
}

// A ceremony that More adds has no real key and signs nothing: the root list is not signed, no key
// file is made, and no secret is written.
func TestMoreMakesNoKeyAndNoSignature(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	keysBefore := shape(treeOf(t, m.KeyDir))
	out := ceremonytest.More(t, m, 1)
	if got := shape(treeOf(t, m.KeyDir)); !slices.Equal(got, keysBefore) {
		t.Errorf("the key directory changed: %v", got)
	}
	for _, name := range []string{"root-list.jws", "ca-bundle.pem"} {
		if _, err := os.Stat(filepath.Join(m.Dir, "trust", out.Set, name)); err == nil {
			t.Errorf("trust/%s/%s exists: a synthetic list is not signed", out.Set, name)
		}
	}
}

// More refuses what it cannot continue: a bundle that was not made by Bundle, a number below 1, a
// bundle with no recorded ceremony, an open attempt, a history that is not whole.
func TestMoreRefuses(t *testing.T) {
	recorded := func(t *testing.T) *ceremonytest.Made {
		return ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	}
	t.Run("no bundle", func(t *testing.T) {
		for _, m := range []*ceremonytest.Made{nil, {}} {
			msg := failsWith(t, func(tb testing.TB) { ceremonytest.More(tb, m, 1) })
			if !strings.Contains(msg, "needs a bundle") {
				t.Errorf("message %q", msg)
			}
		}
	})
	t.Run("a number below 1", func(t *testing.T) {
		m := recorded(t)
		for _, n := range []int{0, -4} {
			msg := failsWith(t, func(tb testing.TB) { ceremonytest.More(tb, m, n) })
			if !strings.Contains(msg, "at least 1") {
				t.Errorf("n=%d: message %q", n, msg)
			}
		}
		if _, in := check(t, m.Dir); in.State.Records != 1 {
			t.Errorf("a refusal wrote a record")
		}
	})
	t.Run("a bundle with no recorded ceremony", func(t *testing.T) {
		for _, step := range []ceremonytest.Step{ceremonytest.AtPlan, ceremonytest.AtAttempt, ceremonytest.AtSignatures, ceremonytest.AtSet} {
			m := ceremonytest.Bundle(t, ceremonytest.Options{Step: step})
			before := shape(treeOf(t, m.Dir))
			msg := failsWith(t, func(tb testing.TB) { ceremonytest.More(tb, m, 1) })
			if !strings.Contains(msg, "recorded ceremony") {
				t.Errorf("%s: message %q", step, msg)
			}
			if after := shape(treeOf(t, m.Dir)); !slices.Equal(before, after) {
				t.Errorf("%s: a refusal changed the bundle", step)
			}
		}
	})
	t.Run("an open attempt", func(t *testing.T) {
		m := recorded(t)
		open := filepath.Join(m.Dir, "history", "20270101T000000Z-apply")
		if err := os.Mkdir(open, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(open, "attempt.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.More(tb, m, 1) })
		if !strings.Contains(msg, "no open attempt") || !strings.Contains(msg, "20270101T000000Z-apply") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a history that is not whole", func(t *testing.T) {
		m := recorded(t)
		if err := os.WriteFile(filepath.Join(m.Dir, "history", m.Ceremony, "transcript.txt"), []byte("changed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.More(tb, m, 1) })
		if !strings.Contains(msg, "no state") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a bundle that is gone", func(t *testing.T) {
		m := recorded(t)
		if err := os.RemoveAll(m.Dir); err != nil {
			t.Fatal(err)
		}
		failsWith(t, func(tb testing.TB) { ceremonytest.More(tb, m, 1) })
	})
	t.Run("a wanted file that is gone", func(t *testing.T) {
		m := recorded(t)
		if err := os.Remove(filepath.Join(m.Dir, "want", "roots", "x509.yaml")); err != nil {
			t.Fatal(err)
		}
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.More(tb, m, 1) })
		if !strings.Contains(msg, "wanted file") {
			t.Errorf("message %q", msg)
		}
	})
}

// What More returns is its own: two results made from one bundle do not share the list of pins, so
// that a later call does not change an earlier result.
func TestMoreResultsDoNotShareTheirPins(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	a := ceremonytest.More(t, m, 1)
	aPins := slices.Clone(a.Pins)
	b := ceremonytest.More(t, a, 1)
	bPins := slices.Clone(b.Pins)
	c := ceremonytest.More(t, a, 1)
	if !slices.Equal(a.Pins, aPins) {
		t.Errorf("a later call changed the pins of an earlier result: %v, was %v", a.Pins, aPins)
	}
	if !slices.Equal(b.Pins, bPins) {
		t.Errorf("a second call from the same result changed the pins of the first: %v, was %v", b.Pins, bPins)
	}
	if len(b.Pins) != 4 || len(c.Pins) != 4 || b.Pins[3] == c.Pins[3] {
		t.Errorf("pins %v and %v: the two ceremonies have each their own key", b.Pins, c.Pins)
	}
	if len(m.Pins) != 2 {
		t.Errorf("the pins of the bundle changed: %v", m.Pins)
	}
}
