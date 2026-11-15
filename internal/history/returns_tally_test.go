//go:build linux || darwin

package history

import "testing"

// The running tally of the lists before a list holds counts only: only the tallies that are read as the group before and
// the group of the list have a size, and merging adds the counts of one tally to another and not its size.
func TestTallyMergeAddsTheCountsAndNotTheSize(t *testing.T) {
	var pin [32]byte
	pin[0] = 1
	var fp [20]byte
	fp[0] = 2
	k := rootKey{label: "A", hasPin: true, pin: pin, hasFP: true, fp: fp}

	one, two := &tally{size: 1}, &tally{size: 2}
	one.addList([]rootKey{k, k}) // a list counts once for a key, however many entries name it
	two.addList([]rootKey{k})
	if one.pin[pin] != 1 || one.fp[fp] != 1 || len(one.fpPin) != 1 {
		t.Fatalf("a list that names a key twice counts it once: %v %v %v", one.pin, one.fp, one.fpPin)
	}

	cum := &tally{}
	cum.merge(one)
	cum.merge(two)
	if cum.pin[pin] != 2 || cum.fp[fp] != 2 {
		t.Errorf("the counts are %d and %d, want 2 and 2", cum.pin[pin], cum.fp[fp])
	}
	for _, n := range cum.fpPin {
		if n != 2 {
			t.Errorf("the count of the fingerprint under its pin is %d, want 2", n)
		}
	}
	if cum.size != 0 {
		t.Errorf("the running tally has the size %d: merging adds counts only", cum.size)
	}
	// The tally that is merged is not changed.
	if one.size != 1 || two.size != 2 || one.pin[pin] != 1 || two.pin[pin] != 1 {
		t.Errorf("merging changed what it merged: %+v %+v", one, two)
	}
}
