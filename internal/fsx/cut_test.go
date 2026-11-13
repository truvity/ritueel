package fsx_test

import (
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// What these tests prove: the order of the steps of the real writer, and what a cut between
// two steps leaves in a file system that the model of memfs_test.go describes. What they do
// not prove: that a real removable stick keeps a bundle whole after a cut. There a sector
// can keep the content of the write before it (issue 181; record 0005, "Not yet proven"),
// and the model has no such sector.

// TestCutRealWriterPassesTheOracleAtEveryCut writes the ceremony with the real writer, cuts it
// after every call under every policy, and runs the oracle on each image.
func TestCutRealWriterPassesTheOracleAtEveryCut(t *testing.T) {
	r := runCeremony(t, realMaker, defaultOrder)
	s := sweepCuts(r)

	// A check that finds nothing to check fails.
	if s.Ops < 60 {
		t.Fatalf("the ceremony made only %d file system calls; the cut test is not looking at it", s.Ops)
	}
	if want := (s.Ops + 1) * len(policiesUnderTest()); s.Images != want {
		t.Fatalf("looked at %d images, want %d (every cut under every policy)", s.Images, want)
	}
	if len(r.acks) < 17 {
		t.Fatalf("only %d returned calls are checked", len(r.acks))
	}
	kinds := map[opKind]bool{}
	for _, o := range r.fs.opList() {
		kinds[o.Kind] = true
	}
	for _, k := range []opKind{kMkdir, kCreate, kWrite, kSync, kClose, kRename, kSyncDir} {
		if !kinds[k] {
			t.Errorf("the ceremony never made a %s call", k)
		}
	}
	if s.PartialSaw == 0 {
		t.Errorf("no image held a torn last line of a journal: the partial path of ReadJournal is not exercised by a cut")
	}

	if len(s.Failures) > 0 {
		t.Fatalf("the oracle fails for the real writer after a cut:\n%s", s.table(40))
	}
	t.Logf("%d calls, %d cuts, %d policies, %d images; every image passes the oracle; %d images held a torn journal line",
		s.Ops, s.Ops+1, len(policiesUnderTest()), s.Images, s.PartialSaw)
}

// TestCutTheFinalPlaceOfEveryFileIsReachedByARename: in the real writer's log, a file that
// ends at a final name was created under a temporary name and moved there by one rename,
// except the journals, which are created at their final name.
func TestCutTheFinalPlaceOfEveryFileIsReachedByARename(t *testing.T) {
	r := runCeremony(t, realMaker, defaultOrder)
	finals := map[string]bool{}
	for p := range r.in.files {
		finals[p] = true
	}
	for p := range r.in.journals {
		finals[p] = true
	}
	for p := range r.in.sets {
		finals[p] = true
	}
	for p := range r.in.dirs {
		finals[p] = true
	}
	renamedTo := map[string]bool{}
	var created []string
	for _, o := range r.fs.opList() {
		switch o.Kind {
		case kRename:
			renamedTo[o.New] = true
			if !tempShape.MatchString(path.Base(o.Path)) {
				t.Errorf("%v: a rename from a name that is not a temporary name", o)
			}
		case kCreate, kMkdir:
			created = append(created, o.Path)
		}
	}
	for _, p := range created {
		if inTempFolder(p) {
			continue // a file of a set is written at its own name inside the temporary folder
		}
		base := path.Base(p)
		switch {
		case tempShape.MatchString(base):
			if len(base) > 15 {
				t.Errorf("temporary name %q is longer than 15 characters", base)
			}
		case r.in.journals[p] != nil, r.in.dirs[p]:
			// created at its final name: the journals and the ceremony folder
		default:
			t.Errorf("%s was created at a final name; only a journal or a ceremony folder may be", p)
		}
	}
	for p := range finals {
		if r.in.journals[p] != nil || r.in.dirs[p] {
			continue
		}
		if r.in.sets[p] == nil && path.Dir(p) != "/" && r.in.sets[path.Dir(p)] != nil {
			continue // inside a set: the folder is renamed, not the file
		}
		if !renamedTo[p] {
			t.Errorf("%s never stood at a final name by a rename", p)
		}
	}
}

func inTempFolder(p string) bool {
	for _, e := range strings.Split(path.Dir(p), "/") {
		if strings.HasPrefix(e, fsx.TempPrefix) {
			return true
		}
	}
	return false
}

// TestCutTemporaryNamesAreShortFreshAndNeverAFinalName: rule 32.
func TestCutTemporaryNamesAreShortFreshAndNeverAFinalName(t *testing.T) {
	r := runCeremony(t, realMaker, defaultOrder)
	seen := map[string]bool{}
	finalBases := map[string]bool{}
	for p := range r.in.files {
		finalBases[path.Base(p)] = true
	}
	for p := range r.in.journals {
		finalBases[path.Base(p)] = true
	}
	for p := range r.in.sets {
		finalBases[path.Base(p)] = true
	}
	n := 0
	for _, o := range r.fs.opList() {
		if o.Kind != kRename {
			continue
		}
		n++
		base := path.Base(o.Path)
		if len(base) != 15 || !tempShape.MatchString(base) {
			t.Errorf("%v: temporary name %q is not .rt- and 11 of [a-z0-9]", o, base)
		}
		if seen[base] {
			t.Errorf("temporary name %q was drawn twice in one run", base)
		}
		seen[base] = true
		if finalBases[base] {
			t.Errorf("temporary name %q equals a final name", base)
		}
		for fb := range finalBases {
			if len(fb) > 3 && regexp.MustCompile(regexp.QuoteMeta(fb)).MatchString(base) {
				t.Errorf("temporary name %q carries the final name %q", base, fb)
			}
		}
	}
	if n < 8 {
		t.Fatalf("only %d renames looked at", n)
	}
}

// TestCutControls runs the same oracle on writers that are wrong on purpose. Each must be
// caught, under the policies listed (a wrong writer may pass under a kinder policy: that is
// why there are three).
func TestCutControls(t *testing.T) {
	recordBeforeArtifacts := []string{"mkdir", "plan", "attempt", "births", "sigs", "record", "artifacts", "trust", "transcript"}
	recordBeforeTranscript := []string{"mkdir", "plan", "attempt", "births", "sigs", "artifacts", "trust", "record", "transcript"}
	recordBeforeTrustSet := []string{"mkdir", "plan", "attempt", "births", "sigs", "artifacts", "transcript", "record", "trust"}

	controls := []struct {
		name  string
		mk    func(*memFS) bundleWriter
		order []string
		// the policy kinds that must catch it
		caughtBy []string
	}{
		{"rename before the flush of the file", newWrongMaker(wrongRenameBeforeFileSync), defaultOrder, []string{"seed"}},
		{"rename and flush of the folder before the flush of the file", newWrongMaker(wrongFolderFlushBeforeFileFlush), defaultOrder, []string{"flushed", "seed"}},
		{"no flush of the folder after the rename", newWrongMaker(wrongNoFolderFlush), defaultOrder, []string{"flushed"}},
		{"every file written straight at its final name", newWrongMaker(wrongDirectFinal), defaultOrder, []string{"all"}},
		{"the attempt written straight at its final name", newWrongMaker(wrongDirectAttempt), defaultOrder, []string{"all"}},
		{"temporary name is the final name and a suffix", newWrongMaker(wrongTempIsFinalPlusSuffix), defaultOrder, []string{"all"}},
		{"the record written before the artifacts it lists", realMaker, recordBeforeArtifacts, []string{"flushed", "all"}},
		{"the record written before the transcript it lists", realMaker, recordBeforeTranscript, []string{"flushed", "all"}},
		{"the record written before the trust set it lists", realMaker, recordBeforeTrustSet, []string{"flushed", "all"}},
		{"a trust set built in place at its final name", newWrongMaker(wrongSetInPlace), defaultOrder, []string{"flushed", "all"}},
		{"a journal line written and not flushed", newWrongMaker(wrongJournalNoFlush), defaultOrder, []string{"flushed"}},
	}
	for _, c := range controls {
		t.Run(c.name, func(t *testing.T) {
			r := runCeremony(t, c.mk, c.order)
			s := sweepCuts(r)
			if len(s.Failures) == 0 {
				t.Fatalf("the oracle passes this wrong writer at all %d images: it is too weak", s.Images)
			}
			first := s.Failures[0]
			t.Logf("caught: %d of %d images broken; first at the cut after call %d (%s) under policy %v: %s",
				len(s.Failures), s.Images, first.Cut, first.After, first.Pol, first.Msgs[0])
			for _, k := range s.kinds() {
				v := s.byKind()[k]
				t.Logf("   policy %-7s first caught at the cut after call %d (%s): %s", k, v.Cut, v.After, v.Msgs[0])
			}
			for _, want := range c.caughtBy {
				if _, ok := s.byKind()[want]; !ok {
					t.Errorf("the oracle did not catch this writer under the %q policy (caught under %v)", want, s.kinds())
				}
			}
		})
	}
}

// TestCutControlsFailTheRealOrderTooWhenTheyAreTheRealWriter is a guard on the controls: the
// ones that use the real writer with another order are wrong only by the order, so the same
// real writer in the right order must pass.
func TestCutControlsAreWrongOnlyByTheirOrder(t *testing.T) {
	for _, order := range [][]string{
		{"mkdir", "plan", "attempt", "births", "sigs", "record", "artifacts", "trust", "transcript"},
		defaultOrder,
	} {
		r := runCeremony(t, realMaker, order)
		s := sweepCuts(r)
		wantBroken := !slices.Equal(order, defaultOrder)
		if (len(s.Failures) > 0) != wantBroken {
			t.Errorf("order %v: %d broken images, want broken=%v\n%s", order, len(s.Failures), wantBroken, s.table(5))
		}
	}
}

// TestCutRealWriterAlsoPassesWithOtherRandomSources: the temporary names differ from run to run
// and must not matter.
func TestCutRealWriterAlsoPassesWithOtherRandomSources(t *testing.T) {
	for seed := byte(10); seed < 14; seed++ {
		mk := func(f *memFS) bundleWriter {
			return realWriter{&fsx.Writer{FS: f, Rand: newDetRand(seed)}}
		}
		r := runCeremony(t, mk, defaultOrder)
		if s := sweepCuts(r); len(s.Failures) > 0 {
			t.Fatalf("random source %d: %s", seed, s.table(10))
		}
	}
}
