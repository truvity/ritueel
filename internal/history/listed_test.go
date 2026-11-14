//go:build linux || darwin

package history

import (
	"strings"
	"testing"
)

// The files that a record lists: the transcript, the copies of the wanted files, the plan, the
// artifacts, and for a closing record the attempt of the ceremony it closes.

func TestListedFilesThatChangedOrAreGone(t *testing.T) {
	type tamper func(b *bundle, r *rec)
	cases := []struct {
		name string
		do   tamper
		code Code
		path func(r *rec) string
	}{
		{"transcript changed", func(b *bundle, r *rec) { b.put("history/"+r.folder+"/transcript.txt", []byte("x")) }, TranscriptDigest,
			func(r *rec) string { return "history/" + r.folder + "/transcript.txt" }},
		{"transcript removed", func(b *bundle, r *rec) { b.remove("history/" + r.folder + "/transcript.txt") }, FileMissing,
			func(r *rec) string { return "history/" + r.folder + "/transcript.txt" }},
		{"wanted copy changed", func(b *bundle, r *rec) { b.put("history/"+r.folder+"/wanted/ritueel.yaml", []byte("x")) }, FileDigest,
			func(r *rec) string { return "history/" + r.folder + "/wanted/ritueel.yaml" }},
		{"wanted copy removed", func(b *bundle, r *rec) { b.remove("history/" + r.folder + "/wanted/ritueel.yaml") }, FileMissing,
			func(r *rec) string { return "history/" + r.folder + "/wanted/ritueel.yaml" }},
		{"wanted folder removed", func(b *bundle, r *rec) { b.remove("history/" + r.folder + "/wanted") }, FileMissing,
			func(r *rec) string { return "history/" + r.folder + "/wanted/ritueel.yaml" }},
		{"plan changed", func(b *bundle, r *rec) {
			b.put("history/"+r.folder+"/plan.json", append(b.get("history/"+r.folder+"/plan.json"), ' '))
		}, FileDigest,
			func(r *rec) string { return "history/" + r.folder + "/plan.json" }},
		{"plan removed", func(b *bundle, r *rec) { b.remove("history/" + r.folder + "/plan.json") }, FileMissing,
			func(r *rec) string { return "history/" + r.folder + "/plan.json" }},
		{"artifact changed", func(b *bundle, r *rec) { b.put("trust/"+r.set+"/keys.txt", []byte("x")) }, FileDigest,
			func(r *rec) string { return "trust/" + r.set + "/keys.txt" }},
		{"artifact removed", func(b *bundle, r *rec) { b.remove("trust/" + r.set + "/keys.txt") }, FileMissing,
			func(r *rec) string { return "trust/" + r.set + "/keys.txt" }},
		{"artifact folder removed", func(b *bundle, r *rec) { b.remove("trust/" + r.set) }, FileMissing,
			func(r *rec) string { return "trust/" + r.set + "/keys.txt" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, r := threeRecords(t)
			c.do(b, r[1])
			rep := b.run()
			has(t, rep, c.code, c.path(r[1]))
			if rep.Clean() {
				t.Error("clean")
			}
			// Another record is not touched by it.
			for _, f := range rep.Findings {
				if strings.Contains(f.Path, r[0].folder) || strings.Contains(f.Path, r[2].folder) || strings.Contains(f.Path, r[0].set) || strings.Contains(f.Path, r[2].set) {
					if f.Code != AnchorUnknown { // a removed root list is not what this test is about
						t.Errorf("a finding about another record: %s", f.Line())
					}
				}
			}
			checkForm(t, rep)
		})
	}
}

// A trust set that lost its folder: every file the record lists there is missing, and the set is
// not a trust set any more, so there is nothing else to say about it.
func TestListedTrustSetThatLostItsFolder(t *testing.T) {
	b, r := threeRecords(t)
	b.remove("trust/" + r[2].set)
	rep := b.run()
	has(t, rep, FileMissing, "trust/"+r[2].set+"/keys.txt")
	has(t, rep, FileMissing, "trust/"+r[2].set+"/root-list.json")
	lacks(t, rep, TrustSetUnlisted)
	lacks(t, rep, AnchorUnknown)
}

func TestPlanOfARecordIsCheckedAgainstItsDigest(t *testing.T) {
	b, r := threeRecords(t)
	// A plan that was changed and written in canonical form again is still not the plan of the record.
	plan := r[0].plan
	plan.Touches = 5
	b.put("history/"+r[0].folder+"/plan.json", must(plan.Canonical()))
	rep := b.run()
	wantFindings(t, rep, []wf{{FileDigest, "history/" + r[0].folder + "/plan.json"}})
}

func TestAttemptOfAClosedCeremonyIsCheckedAgainstTheClosingRecord(t *testing.T) {
	build := func(t *testing.T) (*bundle, *rec, *rec) {
		b := newBundle(t)
		b.apply()
		stopped := b.unfinished()
		closing := b.closing(stopped, func(r *rec) {
			for p, data := range stopped.artifacts {
				r.artifacts[p] = data
			}
			r.refresh()
		})
		return b, stopped, closing
	}
	t.Run("whole", func(t *testing.T) {
		b, _, _ := build(t)
		wantFindings(t, b.run(), nil)
	})
	t.Run("changed", func(t *testing.T) {
		b, stopped, _ := build(t)
		b.put("history/"+stopped.folder+"/attempt.json", append(b.get("history/"+stopped.folder+"/attempt.json"), '\n'))
		rep := b.run()
		has(t, rep, FileDigest, "history/"+stopped.folder+"/attempt.json")
		if rep.Clean() {
			t.Error("clean")
		}
	})
	t.Run("removed", func(t *testing.T) {
		b, stopped, _ := build(t)
		b.remove("history/" + stopped.folder + "/attempt.json")
		rep := b.run()
		has(t, rep, FileMissing, "history/"+stopped.folder+"/attempt.json")
	})
	t.Run("the whole folder of the closed ceremony removed", func(t *testing.T) {
		b, stopped, _ := build(t)
		b.remove("history/" + stopped.folder)
		rep := b.run()
		has(t, rep, FileMissing, "history/"+stopped.folder+"/attempt.json")
	})
	t.Run("a closing record that names another digest", func(t *testing.T) {
		b := newBundle(t)
		stopped := b.unfinished()
		b.closing(stopped, func(r *rec) {
			r.record.Closes.AttemptSHA256 = digestA
			for p, data := range stopped.artifacts {
				r.artifacts[p] = data
			}
			r.refresh()
			r.record.Closes.AttemptSHA256 = digestA
		})
		rep := b.run()
		has(t, rep, FileDigest, "history/"+stopped.folder+"/attempt.json")
	})
}

// A wanted file in want/ is written by a person, so it may have changed since: it is not read.
func TestWantedFileOfThePersonIsNotChecked(t *testing.T) {
	b := newBundle(t)
	b.apply()
	b.put("want/cards/root-a.yaml", []byte("changed after the ceremony\n"))
	b.put("want/ritueel.yaml", []byte("also changed\n"))
	b.apply()
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	for p := range log.reads {
		if strings.HasPrefix(p, "want/") {
			t.Errorf("the check read %s", p)
		}
	}
	for p := range log.lists {
		if strings.HasPrefix(p, "want") {
			t.Errorf("the check listed %s", p)
		}
	}
}

func TestListedFileThatIsEmptyHasTheDigestOfNothing(t *testing.T) {
	b := newBundle(t)
	b.apply(func(r *rec) {
		r.artifacts["a/empty.txt"] = []byte{}
		r.refresh()
	})
	wantFindings(t, b.run(), nil)
	b.put("a/empty.txt", []byte("x"))
	has(t, b.run(), FileDigest, "a/empty.txt")
}

func TestArtifactOutsideTheTrustSetIsCheckedToo(t *testing.T) {
	b := newBundle(t)
	b.apply(func(r *rec) {
		r.artifacts["requests/alice/answer.result.json"] = []byte(`{"outcome":"issued"}`)
		r.refresh()
	})
	wantFindings(t, b.run(), nil)
	b.put("requests/alice/answer.result.json", []byte(`{"outcome":"refused"}`))
	has(t, b.run(), FileDigest, "requests/alice/answer.result.json")
	b.remove("requests/alice/answer.result.json")
	has(t, b.run(), FileMissing, "requests/alice/answer.result.json")
}

func TestRecordThatNamesTheDigestOfAnotherFileIsFoundOnEachFile(t *testing.T) {
	// Two records list the same artifact with two digests: at most one is right.
	b := newBundle(t)
	b.apply(func(r *rec) {
		r.artifacts["shared.txt"] = []byte("one")
		r.refresh()
	})
	b.apply(func(r *rec) {
		r.artifacts["shared.txt"] = []byte("two")
		r.refresh()
	})
	rep := b.run()
	// The file holds "two": the first record's digest fails.
	wantFindings(t, rep, []wf{{FileDigest, "shared.txt"}})
	if d := detail(rep, FileDigest, "shared.txt"); !strings.Contains(d, b.recs[0].folder) {
		t.Errorf("the detail %q does not name the record that lists the file with the wrong digest, %s", d, b.recs[0].folder)
	}
}

func TestEveryListedFileOfOneKindIsReportedOnceForItsPath(t *testing.T) {
	b := newBundle(t)
	b.apply(func(r *rec) {
		for i := 0; i < 5; i++ {
			r.artifacts[strings.Repeat("d/", 1)+"f"+string(rune('a'+i))] = []byte{byte(i)}
		}
		r.refresh()
	})
	for i := 0; i < 5; i++ {
		b.remove("d/f" + string(rune('a'+i)))
	}
	rep := b.run()
	var missing []string
	for _, f := range rep.Findings {
		if f.Code == FileMissing && strings.HasPrefix(f.Path, "d/") {
			missing = append(missing, f.Path)
		}
	}
	if len(missing) != 5 {
		t.Errorf("file-missing for %v, want five files", missing)
	}
}

func TestRecordFieldsOfTheClosingRecordAreUsed(t *testing.T) {
	// The attempt a closing record names is in the folder of the ceremony it names, not in its own.
	b := newBundle(t)
	stopped := b.unfinished()
	closing := b.closing(stopped, func(r *rec) {
		for p, data := range stopped.artifacts {
			r.artifacts[p] = data
		}
		r.refresh()
	})
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	if log.reads["history/"+stopped.folder+"/attempt.json"] == 0 {
		t.Error("the attempt of the closed ceremony was not read")
	}
	if log.reads["history/"+closing.folder+"/attempt.json"] != 0 {
		t.Error("an attempt in the folder of the closing record was read")
	}
}
