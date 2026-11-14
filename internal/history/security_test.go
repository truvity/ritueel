//go:build linux || darwin

package history

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// Bundles built by hand to find a way to a wrong "clean", each as a test. A change to a
// history that leaves the printed end as it was is the one change that nothing else protects the
// person from, so each of these asserts that the run is not clean, and says what the end line
// would have shown. The result of each is a rule of the page or a repair of a fault.

// endBefore returns the end of the history as the end line shows it.
func endBefore(t *testing.T, rep *Report) string {
	t.Helper()
	eight, _, ok := rep.End()
	if !ok {
		return ""
	}
	return eight
}

// wantNotCleanEndUnchanged fails the test unless the run is not clean while its end line is still
// the end line of the untouched history (want, the first eight characters of the end).
func wantNotCleanEndUnchanged(t *testing.T, rep *Report, want string) {
	t.Helper()
	if rep.Clean() {
		t.Error("the run is clean")
	}
	if got := endBefore(t, rep); got != want {
		t.Errorf("the end line shows %q, want the end of the untouched history, %q", got, want)
	}
}

// A planted ceremony: two small files and a trust set, in a history that has records.
func TestPlantedUnfinishedCeremonyIsNotANoticeInAHistoryWithRecords(t *testing.T) {
	plant := func(mut func(r *rec)) (*bundle, *rec, string) {
		b := newBundle(t)
		b.apply()
		b.apply()
		last := b.apply()
		u := b.unfinished(mut)
		return b, u, last.digest[:8]
	}
	t.Run("a plan with no last_record_sha256 and a list with no anchor", func(t *testing.T) {
		b, u, end := plant(func(r *rec) {
			r.plan.LastRecordSHA256 = ""
			r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes("")
			r.refresh()
		})
		rep := b.run()
		// Before: unfinished-ceremony, exit 0, and the end line of the untouched history.
		wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(u)}, {AnchorUnknown, "trust/" + u.set + "/root-list.json"}})
		wantNotCleanEndUnchanged(t, rep, end)
	})
	t.Run("a plan whose last_record_sha256 is an empty text", func(t *testing.T) {
		b, u, end := plant(func(r *rec) {
			r.rawPlan = bytes.Replace(must(r.plan.Canonical()), []byte(`"last_record_sha256":"`+r.plan.LastRecordSHA256+`"`), []byte(`"last_record_sha256":""`), 1)
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		})
		rep := b.run()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(u)}})
		wantNotCleanEndUnchanged(t, rep, end)
	})
	t.Run("a plan that names a digest that is not the end", func(t *testing.T) {
		b, u, end := plant(func(r *rec) {
			r.plan.LastRecordSHA256 = digestA
			r.refresh()
		})
		rep := b.run()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(u)}})
		wantNotCleanEndUnchanged(t, rep, end)
	})
	t.Run("a plan that names an older record", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply()
		b.apply()
		last := b.apply()
		u := b.unfinished(func(r *rec) {
			r.plan.LastRecordSHA256 = first.digest
			r.refresh()
		})
		rep := b.run()
		has(t, rep, TrustSetUnlisted, setPath(u))
		wantNotCleanEndUnchanged(t, rep, last.digest[:8])
	})
	t.Run("a plan that names the end, and a list that anchors it, is the notice", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		last := b.apply()
		u := b.unfinished()
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
		if !rep.Clean() || endBefore(t, rep) != last.digest[:8] {
			t.Errorf("Clean() = %v, end %q", rep.Clean(), endBefore(t, rep))
		}
	})
	t.Run("a genuine ceremony whose list has no anchor", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		b.apply()
		u := b.unfinished(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes("")
			r.refresh()
		})
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}, {AnchorUnknown, "trust/" + u.set + "/root-list.json"}})
		if rep.Clean() {
			t.Error("clean")
		}
	})
	t.Run("a genuine ceremony whose list anchors an older record", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply()
		b.apply()
		u := b.unfinished(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes(first.digest)
			r.refresh()
		})
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}, {AnchorUnknown, "trust/" + u.set + "/root-list.json"}})
	})
	t.Run("a history with two ends has no end to plan against", func(t *testing.T) {
		b := newBundle(t)
		a := b.apply()
		b.apply()
		b.apply(prev(a.digest)) // a fork: two ends
		u := b.unfinished()
		rep := b.run()
		has(t, rep, TrustSetUnlisted, setPath(u))
		lacks(t, rep, UnfinishedCeremony)
	})
}

// The first ceremony of an empty history has no end to name. Nothing else may be taken for it.
func TestUnfinishedFirstCeremonyOfAHistoryWithNoRecordMustNameNoEnd(t *testing.T) {
	t.Run("a plan with no end", func(t *testing.T) {
		b := newBundle(t)
		u := b.unfinished()
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
		if want := "history: 0 ceremony records"; rep.EndLine() != want {
			t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
		}
	})
	t.Run("a plan that names an end", func(t *testing.T) {
		b := newBundle(t)
		u := b.unfinished(func(r *rec) {
			r.plan.LastRecordSHA256 = digestA
			r.refresh()
		})
		rep := b.run()
		// The list has no anchor and the set has the lowest number: the one finding says it all.
		wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(u)}})
	})
	t.Run("a plan whose end is an empty text", func(t *testing.T) {
		b := newBundle(t)
		u := b.unfinished(func(r *rec) {
			r.rawPlan = bytes.Replace(must(r.plan.Canonical()), []byte(`"trust_sequence"`), []byte(`"last_record_sha256":"","trust_sequence"`), 1)
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		})
		wantFindings(t, b.run(), []wf{{TrustSetUnlisted, setPath(u)}})
	})
}

// Several open ceremonies of one set: each names the one end, and one notice names them.
func TestSeveralOpenCeremoniesOfOneSetAreOneNotice(t *testing.T) {
	b := newBundle(t)
	b.apply()
	one := b.unfinished()
	two := b.unfinished(setName(one.set), func(r *rec) {
		r.plan.TrustSequence = ptr(int64(one.n))
		r.refresh()
	})
	rep := b.run()
	wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(one)}})
	d := detail(rep, UnfinishedCeremony, setPath(one))
	if !strings.Contains(d, one.folder) || !strings.Contains(d, two.folder) {
		t.Errorf("the detail %q does not name both ceremonies", d)
	}
	// If one of them names another end, the set is still the other's, and the anchor is the end.
	b2 := newBundle(t)
	b2.apply()
	good := b2.unfinished()
	b2.unfinished(setName(good.set), func(r *rec) {
		r.plan.TrustSequence = ptr(int64(good.n))
		r.plan.LastRecordSHA256 = digestA
		r.refresh()
	})
	wantFindings(t, b2.run(), []wf{{UnfinishedCeremony, setPath(good)}})
}

// The root list of a set that an open ceremony wrote anchors the end that its plan names.
func TestRootListOfAnUnfinishedSetAnchorsTheEndOfItsPlan(t *testing.T) {
	cases := map[string]string{
		"the anchor of its plan": "plan",
		"no anchor":              "",
		"an older record":        "older",
		"a digest that is none":  digestB,
	}
	for name, which := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			first := b.apply()
			b.apply()
			u := b.unfinished(func(r *rec) {
				anchor := which
				switch which {
				case "plan":
					anchor = r.plan.LastRecordSHA256
				case "older":
					anchor = first.digest
				}
				r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes(anchor)
				r.refresh()
			})
			rep := b.run()
			if which == "plan" {
				wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
				return
			}
			has(t, rep, UnfinishedCeremony, setPath(u))
			has(t, rep, AnchorUnknown, "trust/"+u.set+"/root-list.json")
		})
	}
}

// An empty text is not "absent". The page: a digest is 64 hexadecimal characters, a time has its
// form, and the first record is the only one with no predecessor.
func TestRecordWithAnEmptyTextForAnOptionalMemberIsInvalid(t *testing.T) {
	members := map[string]string{
		"prev_record_sha256": `"prev_record_sha256":""`,
		"started_at":         `"started_at":""`,
		"finished_at":        `"finished_at":""`,
		"ran_on":             `"ran_on":""`,
		"root_reason":        `"root_reason":""`,
		"confirmation.at":    `"confirmation":{"at":"","by":"typed"}`,
		"advisory_review.at": `"advisory_review":{"at":"","note":"x"}`,
	}
	for name, member := range members {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet, recordAs(func(canon []byte) []byte {
				return bytes.Replace(canon, []byte(`"transcript_sha256"`), []byte(member+`,"transcript_sha256"`), 1)
			}))
			rep := b.run()
			has(t, rep, RecordInvalid, recordPath(r))
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}

// Before, a record with "prev_record_sha256":"" was read as the first record: a one-record history
// was clean, and its end line was the line of the history without the member.
func TestFirstRecordWithAnEmptyPredecessorIsNotTheFirstRecord(t *testing.T) {
	b := newBundle(t)
	r := b.apply(noSet, recordAs(func(c []byte) []byte {
		return bytes.Replace(c, []byte(`"transcript_sha256"`), []byte(`"prev_record_sha256":"","transcript_sha256"`), 1)
	}))
	rep := b.run()
	wantFindings(t, rep, []wf{{RecordInvalid, recordPath(r)}}, RecordOffChain)
	if rep.Clean() {
		t.Error("clean")
	}
}

// A plan with an empty text for an optional member is unreadable; so is an attempt. A ceremony
// whose files do not read does not link to its trust set.
func TestPlanOrAttemptWithAnEmptyTextDoesNotLinkAnOpenCeremony(t *testing.T) {
	for _, member := range []string{"made_at", "ceremony_time", "root_reason"} {
		t.Run("plan "+member, func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			u := b.unfinished(func(r *rec) {
				r.rawPlan = bytes.Replace(must(r.plan.Canonical()), []byte(`"trust_sequence"`), []byte(`"`+member+`":"","trust_sequence"`), 1)
				r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
			})
			wantFindings(t, b.run(), []wf{{TrustSetUnlisted, setPath(u)}})
		})
	}
	for _, member := range []string{"root", "started_at"} {
		t.Run("attempt "+member, func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			u := b.unfinished(func(r *rec) {
				r.rawAttempt = bytes.Replace(must(r.attempt.Canonical()), []byte(`"version"`), []byte(`"`+member+`":"","version"`), 1)
			})
			wantFindings(t, b.run(), []wf{{TrustSetUnlisted, setPath(u)}})
		})
	}
}

// A root list rolled back to the list of the set before: the newest record is rewritten to list it,
// so the record before it and the chain are as they were.
func TestRootListRolledBackToTheListBeforeIsNotClean(t *testing.T) {
	b := newBundle(t)
	b.apply()
	two := b.apply()
	three := b.apply(func(r *rec) {
		// The list of the set before, as it stands in the second set: anchored on the first record.
		r.artifacts["trust/"+r.set+"/root-list.json"] = two.artifacts["trust/"+two.set+"/root-list.json"]
		r.refresh()
	})
	rep := b.run()
	// Before: exit 0, and an end line that is the third record's digest, changed from the
	// untouched history's, which was the only sign.
	wantFindings(t, rep, []wf{{AnchorUnknown, "trust/" + three.set + "/root-list.json"}})
	if rep.Clean() {
		t.Error("clean")
	}
}

func TestAnchorRulesOfTheRecordBeforeTheCeremony(t *testing.T) {
	t.Run("the first list has an anchor", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes(digestA)
			r.refresh()
		})
		wantFindings(t, b.run(), []wf{{AnchorUnknown, "trust/" + r.set + "/root-list.json"}})
	})
	t.Run("a later list has none", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		r := b.apply(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes("")
			r.refresh()
		})
		wantFindings(t, b.run(), []wf{{AnchorUnknown, "trust/" + r.set + "/root-list.json"}})
	})
	t.Run("two records list one set, and they do not follow the same record", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply()
		b.apply()
		b.apply(func(r *rec) {
			// The third record lists a file of the first set too.
			p := "trust/" + first.set + "/keys.txt"
			r.artifacts[p] = first.artifacts[p]
			r.refresh()
		})
		rep := b.run()
		has(t, rep, AnchorUnknown, "trust/"+first.set+"/root-list.json")
		if rep.Clean() {
			t.Error("clean")
		}
	})
	t.Run("the set is listed by a record that is not on the chain", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		r := b.apply(prev(digestA)) // names a record that is not there: chain-broken
		rep := b.run()
		has(t, rep, ChainBroken, folderPath(r))
		has(t, rep, AnchorUnknown, "trust/"+r.set+"/root-list.json")
	})
}

// One path listed twice by one record, once with its digest and once with another: the file does
// not pass because one of its two listings does. Before, the key that told repeats apart was the
// path alone, and the history was clean.
func TestPathListedTwiceWithTwoDigestsFailsWhicheverComesFirst(t *testing.T) {
	for _, order := range []string{"right first", "wrong first"} {
		t.Run(order, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(func(r *rec) {
				path := "trust/" + r.set + "/keys.txt"
				right := files.FileRef{Path: path, SHA256: files.Digest(r.artifacts[path])}
				wrong := files.FileRef{Path: path, SHA256: digestA}
				list := []files.FileRef{right, wrong}
				if order == "wrong first" {
					list = []files.FileRef{wrong, right}
				}
				others := []files.FileRef{{Path: "trust/" + r.set + "/root-list.json", SHA256: files.Digest(r.artifacts["trust/"+r.set+"/root-list.json"])}}
				r.record.Artifacts = slices.Concat(others, list)
			})
			rep := b.run()
			wantFindings(t, rep, []wf{{FileDigest, "trust/" + r.set + "/keys.txt"}})
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}

// The same path listed as two kinds of file, with two digests: the transcript of the ceremony that
// a record also lists as an artifact, and the wanted copy that it lists as an artifact.
func TestPathListedAsTwoKindsOfFileWithTwoDigestsFailsWhicheverIsWrong(t *testing.T) {
	t.Run("the artifact listing is wrong", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet, func(r *rec) {
			r.record.Artifacts = []files.FileRef{{Path: "history/" + r.folder + "/transcript.txt", SHA256: digestA}}
		})
		wantFindings(t, b.run(), []wf{{FileDigest, "history/" + r.folder + "/transcript.txt"}})
	})
	t.Run("the transcript listing is wrong", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet, func(r *rec) {
			r.record.TranscriptSHA256 = digestA
			r.record.Artifacts = []files.FileRef{{Path: "history/" + r.folder + "/transcript.txt", SHA256: files.Digest(r.transcript)}}
		})
		wantFindings(t, b.run(), []wf{{TranscriptDigest, "history/" + r.folder + "/transcript.txt"}})
	})
	t.Run("a wanted copy listed as an artifact with another digest", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet, func(r *rec) {
			r.record.Artifacts = []files.FileRef{{Path: "history/" + r.folder + "/wanted/ritueel.yaml", SHA256: digestA}}
		})
		wantFindings(t, b.run(), []wf{{FileDigest, "history/" + r.folder + "/wanted/ritueel.yaml"}})
	})
	t.Run("a path listed many times, with a wrong digest among them", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet, func(r *rec) {
			r.artifacts["a.txt"] = []byte("x")
			r.refresh()
			right := r.record.Artifacts[0]
			list := make([]files.FileRef, 0, 500)
			for i := 0; i < 499; i++ {
				list = append(list, right)
			}
			wrong := right
			wrong.SHA256 = digestB
			r.record.Artifacts = slices.Concat(list, []files.FileRef{wrong})
		})
		rep, log := b.runSpied()
		has(t, rep, FileDigest, "a.txt")
		if n := log.reads["a.txt"]; n != 1 {
			t.Errorf("a.txt was read %d times, want once", n)
		}
		_ = r
	})
}

// Cases that the printed end protects, which the pages set: the check says what it can, and the
// end line the person keeps is the rest. These hold that the answer is the one the pages give, and
// that the repairs did not change it.
func TestRemovedNewestRecordIsWhatTheEndLineProtects(t *testing.T) {
	build := func() (*bundle, [3]*rec) {
		b := newBundle(t)
		var r [3]*rec
		for i := range r {
			r[i] = b.apply()
		}
		return b, r
	}
	t.Run("the newest folder and its set removed: clean, and the end is the one before", func(t *testing.T) {
		b, r := build()
		b.remove("history/" + r[2].folder)
		b.remove("trust/" + r[2].set)
		rep := b.run()
		wantFindings(t, rep, nil)
		if want := "history: 2 ceremony records, end " + r[1].digest[:8]; rep.EndLine() != want {
			t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
		}
	})
	t.Run("the two newest folders and their sets removed", func(t *testing.T) {
		b, r := build()
		for _, x := range r[1:] {
			b.remove("history/" + x.folder)
			b.remove("trust/" + x.set)
		}
		rep := b.run()
		wantFindings(t, rep, nil)
		if want := "history: 1 ceremony records, end " + r[0].digest[:8]; rep.EndLine() != want {
			t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
		}
	})
	t.Run("the newest folder removed and its set left", func(t *testing.T) {
		b, r := build()
		b.remove("history/" + r[2].folder)
		wantFindings(t, b.run(), []wf{{TrustSetUnlisted, setPath(r[2])}})
	})
	t.Run("record.json of the newest removed alone", func(t *testing.T) {
		b, r := build()
		b.remove("history/" + r[2].folder + "/record.json")
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(r[2])}})
		if !rep.Clean() {
			t.Error("a notice makes the history unclean")
		}
		if want := "history: 2 ceremony records, end " + r[1].digest[:8]; rep.EndLine() != want {
			t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
		}
	})
	t.Run("record.json and attempt.json of the newest removed", func(t *testing.T) {
		b, r := build()
		b.remove("history/" + r[2].folder + "/record.json")
		b.remove("history/" + r[2].folder + "/attempt.json")
		wantFindings(t, b.run(), []wf{{TrustSetUnlisted, setPath(r[2])}})
	})
	t.Run("record.json of a record in the middle removed alone: the plan is stale", func(t *testing.T) {
		b, r := build()
		b.remove("history/" + r[1].folder + "/record.json")
		rep := b.run()
		// Its plan names the first record, and the end is the third now: the attempt does not
		// belong to this history, and the set is unlisted (it was a notice before).
		has(t, rep, TrustSetUnlisted, setPath(r[1]))
		has(t, rep, ChainBroken, folderPath(r[2]))
		lacks(t, rep, UnfinishedCeremony)
	})
	t.Run("a capital R in the name of the newest record.json", func(t *testing.T) {
		b, r := build()
		b.put("history/"+r[2].folder+"/Record.json", b.get("history/"+r[2].folder+"/record.json"))
		b.remove("history/" + r[2].folder + "/record.json")
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(r[2])}, {UnexpectedFile, "history/" + r[2].folder + "/Record.json"}})
		if !rep.Clean() {
			t.Error("two notices make the history unclean")
		}
	})
	t.Run("a hidden temporary name for the newest folder", func(t *testing.T) {
		b, r := build()
		if err := renameDir(b, "history/"+r[2].folder, "history/.RT-"+"c3"); err != nil {
			t.Fatal(err)
		}
		b.remove("trust/" + r[2].set)
		rep := b.run()
		wantFindings(t, rep, []wf{{UnexpectedFile, "history/.RT-c3"}})
		if !rep.Clean() {
			t.Error("a notice makes the history unclean")
		}
	})
}

// What is not part of the bundle is not read: another folder that holds the history of a copy, or
// a folder whose name is a case twin of history.
func TestFoldersBesideTheHistoryAreNotRead(t *testing.T) {
	b, _ := threeRecords(t)
	for _, name := range []string{"history2", "History", "history.bak", "trust.old"} {
		b.put(name+"/20269999T000000Z-apply/record.json", []byte("junk"))
	}
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	for p := range log.reads {
		if strings.HasPrefix(p, "history2") || strings.HasPrefix(p, "History") || strings.HasPrefix(p, "history.bak") || strings.HasPrefix(p, "trust.old") {
			t.Errorf("the check read %s", p)
		}
	}
}

func TestJunkFolderInTheHistoryIsAFaultAndTrustThatIsGoneMakesTheListedFilesMissing(t *testing.T) {
	t.Run("a folder with a junk record", func(t *testing.T) {
		b, _ := threeRecords(t)
		b.put("history/20269999T000000Z-apply/record.json", []byte("junk"))
		rep := b.run()
		has(t, rep, RecordInvalid, "history/20269999T000000Z-apply/record.json")
		if rep.Clean() {
			t.Error("clean")
		}
	})
	t.Run("trust removed", func(t *testing.T) {
		b, r := threeRecords(t)
		b.remove("trust")
		rep := b.run()
		for _, x := range r {
			has(t, rep, FileMissing, "trust/"+x.set+"/keys.txt")
			has(t, rep, FileMissing, "trust/"+x.set+"/root-list.json")
		}
	})
}

func TestHistoryOrTrustThatIsALinkIsNoBundleToCheck(t *testing.T) {
	for _, name := range []string{"history", "trust"} {
		t.Run(name, func(t *testing.T) {
			b, _ := threeRecords(t)
			if err := renameDir(b, name, name+"-moved"); err != nil {
				t.Fatal(err)
			}
			b.symlink(name+"-moved", name)
			rep, err := runDirErr(t, b.dir)
			if err == nil || rep != nil {
				t.Fatalf("Check = %v, %v; want an error and no report", rep, err)
			}
			if !printable(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII: %q", err)
			}
		})
	}
}

// A known name of a ceremony folder that is not a file: it is said only when no record lists the
// path, because a listed path has its own finding.
func TestKnownNameThatIsNotAFileIsOneFindingWhenARecordListsIt(t *testing.T) {
	t.Run("a transcript that the record lists", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet)
		p := "history/" + r.folder + "/transcript.txt"
		b.remove(p)
		b.fifo(p)
		wantFindings(t, b.run(), []wf{{FileDigest, p}})
	})
	t.Run("a journal that no record lists", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet)
		p := "history/" + r.folder + "/births.jsonl"
		b.fifo(p)
		rep := b.run()
		// A FIFO where a journal belongs is not a name that ritueel writes: it fails.
		wantFindings(t, rep, []wf{{UnexpectedName, p}})
		if rep.Clean() {
			t.Error("clean")
		}
	})
	t.Run("a transcript whose record cannot be read", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet)
		p := "history/" + r.folder + "/transcript.txt"
		b.remove(p)
		b.fifo(p)
		rewrite(b, r, func(c []byte) []byte { return append(c, []byte("junk")...) })
		// The record lists nothing now, so the notice is the only sign of the transcript.
		has(t, b.run(), UnexpectedFile, p)
	})
}

// Each file that is listed is read once; the root list is parsed from the read that gave its
// digest, and the attempt and the plan of a ceremony with no record are read once for their content.
func TestEveryFileOfACleanBundleIsReadOnceAndTheRootListToo(t *testing.T) {
	b, _ := threeRecords(t)
	_, log := b.runSpied()
	// Six files for each of the three records: the record, the transcript, the plan, the copy of
	// the wanted file, and the two files of the trust set.
	if len(log.reads) != 6*3 {
		t.Errorf("%d different files were read, want %d", len(log.reads), 6*3)
	}
	for p, n := range log.reads {
		if n != 1 {
			t.Errorf("%s was read %d times", p, n)
		}
	}
	b2 := newBundle(t)
	b2.apply()
	u := b2.unfinished()
	_, log2 := b2.runSpied()
	for _, f := range []string{"attempt.json", "plan.json"} {
		if n := log2.reads["history/"+u.folder+"/"+f]; n != 1 {
			t.Errorf("%s of the open ceremony was read %d times", f, n)
		}
	}
}
