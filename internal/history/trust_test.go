//go:build linux || darwin

package history

import (
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/testrepo"
)

// Trust sets: the ones no record lists, an unfinished ceremony, and the anchor of a root list.

func TestTrustSetThatNoRecordListsIsUnlisted(t *testing.T) {
	b := newBundle(t)
	b.apply()
	b.mkdir("trust/9-3fa9c1d2")
	b.put("trust/9-3fa9c1d2/root-list.json", rootListBytes(b.end))
	rep := b.run()
	wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/9-3fa9c1d2"}})
	wantReasons(t, rep, []Code{TrustSetUnlisted}, nil)
}

func TestTrustSetWithAnyNameThatNoRecordListsIsUnlisted(t *testing.T) {
	for _, name := range []string{"x", "abc-def", "007-aaaa", "1", "-1-a", "99999999999999999999-a", "3fa9c1d2"} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply(noSet)
			b.mkdir("trust/" + name)
			wantFindings(t, b.run(), []wf{{TrustSetUnlisted, "trust/" + name}})
		})
	}
}

func TestEntryOfTrustThatIsAFileIsNotATrustSet(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet)
	b.put("trust/README", []byte("hello\n"))
	rep := b.run()
	wantFindings(t, rep, []wf{{UnexpectedFile, "trust/README"}})
	wantReasons(t, rep, nil, []Code{UnexpectedFile})
}

func TestTrustSetIsListedByAnyFileOfItsFolder(t *testing.T) {
	b := newBundle(t)
	b.apply(func(r *rec) {
		// The record lists only one of the two files of its set.
		delete(r.artifacts, "trust/"+r.set+"/keys.txt")
		r.refresh()
	})
	wantFindings(t, b.run(), nil)
}

func TestUnfinishedCeremonyIsANoticeAndTheEndIsStillPrinted(t *testing.T) {
	b := newBundle(t)
	a := b.apply()
	u := b.unfinished()
	rep := b.run()
	wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
	wantReasons(t, rep, nil, []Code{UnfinishedCeremony})
	if !rep.Clean() {
		t.Error("a notice makes the history unclean")
	}
	if want := "history: 1 ceremony records, end " + a.digest[:8]; rep.EndLine() != want {
		t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
	}
	if len(rep.Failing()) != 0 || len(rep.Notices()) != 1 {
		t.Errorf("Failing() = %v, Notices() = %v", rep.Failing(), rep.Notices())
	}
	if d := detail(rep, UnfinishedCeremony, setPath(u)); !strings.Contains(d, u.folder) {
		t.Errorf("the detail %q does not name the ceremony %s", d, u.folder)
	}
}

func TestUnfinishedFirstCeremonyMayLackAnAnchor(t *testing.T) {
	b := newBundle(t)
	u := b.unfinished()
	rep := b.run()
	wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
	if rep.Records != 0 {
		t.Errorf("Records = %d, want 0", rep.Records)
	}
	if want := "history: 0 ceremony records"; rep.EndLine() != want {
		t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
	}
}

// What links an unfinished ceremony to its trust set is the attempt, its plan and the plan's
// trust_sequence. Break any link and the set is unlisted (record 0006, rule 34).
func TestUnfinishedCeremonyThatDoesNotLinkLeavesTheSetUnlisted(t *testing.T) {
	cases := map[string]func(r *rec){
		"the plan does not have the digest of the attempt": func(r *rec) {
			r.plan.Touches = 9 // the attempt keeps the digest of the plan as it was
		},
		"another trust sequence": func(r *rec) {
			r.plan.TrustSequence = ptr(int64(77))
			r.refresh()
		},
		"the sequence one too low": func(r *rec) {
			r.plan.TrustSequence = ptr(int64(r.n - 1))
			r.refresh()
		},
		"a plan of version 2": func(r *rec) {
			r.rawPlan = []byte(`{"version":2,"x":{}}`)
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		},
		"an attempt that cannot be read": func(r *rec) { r.rawAttempt = []byte("not json") },
		"an attempt of version 2":        func(r *rec) { r.rawAttempt = []byte(`{"version":2}`) },
		"an attempt with no plan digest": func(r *rec) {
			r.rawAttempt = []byte(`{"ceremony":"` + r.folder + `","version":1}`)
		},
		"a plan that cannot be read": func(r *rec) {
			r.rawPlan = []byte("not json")
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		},
		"a plan with no trust sequence": func(r *rec) {
			r.rawPlan = []byte(`{"ceremony":"` + r.folder + `","command":"apply","version":1}`)
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		},
		"a plan with no command": func(r *rec) {
			r.rawPlan = []byte(`{"ceremony":"` + r.folder + `","trust_sequence":2,"version":1}`)
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		},
		"a plan that is missing": func(r *rec) { r.noPlan = true },
		"an attempt that is missing": func(r *rec) {
			r.noAttempt = true
		},
		"an attempt for another plan": func(r *rec) { r.attempt.PlanSHA256 = digestA },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			u := b.unfinished(f)
			rep := b.run()
			wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(u)}})
			wantReasons(t, rep, []Code{TrustSetUnlisted}, nil)
		})
	}
}

// The attempt of a ceremony that a closing record names is resolved; the trust set it left stays
// unlisted until a closing record lists its files, and is listed like any other after.
func TestTrustSetOfAClosedCeremonyIsUnlistedUntilTheClosingRecordListsIt(t *testing.T) {
	t.Run("the closing record lists nothing", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		stopped := b.unfinished()
		b.closing(stopped)
		rep := b.run()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(stopped)}})
		wantReasons(t, rep, []Code{TrustSetUnlisted}, nil)
	})
	t.Run("the closing record lists the files of the set", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		stopped := b.unfinished()
		b.closing(stopped, func(r *rec) {
			for p, data := range stopped.artifacts {
				r.artifacts[p] = data
			}
			r.refresh()
		})
		rep := b.run()
		wantFindings(t, rep, nil)
		wantReasons(t, rep, nil, nil)
	})
	t.Run("the closing record lists one file of the set", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		stopped := b.unfinished()
		b.closing(stopped, func(r *rec) {
			r.artifacts["trust/"+stopped.set+"/keys.txt"] = stopped.artifacts["trust/"+stopped.set+"/keys.txt"]
			r.refresh()
		})
		// Any file of the set that a record lists lists the set: it is not unlisted and not unfinished.
		rep := b.run()
		lacks(t, rep, TrustSetUnlisted)
		lacks(t, rep, UnfinishedCeremony)
	})
	t.Run("a closing record for another ceremony does not resolve this one", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		stopped := b.unfinished()
		other := b.unfinished()
		b.closing(other)
		rep := b.run()
		// Both sets stay unlisted. The ceremony that was closed is resolved and its set is not
		// listed (above). The other is still open, but its plan names the end before the closing
		// record, and the closing record is the end now, so it no longer belongs to the history.
		wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(stopped)}, {TrustSetUnlisted, setPath(other)}}, AnchorUnknown)
	})
}

func TestNoticeAndFatalFindingTogether(t *testing.T) {
	b := newBundle(t)
	b.apply()
	u := b.unfinished()
	b.mkdir("trust/9-3fa9c1d2") // a set nobody lists
	b.put("history/"+u.folder+"/stray.txt", []byte("x"))
	rep := b.run()
	wantFindings(t, rep, []wf{
		{TrustSetUnlisted, "trust/9-3fa9c1d2"},
		{UnfinishedCeremony, setPath(u)},
		{UnexpectedFile, "history/" + u.folder + "/stray.txt"},
	})
	// reasons holds the failing code only, warnings the two notices, in the order of the codes.
	wantReasons(t, rep, []Code{TrustSetUnlisted}, []Code{UnfinishedCeremony, UnexpectedFile})
	if rep.Clean() {
		t.Error("clean")
	}
}

// Anchors: the last_record_sha256 of a root list is the digest of a record on the chain.

// The anchor of a root list is the record before the ceremony that wrote the set: the
// prev_record_sha256 of the record that lists it. A record of the chain that is not that one is
// not enough (it was, before the rule was tightened: a list rolled back to an older list passed).
func TestRootListAnchorsToTheRecordBeforeTheCeremonyThatWroteTheSet(t *testing.T) {
	b := newBundle(t)
	b.apply()
	b.apply()
	b.apply()
	wantFindings(t, b.run(), nil) // the list of the third set anchors the second record

	// The third set with a list that anchors the first record. That is a record of the chain, and
	// the third record lists the list as it is, as an attacker who rewrote it would.
	b2 := newBundle(t)
	first := b2.apply()
	b2.apply()
	third := b2.apply(func(r *rec) {
		r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes(first.digest)
		r.refresh()
	})
	rep := b2.run()
	wantFindings(t, rep, []wf{{AnchorUnknown, "trust/" + third.set + "/root-list.json"}})
	// The end line would have been the one of an untouched history, three records and the digest
	// of the third, with no notice: the list was the only thing that changed.
	if eight, count, ok := rep.End(); !ok || count != 3 || eight != third.digest[:8] || rep.Clean() {
		t.Errorf("End() = %q, %d, %v; Clean() = %v", eight, count, ok, rep.Clean())
	}
}

func rootListAs(last string, bytesOf func(string) []byte) func(*rec) {
	return func(r *rec) {
		r.artifacts["trust/"+r.set+"/root-list.json"] = bytesOf(last)
		r.refresh()
	}
}

func TestRootListThatDoesNotAnchorToTheChain(t *testing.T) {
	enc := rootListBytes
	cases := []struct {
		name string
		list func(first *rec) []byte
	}{
		{"a digest that is no record", func(*rec) []byte { return enc(digestB) }},
		{"a digest in capitals", func(f *rec) []byte { return enc(strings.ToUpper(f.digest)) }},
		{"a digest that is too short", func(f *rec) []byte { return enc(f.digest[:63]) }},
		{"a text that is no digest", func(*rec) []byte { return []byte(`{"last_record_sha256":"hello","version":1}`) }},
		{"a number for the digest", func(*rec) []byte { return []byte(`{"last_record_sha256":5,"version":1}`) }},
		{"null for the digest", func(*rec) []byte { return []byte(`{"last_record_sha256":null,"version":1}`) }},
		{"no anchor in a list that is not the first", func(*rec) []byte { return []byte(`{"version":1}`) }},
		{"an empty object", func(*rec) []byte { return []byte(`{}`) }},
		{"a list that is cut short", func(f *rec) []byte {
			return []byte(`{"last_record_sha256":"` + f.digest[:20])
		}},
		{"a list that is not JSON", func(*rec) []byte { return []byte("garbage") }},
		{"an empty file", func(*rec) []byte { return nil }},
		{"a list that is an array", func(*rec) []byte { return []byte(`[]`) }},
		{"a repeated anchor", func(f *rec) []byte {
			return []byte(`{"last_record_sha256":"` + f.digest + `","last_record_sha256":"` + f.digest + `","version":1}`)
		}},
		{"a byte order mark", func(f *rec) []byte {
			return append([]byte("\xef\xbb\xbf"), enc(f.digest)...)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBundle(t)
			first := b.apply()
			second := b.apply(func(r *rec) {
				r.artifacts["trust/"+r.set+"/root-list.json"] = c.list(first)
				r.refresh()
			})
			rep := b.run()
			wantFindings(t, rep, []wf{{AnchorUnknown, "trust/" + second.set + "/root-list.json"}})
			wantReasons(t, rep, []Code{AnchorUnknown}, nil)
		})
	}
}

func TestRootListAnchorDetailSaysWhichCase(t *testing.T) {
	b := newBundle(t)
	b.apply()
	hex16 := regexp.MustCompile(`[0-9a-f]{16}`)
	var details []string
	for _, list := range [][]byte{enc(digestB), []byte(`{"version":1}`), []byte("garbage")} {
		second := b.apply(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = list
			r.refresh()
		})
		rep := b.run()
		d := detail(rep, AnchorUnknown, "trust/"+second.set+"/root-list.json")
		if d == "" {
			t.Fatalf("no anchor-unknown for %q", list)
		}
		// The digests in a detail differ from one set to the next; the cases must differ without them.
		details = append(details, hex16.ReplaceAllString(d, "DIGEST"))
	}
	// The three cases read differently: not a record, no anchor in a later list, cannot be read.
	if details[0] == details[1] || details[1] == details[2] || details[0] == details[2] {
		t.Errorf("the details do not tell the cases apart: %q", details)
	}
	if !strings.Contains(details[2], "read") || strings.Contains(details[1], "read") || strings.Contains(details[0], "read") {
		t.Errorf("only the list that cannot be read says so: %q", details)
	}
}

func enc(s string) []byte { return rootListBytes(s) }

func TestRootListThatIsNotTheFirstNeedsAnAnchorButTheFirstDoesNot(t *testing.T) {
	b := newBundle(t)
	b.apply(rootListAs("", enc)) // the first list, with no anchor: nothing to say
	wantFindings(t, b.run(), nil)
}

func TestRootListWithAnythingElseInItIsNotLookedInto(t *testing.T) {
	// The root list is read for its anchor only: its version, its signature and members that this
	// check does not know belong to the check of the root list.
	for name, extra := range map[string]string{
		"an unknown member": `"comment":"not a member of version 1",`,
		"version 2":         `"x":1,`,
		"a list of roots":   `"roots":[{"label":"A","x509_spki_sha256":"` + pa + `"}],`,
	} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			first := b.apply()
			version := "1"
			if name == "version 2" {
				version = "2"
			}
			b.apply(func(r *rec) {
				r.artifacts["trust/"+r.set+"/root-list.json"] = []byte(`{` + extra + `"last_record_sha256":"` + first.digest + `","version":` + version + `}`)
				r.refresh()
			})
			wantFindings(t, b.run(), nil)
		})
	}
}

// The root lists of the repository's own vectors, read as the anchor reader reads them.
func TestRootListVectorsOfTheRepository(t *testing.T) {
	t.Run("a list with an anchor that is no record of this bundle", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = testrepo.Read(t, "testdata", "root-list", "v1", "lists", "seq7-a.json")
			r.refresh()
		})
		wantFindings(t, b.run(), []wf{{AnchorUnknown, "trust/" + r.set + "/root-list.json"}})
	})
	t.Run("the first list has no anchor", func(t *testing.T) {
		b := newBundle(t)
		b.apply(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = testrepo.Read(t, "testdata", "root-list", "v1", "lists", "init-a.json")
			r.refresh()
		})
		wantFindings(t, b.run(), nil)
	})
	t.Run("a later list with no anchor", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		r := b.apply(func(r *rec) {
			r.artifacts["trust/"+r.set+"/root-list.json"] = testrepo.Read(t, "testdata", "root-list", "v1", "lists", "init-a.json")
			r.refresh()
		})
		wantFindings(t, b.run(), []wf{{AnchorUnknown, "trust/" + r.set + "/root-list.json"}})
	})
	for _, name := range []string{"seq8-a-unknown-member.json", "seq8-a-version-2.json"} {
		t.Run(name+" gives its anchor", func(t *testing.T) {
			b := newBundle(t)
			first := b.apply()
			list := string(testrepo.Read(t, "testdata", "root-list", "v1", "lists", name))
			// The anchor is the one the vector names, read from the vector's own member.
			found := regexp.MustCompile(`"last_record_sha256":"([0-9a-f]{64})"`).FindStringSubmatch(list)
			if found == nil {
				t.Fatalf("the vector %s names no last_record_sha256", name)
			}
			anchor := found[1]
			// The anchor is a record of this bundle: the list is read, not refused.
			b.apply(func(r *rec) {
				r.artifacts["trust/"+r.set+"/root-list.json"] = []byte(strings.Replace(list, anchor, first.digest, 1))
				r.refresh()
			})
			wantFindings(t, b.run(), nil)
		})
	}
}

func TestRootListThatAnchorsToARecordThatIsNotValidIsUnknown(t *testing.T) {
	b := newBundle(t)
	first := b.apply()
	second := b.apply()
	// The anchor of set 2 is record 1; make record 1 invalid.
	rewrite(b, first, func(c []byte) []byte {
		return []byte(strings.Replace(string(c), `"outcome":"completed"`, `"outcome":"done"`, 1))
	})
	rep := b.run()
	has(t, rep, RecordInvalid, recordPath(first))
	has(t, rep, AnchorUnknown, "trust/"+second.set+"/root-list.json")
}

func TestTrustSetWithNoRootListIsNotChecked(t *testing.T) {
	// A personal bundle's trust set has only a certificate (record 0006, rule 12).
	b := newBundle(t)
	b.apply(func(r *rec) {
		r.artifacts = map[string][]byte{"trust/" + r.set + "/root.pem": []byte("-----BEGIN CERTIFICATE-----\n")}
		r.refresh()
	})
	b.apply(func(r *rec) {
		r.artifacts = map[string][]byte{"trust/" + r.set + "/root.pem": []byte("-----BEGIN CERTIFICATE-----\nx\n")}
		r.refresh()
	})
	wantFindings(t, b.run(), nil)
}

func TestRootListThatIsAFolderOrALinkCannotBeRead(t *testing.T) {
	t.Run("a folder", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		p := "trust/" + r.set + "/root-list.json"
		b.remove(p)
		b.mkdir(p)
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, p}, {FileDigest, p}})
	})
	t.Run("a link", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		p := "trust/" + r.set + "/root-list.json"
		b.remove(p)
		b.symlink("keys.txt", p)
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, p}, {FileDigest, p}})
	})
	t.Run("a FIFO", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		p := "trust/" + r.set + "/root-list.json"
		b.remove(p)
		b.fifo(p)
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, p}, {FileDigest, p}})
	})
	t.Run("longer than 8 MiB", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		p := "trust/" + r.set + "/root-list.json"
		b.remove(p)
		b.sparse(p, 8<<20+1)
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, p}, {FileDigest, p}})
	})
}
