package ceremony_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The record of a ceremony that made keys of two kinds (docs/reference/ceremony-record.md, "The
// record": revocations, root; "The birth journal"; docs/reference/bundle.md, "root.json").

func TestRecordOfAnOpenPGPRootListsTheRevocationsAndTheFingerprintOfTheRoot(t *testing.T) {
	k := newTK(t, tkOpts{})
	out, err := k.record(nil)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	r, err := files.ReadRecord(out)
	if err != nil {
		t.Fatalf("the reader refuses the record: %v", err)
	}
	want := k.wantRevocations()
	if len(want) != 3 {
		t.Fatalf("the test makes %d entries, want 3 (removal, compromised, superseded)", len(want))
	}
	if !reflect.DeepEqual(r.Revocations, want) {
		t.Errorf("revocations = %+v\nwant %+v", r.Revocations, want)
	}
	if r.Root == nil || r.Root.OpenPGP != k.fpr["A"] || r.Root.X509 != k.pin["A"] {
		t.Errorf("root = %+v", r.Root)
	}
	// Each journal holds two births and the plan's signatures, and the record names both journals.
	if got := strings.Count(string(k.fl.file("births.jsonl")), "\n"); got != 2 {
		t.Errorf("births.jsonl has %d lines, want 2", got)
	}
	if r.BirthsSHA256 != sum(k.fl.file("births.jsonl")) || r.SignaturesSHA256 != sum(k.fl.file("signatures.jsonl")) {
		t.Errorf("the record does not name the digests of the journals")
	}
	if len(r.Signatures) != 6 {
		t.Errorf("the record lists %d signatures, want 6", len(r.Signatures))
	}
	// The same bytes are on the disk, and the check of the history finds nothing.
	if !strings.Contains(string(k.fl.file("record.json")), `"revocations":[`) {
		t.Error("record.json has no list of revocations")
	}
	if rep := k.b.check(); !rep.Clean() {
		t.Errorf("findings %+v", rep.Findings)
	}
}

// The digest of a revocation signature in the record is the one of the line of the journal, and the
// one of root.json: the three say the same thing, and the entry of a removal is the digest of the
// text that root.json holds.
func TestTheRecordTakesEachDigestOfTheRevocationsFromTheJournalAndRootJSONAlike(t *testing.T) {
	k := newTK(t, tkOpts{reasons: []string{"compromised", "superseded", "retired", "no-reason"}})
	out, err := k.record(nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := files.ReadRecord(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Revocations) != 5 {
		t.Fatalf("%d entries, want 5", len(r.Revocations))
	}
	rj, err := files.ReadRootJSON(k.b.read("roots", "A", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	signatureEntries := 0
	for _, e := range r.Revocations {
		if e.Reason == "root-removal" {
			if e.SHA256 != rj.RemovalSHA256 {
				t.Errorf("the removal entry %s is not removal_sha256 %s", e.SHA256, rj.RemovalSHA256)
			}
			continue
		}
		signatureEntries++
		if e.SHA256 != rj.Revocations[e.Reason] {
			t.Errorf("the entry %s has %s and root.json %s", e.Reason, e.SHA256, rj.Revocations[e.Reason])
		}
		var line string
		for _, s := range r.Signatures {
			m := s.(map[string]any)
			if m["kind"] == "primary-revocation" && m["reason"] == e.Reason {
				line, _ = m["signature_sha256"].(string)
			}
		}
		if line != e.SHA256 {
			t.Errorf("the entry %s has %s and the signature of the record %s", e.Reason, e.SHA256, line)
		}
	}
	if signatureEntries != 4 {
		t.Errorf("%d reason entries, want 4", signatureEntries)
	}
	if rep := k.b.check(); !rep.Clean() {
		t.Errorf("findings %+v", rep.Findings)
	}
}

// Two keys of two kinds: the entries come in the order of the plan's signatures, label by label.
func TestTheRecordOfTwoLabelsListsTheEntriesInTheOrderOfThePlan(t *testing.T) {
	k := newTK(t, tkOpts{labels: []string{"A", "B"}})
	out, err := k.record(nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := files.ReadRecord(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range r.Revocations {
		got = append(got, e.Label+" "+e.Reason)
	}
	want := []string{"A root-removal", "A compromised", "A superseded", "B root-removal", "B compromised", "B superseded"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the entries are %v, want %v", got, want)
	}
	if len(strings.Split(strings.TrimSpace(string(k.fl.file("births.jsonl"))), "\n")) != 4 {
		t.Error("births.jsonl does not hold four births")
	}
	if rep := k.b.check(); !rep.Clean() {
		t.Errorf("findings %+v", rep.Findings)
	}
}

// A ceremony of an X.509 key only: no primary, no revocation signature. The list is not required and
// is optional: the record of part 13 has no member, and one with a root-removal entry for each key is
// accepted too.
func TestTheRecordOfAnX509OnlyCeremonyNeedsNoListAndTakesOneOfRemovals(t *testing.T) {
	t.Run("no list: the record has no member", func(t *testing.T) {
		k := newTK(t, tkOpts{noPrimaries: true})
		out, err := k.record(func(in *ceremony.RecordIn) { in.Revocations = nil })
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "revocations") {
			t.Errorf("the record has a list: %s", out)
		}
		if rep := k.b.check(); !rep.Clean() {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
	t.Run("an empty list that is not nil is no list", func(t *testing.T) {
		k := newTK(t, tkOpts{noPrimaries: true})
		out, err := k.record(func(in *ceremony.RecordIn) { in.Revocations = []files.RevocationEntry{} })
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "revocations") {
			t.Errorf("the record has a list: %s", out)
		}
	})
	t.Run("a removal entry for each key", func(t *testing.T) {
		k := newTK(t, tkOpts{noPrimaries: true, labels: []string{"A", "B"}})
		out, err := k.record(nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := files.ReadRecord(out)
		if err != nil {
			t.Fatal(err)
		}
		want := []files.RevocationEntry{{Label: "A", Reason: "root-removal", SHA256: k.removal("A")}, {Label: "B", Reason: "root-removal", SHA256: k.removal("B")}}
		if !reflect.DeepEqual(r.Revocations, want) {
			t.Errorf("revocations = %+v, want %+v", r.Revocations, want)
		}
		rj, _ := files.ReadRootJSON(k.b.read("roots", "A", "root.json"))
		if rj.Revocations != nil || rj.OpenPGPFingerprint != "" {
			t.Errorf("the root.json of an X.509 key holds OpenPGP members: %+v", rj)
		}
		if rep := k.b.check(); !rep.Clean() {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
}

// The list that the plan asks for is required when the plan has a signature of the kind
// primary-revocation.
func TestRecordWantsTheListWhenThePlanHasARevocationSignature(t *testing.T) {
	for name, edit := range map[string]func(*ceremony.RecordIn){
		"no list":       func(in *ceremony.RecordIn) { in.Revocations = nil },
		"an empty list": func(in *ceremony.RecordIn) { in.Revocations = []files.RevocationEntry{} },
	} {
		t.Run(name, func(t *testing.T) {
			newTK(t, tkOpts{}).refuses(edit, ceremony.ErrInvalidInput, "revocation")
		})
	}
}

func TestRecordRefusesAListThatIsNotWhatThePlanSigned(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*ceremony.RecordIn)
		words []string
	}{
		{"one entry fewer: the last", func(in *ceremony.RecordIn) { in.Revocations = in.Revocations[:2] }, []string{"2 entries", "3 signatures"}},
		{"one entry fewer: the first", func(in *ceremony.RecordIn) { in.Revocations = in.Revocations[1:] }, []string{"2 entries"}},
		{"one entry fewer: the removal", func(in *ceremony.RecordIn) {
			in.Revocations = append(in.Revocations[:0:0], in.Revocations[1], in.Revocations[2])
		}, []string{"2 entries"}},
		{"one entry too many", func(in *ceremony.RecordIn) {
			in.Revocations = append(in.Revocations, files.RevocationEntry{Label: "A", Reason: "retired", SHA256: tkSum("packet", "A", "retired")})
		}, []string{"4 entries"}},
		{"the first entry twice", func(in *ceremony.RecordIn) { in.Revocations = append(in.Revocations, in.Revocations[0]) }, []string{"4 entries"}},
		{"two entries swapped", func(in *ceremony.RecordIn) {
			in.Revocations[1], in.Revocations[2] = in.Revocations[2], in.Revocations[1]
		}, []string{"revocation entry 2", "compromised", "superseded"}},
		{"the removal after the reasons", func(in *ceremony.RecordIn) {
			in.Revocations = []files.RevocationEntry{in.Revocations[1], in.Revocations[2], in.Revocations[0]}
		}, []string{"revocation entry 1"}},
		{"another label", func(in *ceremony.RecordIn) { in.Revocations[1].Label = "B" }, []string{"revocation entry 2"}},
		{"a label that the plan does not have, in the removal", func(in *ceremony.RecordIn) { in.Revocations[0].Label = "Z" }, []string{"revocation entry 1"}},
		{"another reason: retired for compromised", func(in *ceremony.RecordIn) { in.Revocations[1].Reason = "retired" }, []string{"revocation entry 2", "retired"}},
		{"another reason: no-reason for superseded", func(in *ceremony.RecordIn) { in.Revocations[2].Reason = "no-reason" }, []string{"revocation entry 3"}},
		{"the reason of a removal on a signature", func(in *ceremony.RecordIn) { in.Revocations[1].Reason = "root-removal" }, []string{"revocation entry 2"}},
		{"the reason of a signature on the removal", func(in *ceremony.RecordIn) { in.Revocations[0].Reason = "compromised" }, []string{"revocation entry 1"}},
		{"a digest that is not the one of the journal: compromised", func(in *ceremony.RecordIn) { in.Revocations[1].SHA256 = strings.Repeat("9", 64) }, []string{"revocation entry 2", "signatures.jsonl"}},
		{"a digest that is not the one of the journal: superseded", func(in *ceremony.RecordIn) { in.Revocations[2].SHA256 = strings.Repeat("9", 64) }, []string{"revocation entry 3", "signatures.jsonl"}},
		{"the digest of another reason", func(in *ceremony.RecordIn) { in.Revocations[1].SHA256 = in.Revocations[2].SHA256 }, []string{"revocation entry 2"}},
		{"a digest that differs in its last digit", func(in *ceremony.RecordIn) {
			d := in.Revocations[1].SHA256
			in.Revocations[1].SHA256 = d[:63] + string("0123456789abcdef"[(strings.IndexByte("0123456789abcdef", d[63])+1)%16])
		}, []string{"revocation entry 2"}},
		{"a digest of the removal that is not the one of root.json", func(in *ceremony.RecordIn) { in.Revocations[0].SHA256 = strings.Repeat("9", 64) }, []string{"revocation entry 1", "root.json"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newTK(t, tkOpts{}).refuses(c.edit, ceremony.ErrInvalidInput, c.words...)
		})
	}
}

func TestRecordRefusesAnEntryThatIsNotInItsForm(t *testing.T) {
	cases := map[string]func(*ceremony.RecordIn){
		"an empty label":       func(in *ceremony.RecordIn) { in.Revocations[0].Label = "" },
		"a label of two":       func(in *ceremony.RecordIn) { in.Revocations[0].Label = "AB" },
		"a lower-case label":   func(in *ceremony.RecordIn) { in.Revocations[1].Label = "a" },
		"an empty reason":      func(in *ceremony.RecordIn) { in.Revocations[1].Reason = "" },
		"an unknown reason":    func(in *ceremony.RecordIn) { in.Revocations[1].Reason = "lost" },
		"an empty digest":      func(in *ceremony.RecordIn) { in.Revocations[2].SHA256 = "" },
		"a digest of 63":       func(in *ceremony.RecordIn) { in.Revocations[2].SHA256 = in.Revocations[2].SHA256[:63] },
		"a digest in capitals": func(in *ceremony.RecordIn) { in.Revocations[2].SHA256 = strings.ToUpper(in.Revocations[2].SHA256) },
		"a zero entry":         func(in *ceremony.RecordIn) { in.Revocations[2] = files.RevocationEntry{} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			newTK(t, tkOpts{}).refuses(edit, ceremony.ErrInvalidInput, "revocation entry", "is refused by its reader")
		})
	}
}

func TestRecordRefusesMoreThanTheMostEntriesBeforeItReadsAnything(t *testing.T) {
	k := newTK(t, tkOpts{})
	k.refuses(func(in *ceremony.RecordIn) {
		in.Revocations = in.Revocations[:0]
		for i := 0; i < files.MaxRevocations+1; i++ {
			in.Revocations = append(in.Revocations, files.RevocationEntry{Label: string(rune('A' + i%26)), Reason: "retired", SHA256: tkSum("x", string(rune(i)))})
		}
	}, ceremony.ErrInvalidInput, "131", "130")
}

func TestRecordRefusesAListWhoseRootJSONIsNotThereOrIsNotRead(t *testing.T) {
	t.Run("the root.json of the label is not among the artifacts", func(t *testing.T) {
		k := newTK(t, tkOpts{})
		k.refuses(func(in *ceremony.RecordIn) {
			in.Artifacts = in.Artifacts[1:]
		}, ceremony.ErrInvalidInput, "root.json", "not among the artifacts")
	})
	t.Run("the root.json of the label is not on the disk", func(t *testing.T) {
		k := newTK(t, tkOpts{skipRootJSON: map[string]bool{"A": true}})
		k.refuses(nil, ceremony.ErrInvalidInput, "root.json")
	})
	t.Run("one of two labels has no root.json", func(t *testing.T) {
		k := newTK(t, tkOpts{labels: []string{"A", "B"}, skipRootJSON: map[string]bool{"B": true}})
		k.refuses(nil, ceremony.ErrInvalidInput, "key \"B\"", "not among the artifacts")
	})
	t.Run("a root.json that its reader refuses", func(t *testing.T) {
		k := newTK(t, tkOpts{rootJSONBytes: map[string][]byte{"A": []byte(`{"version":1}`)}})
		k.refuses(nil, ceremony.ErrDiskMismatch, "root.json")
	})
	t.Run("a root.json of another label than its path", func(t *testing.T) {
		k := newTK(t, tkOpts{labels: []string{"A", "B"}, rootJSON: func(l string, r *files.RootJSON) {
			if l == "B" {
				r.Label = "A"
			}
		}})
		k.refuses(nil, ceremony.ErrInvalidInput, "revocation entry 4")
	})
	t.Run("a root.json that is a link or not a file is no artifact", func(t *testing.T) {
		k := newTK(t, tkOpts{})
		if err := os.Remove(k.b.path("roots", "A", "root.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../ritueel.yaml", k.b.path("roots", "A", "root.json")); err != nil {
			t.Skipf("no links: %v", err)
		}
		out, err := k.record(nil)
		if err == nil {
			t.Fatalf("a record was written over a link: %s", out)
		}
		noRecord(t, k.fl)
	})
}

func TestRecordRefusesARootJSONThatDoesNotHoldTheDigestOfTheEntry(t *testing.T) {
	cases := []struct {
		name string
		edit func(l string, r *files.RootJSON)
		kind error
		word string
	}{
		{"another compromised digest", func(_ string, r *files.RootJSON) { r.Revocations["compromised"] = strings.Repeat("7", 64) }, ceremony.ErrInvalidInput, "revocation entry 2"},
		{"another superseded digest", func(_ string, r *files.RootJSON) { r.Revocations["superseded"] = strings.Repeat("7", 64) }, ceremony.ErrInvalidInput, "revocation entry 3"},
		{"the digests of the two reasons swapped", func(_ string, r *files.RootJSON) {
			r.Revocations["compromised"], r.Revocations["superseded"] = r.Revocations["superseded"], r.Revocations["compromised"]
		}, ceremony.ErrInvalidInput, "revocation entry 2"},
		{"another removal digest", func(_ string, r *files.RootJSON) { r.RemovalSHA256 = strings.Repeat("7", 64) }, ceremony.ErrInvalidInput, "revocation entry 1"},
		{"no removal digest", func(_ string, r *files.RootJSON) { r.RemovalSHA256 = "" }, ceremony.ErrInvalidInput, "revocation entry 1"},
		{"a retired digest that the plan did not make is left alone", nil, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.edit == nil {
				return
			}
			k := newTK(t, tkOpts{rootJSON: c.edit})
			k.refuses(nil, c.kind, c.word)
		})
	}
}

// root.json holds more reasons than the plan made: not judged here (the checks of the artifacts
// judge the file against the plan), and the record lists what the plan made.
func TestRecordDoesNotJudgeAReasonThatRootJSONHoldsAndThePlanDidNotMake(t *testing.T) {
	k := newTK(t, tkOpts{rootJSON: func(_ string, r *files.RootJSON) { r.Revocations["retired"] = strings.Repeat("7", 64) }})
	out, err := k.record(nil)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	r, err := files.ReadRecord(out)
	if err != nil || len(r.Revocations) != 3 {
		t.Fatalf("%+v, %v", r, err)
	}
}

// The root of the record: its OpenPGP fingerprint is the key of the line of the journal of
// signatures for the self-signature of its label.
func TestRecordHoldsTheOpenPGPFingerprintOfTheRootToTheSelfSignature(t *testing.T) {
	wrongFpr := strings.Repeat("9", 40)
	cases := []struct {
		name  string
		edit  func(*ceremony.RecordIn)
		words []string
	}{
		{"no fingerprint", func(in *ceremony.RecordIn) { in.Root.OpenPGP = "" }, []string{"OpenPGP fingerprint"}},
		{"another fingerprint", func(in *ceremony.RecordIn) { in.Root.OpenPGP = wrongFpr }, []string{"OpenPGP fingerprint", "self-signature"}},
		{"the fingerprint with its last digit changed", func(in *ceremony.RecordIn) { in.Root.OpenPGP = in.Root.OpenPGP[:39] + "9" }, []string{"self-signature"}},
		{"the pin of the X.509 key in its place", func(in *ceremony.RecordIn) { in.Root.OpenPGP = in.Root.X509 }, []string{"OpenPGP fingerprint"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newTK(t, tkOpts{}).refuses(c.edit, ceremony.ErrInvalidInput, c.words...)
		})
	}
	t.Run("the fingerprint of the other label", func(t *testing.T) {
		k := newTK(t, tkOpts{labels: []string{"A", "B"}})
		k.refuses(func(in *ceremony.RecordIn) { in.Root.OpenPGP = k.fpr["B"] }, ceremony.ErrInvalidInput, "self-signature")
	})
	t.Run("a plan with no self-signature takes a root with none, as before", func(t *testing.T) {
		k := newTK(t, tkOpts{noSelfSignature: true})
		if _, err := k.record(func(in *ceremony.RecordIn) { in.Root.OpenPGP = "" }); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
	t.Run("a plan with no self-signature takes a fingerprint that the plan's root does not have", func(t *testing.T) {
		k := newTK(t, tkOpts{noSelfSignature: true})
		if _, err := k.record(nil); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
}

// A cut or a hand edit of a journal: two lines for one pair of label and purpose are not a journal
// that a record can list; two lines for one label and two purposes are.
func TestRecordTakesTwoBirthsForOneLabelAndRefusesTheSamePairTwice(t *testing.T) {
	t.Run("two purposes: accepted", func(t *testing.T) {
		k := newTK(t, tkOpts{})
		if _, err := k.record(nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the primary born twice, by a hand edit of the journal", func(t *testing.T) {
		k := newTK(t, tkOpts{planEdit: func(m map[string]any) {
			births := m["births"].([]any)
			m["births"] = append(births, births[1])
		}})
		// The folder does not write such a line (the journal refuses it); a hand edit does.
		line, err := (&files.BirthLine{At: ts, Label: "A", Purpose: tkPurposePGP, Store: "software", Place: "A.openpgp.key.asc", PublicKeySHA256: k.pgpKey["A"]}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if got := k.b.read("history", name1, "births.jsonl"); strings.Count(string(got), "\n") != 2 {
			t.Fatalf("the journal holds %q", got)
		}
		appendToFile(t, k.b.path("history", name1, "births.jsonl"), string(line)+"\n")
		k.badDisk = true
		k.refuses(nil, ceremony.ErrDiskMismatch, "twice", "openpgp-primary")
	})
	t.Run("the X.509 key born twice, by a hand edit of the journal", func(t *testing.T) {
		k := newTK(t, tkOpts{planEdit: func(m map[string]any) {
			births := m["births"].([]any)
			m["births"] = append(births, births[0])
		}})
		line, err := (&files.BirthLine{At: ts, Label: "A", Purpose: tkPurposeX509, Store: "software", Place: "A.x509.key.pem", PublicKeySHA256: k.pin["A"]}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		appendToFile(t, k.b.path("history", name1, "births.jsonl"), string(line)+"\n")
		k.badDisk = true
		k.refuses(nil, ceremony.ErrDiskMismatch, "twice", "x509-root")
	})
}

func appendToFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// A cut at every changing call of a ceremony with two births for one label and the signatures of both
// kinds: what is on disk is what the order of the writes leaves, nothing is deleted, and the check of
// the history finds nothing that fails: at most the notice of a ceremony that was not finished.
func TestACutAtEveryWriteOfACeremonyOfTwoKindsOfKeyIsCleanOrUnfinished(t *testing.T) {
	whole, err := tryTK(t, tkOpts{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := whole.record(nil); err != nil {
		t.Fatal(err)
	}
	total := whole.b.r.count
	if total < 50 {
		t.Fatalf("a whole ceremony made only %d changing calls", total)
	}
	t.Logf("a whole ceremony of two kinds of key makes %d changing calls", total)
	for n := 1; n <= total; n++ {
		t.Run(fmt.Sprintf("cut at call %d of %d", n, total), func(t *testing.T) {
			t.Parallel()
			k, err := tryTK(t, tkOpts{}, n)
			if err == nil {
				_, err = k.record(nil)
			}
			if err == nil {
				t.Fatalf("the cut at call %d did not stop the ceremony", n)
			}
			if !errors.Is(err, errCut) {
				t.Errorf("the error does not hold the failed write: %v", err)
			}
			rep := k.b.check()
			if f := rep.Failing(); len(f) != 0 {
				t.Errorf("history.Check finds %+v", f)
			}
			_, recErr := os.Lstat(k.b.path("history", name1, "record.json"))
			haveRecord := recErr == nil
			_, setErr := os.Lstat(k.b.path(strings.Split(k.fl.s.setName(), "/")...))
			haveSet := setErr == nil
			want := 0
			if haveRecord {
				want = 1
			}
			if rep.Records != want {
				t.Errorf("the check counts %d records, want %d", rep.Records, want)
			}
			warns := codes(rep.Warnings())
			if unfinished := haveSet && !haveRecord; slices.Contains(warns, "unfinished-ceremony") != unfinished {
				t.Errorf("the notices are %v; unfinished-ceremony expected: %v", warns, unfinished)
			}
			for _, w := range warns {
				if w != "unfinished-ceremony" && w != "unexpected-file" {
					t.Errorf("an unexpected notice %s", w)
				}
			}
		})
	}
}

// What the plan says about its signatures that the record reads: the subject of a signature is a
// label, and a label has one self-signature of its primary.
func TestRecordRefusesAPlanWhoseSignaturesDoNotNameTheirKeys(t *testing.T) {
	setSub := func(kind, to string, all bool) func(m map[string]any) {
		return func(m map[string]any) {
			for _, s := range m["signatures"].([]any) {
				e := s.(map[string]any)
				if e["kind"] == kind {
					if to == "<none>" {
						delete(e, "subject")
					} else {
						e["subject"] = to
					}
					if !all {
						return
					}
				}
			}
		}
	}
	cases := []struct {
		name  string
		opts  tkOpts
		words []string
	}{
		{"a revocation with a subject that is not a label", tkOpts{planEdit: setSub("primary-revocation", "x", false)}, []string{"no key as its subject"}},
		{"a revocation with a subject in lower case", tkOpts{planEdit: setSub("primary-revocation", "a", false)}, []string{"no key as its subject"}},
		{"a removal with no subject", tkOpts{planEdit: setSub("root-removal", "<none>", false)}, []string{"no key as its subject"}},
		{"a removal with an empty subject", tkOpts{planEdit: setSub("root-removal", "", false)}, []string{"no key as its subject"}},
		{"a self-signature with an empty subject", tkOpts{planEdit: setSub("primary-self-signature", "", false)}, []string{"single subject"}},
		{"a self-signature with no subject", tkOpts{planEdit: setSub("primary-self-signature", "<none>", false)}, []string{"single subject"}},
		{"two self-signatures of one label", tkOpts{twoSelfSignatures: true}, []string{"single subject"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := newTK(t, c.opts)
			k.badDisk = true
			k.refuses(nil, ceremony.ErrDiskMismatch, c.words...)
		})
	}
	t.Run("a revocation with no reason: no list is the right one", func(t *testing.T) {
		k := newTK(t, tkOpts{planEdit: func(m map[string]any) {
			for _, s := range m["signatures"].([]any) {
				if e := s.(map[string]any); e["kind"] == "primary-revocation" {
					delete(e, "reason")
					return
				}
			}
		}})
		k.badDisk = true
		k.refuses(nil, ceremony.ErrInvalidInput, "revocation entry 2")
	})
}

// A file in the folder of a key that is not its root.json is not read as it, however its name sorts.
func TestRecordTakesOtherArtifactsInTheFolderOfAKeyAndReadsOnlyRootJSON(t *testing.T) {
	k := newTK(t, tkOpts{})
	for p, data := range map[string]string{
		"roots/A/zz.json":       `{"label":"A"}`,
		"roots/A/z/root.json":   `{"label":"A"}`,
		"roots/A/zz/root.json":  `not json`,
		"roots/AB/root.json":    `{}`,
		"roots/B/root.json":     `{}`,
		"roots/A/root.json.bak": `{}`,
	} {
		dir := k.b.path(strings.Split(p, "/")[:len(strings.Split(p, "/"))-1]...)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(k.b.path(strings.Split(p, "/")...), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err := k.record(func(in *ceremony.RecordIn) {
		in.Artifacts = append(in.Artifacts, "roots/A/zz.json", "roots/A/z/root.json", "roots/A/zz/root.json", "roots/AB/root.json", "roots/B/root.json", "roots/A/root.json.bak")
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	r, err := files.ReadRecord(out)
	if err != nil || len(r.Revocations) != 3 {
		t.Fatalf("%+v, %v", r, err)
	}
	if len(r.Artifacts) != 2+6 {
		t.Errorf("%d artifacts", len(r.Artifacts))
	}
}

// Record judges one copy of the list that its caller gave. The caller changes an entry while Record
// reads the files, at its first look at a folder; the record holds the entries as they were given.
func TestRecordJudgesOneCopyOfTheListOfRevocations(t *testing.T) {
	k := newTK(t, tkOpts{})
	in := k.recordIn()
	given := append([]files.RevocationEntry(nil), in.Revocations...)
	fired := 0
	k.b.r.openHook = func(string) {
		fired++
		if fired > 1 {
			return
		}
		in.Revocations[0].SHA256 = strings.Repeat("9", 64)
		in.Revocations[1].Reason = "retired"
		in.Revocations = in.Revocations[:1]
	}
	out, err := k.fl.f.Record(in)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if fired == 0 {
		t.Fatal("the hook never ran, so nothing was shown")
	}
	r, err := files.ReadRecord(out)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Revocations, given) {
		t.Errorf("the record holds %+v, the caller gave %+v", r.Revocations, given)
	}
}

// A root.json that is not a plain file of a size that is read, or that is hostile text, is refused
// when the list names its label: no hang on a pipe, no link followed, no read past the limit.
func TestRecordRefusesARootJSONThatIsNotAPlainFileOrIsHostile(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"a pipe": func(t *testing.T, p string) {
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Skipf("no pipes: %v", err)
			}
		},
		"a folder": func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a link to a file": func(t *testing.T, p string) {
			if err := os.Symlink("../../ritueel.yaml", p); err != nil {
				t.Skipf("no links: %v", err)
			}
		},
		"a link to nowhere": func(t *testing.T, p string) {
			if err := os.Symlink("nowhere", p); err != nil {
				t.Skipf("no links: %v", err)
			}
		},
		"a file of nine mebibytes": func(t *testing.T, p string) {
			if err := os.WriteFile(p, bytes.Repeat([]byte(" "), 9<<20), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"nesting a hundred thousand deep": func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte(strings.Repeat("[", 100000)), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"bytes that are not UTF-8": func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("\xff\xfe\x00{"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"an empty file": func(t *testing.T, p string) {
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, place := range cases {
		t.Run(name, func(t *testing.T) {
			k := newTK(t, tkOpts{})
			path := k.b.path("roots", "A", "root.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			place(t, path)
			k.badDisk = true
			k.refuses(nil, nil)
		})
	}
}

// A ceremony of an X.509 key only has one removal authorisation for each key and no revocation
// signature: a list that names a reason, or one entry too many, is refused.
func TestRecordOfAnX509OnlyCeremonyRefusesAListThatIsNotOneRemovalForEachKey(t *testing.T) {
	cases := map[string]func(k *tk, in *ceremony.RecordIn){
		"a reason that the plan did not sign": func(k *tk, in *ceremony.RecordIn) {
			in.Revocations = []files.RevocationEntry{{Label: "A", Reason: "compromised", SHA256: k.removal("A")}}
		},
		"the removal and a reason": func(k *tk, in *ceremony.RecordIn) {
			in.Revocations = append(in.Revocations, files.RevocationEntry{Label: "A", Reason: "superseded", SHA256: k.packet("A", "superseded")})
		},
		"the removal of a label that the plan does not make": func(k *tk, in *ceremony.RecordIn) {
			in.Revocations = []files.RevocationEntry{{Label: "B", Reason: "root-removal", SHA256: k.removal("A")}}
		},
		"the removal twice": func(k *tk, in *ceremony.RecordIn) {
			in.Revocations = append(in.Revocations, in.Revocations[0])
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			k := newTK(t, tkOpts{noPrimaries: true})
			k.refuses(func(in *ceremony.RecordIn) { edit(k, in) }, ceremony.ErrInvalidInput)
		})
	}
}

// The list at the limit of 130 entries is judged against the plan like any other list: it is the
// count of the plan that refuses it, and not the limit. 131 is refused for the limit.
func TestRecordJudgesAListOfTheMostEntriesAgainstThePlanAndOneMoreAgainstTheLimit(t *testing.T) {
	list := func(n int) func(*ceremony.RecordIn) {
		return func(in *ceremony.RecordIn) {
			in.Revocations = in.Revocations[:0]
			for i := 0; i < n; i++ {
				in.Revocations = append(in.Revocations, files.RevocationEntry{Label: string(rune('A' + i%26)), Reason: []string{"root-removal", "compromised", "superseded", "retired", "no-reason"}[i/26%5], SHA256: tkSum("x", fmt.Sprint(i))})
			}
		}
	}
	newTK(t, tkOpts{}).refuses(list(files.MaxRevocations), ceremony.ErrInvalidInput, "130 entries", "plan has 3")
	newTK(t, tkOpts{}).refuses(list(files.MaxRevocations+1), ceremony.ErrInvalidInput, "131", "more than the 130")
}
