package files_test

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The record names the digest of the attempt and of each journal of its ceremony: attempt_sha256,
// births_sha256 and signatures_sha256. Each is optional and, when it is there, a digest in the fixed
// form. attempt_sha256 is only in an apply record that was completed: a declined record has no
// attempt, and a closing record names the attempt it closes in closes.

var digestMembers = []string{"attempt_sha256", "births_sha256", "signatures_sha256"}

func TestRecordTakesTheDigestsOfTheAttemptAndTheJournals(t *testing.T) {
	m := applyDoc()
	m["attempt_sha256"] = dg('a')
	m["births_sha256"] = dg('b')
	m["signatures_sha256"] = dg('c')
	r, err := files.ReadRecord(encode(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r.AttemptSHA256 != dg('a') || r.BirthsSHA256 != dg('b') || r.SignaturesSHA256 != dg('c') {
		t.Errorf("read %q, %q, %q", r.AttemptSHA256, r.BirthsSHA256, r.SignaturesSHA256)
	}
	// Each alone, and none.
	for _, name := range digestMembers {
		m := applyDoc()
		m[name] = dg('d')
		if _, err := files.ReadRecord(encode(t, m, nil)); err != nil {
			t.Errorf("%s alone: %v", name, err)
		}
	}
	if r, err := files.ReadRecord(encode(t, applyDoc(), nil)); err != nil || r.AttemptSHA256 != "" || r.BirthsSHA256 != "" || r.SignaturesSHA256 != "" {
		t.Errorf("none of them: %v, %+v", err, r)
	}
}

func TestDigestOfTheAttemptOrAJournalHasTheFormOfADigest(t *testing.T) {
	bad := map[string]string{
		"upper case":         strings.ToUpper(dg('a')),
		"63 characters":      dg('a')[:63],
		"65 characters":      dg('a') + "a",
		"not hexadecimal":    strings.Repeat("g", 64),
		"with a prefix":      "sha256:" + dg('a')[:57],
		"with a line break":  dg('a')[:63] + "\n",
		"a Cyrillic letter":  dg('a')[:63] + string(rune(0x430)),
		"a name, not a hash": "attempt.json",
	}
	for _, member := range digestMembers {
		for name, v := range bad {
			t.Run(member+" "+name, func(t *testing.T) {
				_, err := files.ReadRecord(encode(t, applyDoc(), set(member, v)))
				wantMember(t, err, member)
			})
		}
		t.Run(member+" empty text", func(t *testing.T) {
			_, err := files.ReadRecord(encode(t, applyDoc(), set(member, "")))
			wantMember(t, err, member)
			var fe *files.FormatError
			if errors.As(err, &fe) && !strings.Contains(fe.Reason, "empty") {
				t.Errorf("the reason %q does not say that the text is empty", fe.Reason)
			}
		})
		t.Run(member+" of another type", func(t *testing.T) {
			if _, err := files.ReadRecord(encode(t, applyDoc(), set(member, 5))); err == nil {
				t.Error("a number is accepted")
			}
			if _, err := files.ReadRecord(encode(t, applyDoc(), set(member, nil))); err == nil {
				t.Error("null is accepted")
			}
		})
	}
}

// The three members are only in a completed apply: a declined request writes no attempt and
// nothing is signed or born, and a closing record names the attempt it closes in closes and has no
// journals of its own. In any other kind of record each of them is a fault of that member.
func TestDigestsOfTheAttemptAndTheJournalsAreOnlyInACompletedApply(t *testing.T) {
	kinds := []struct {
		name string
		doc  func() map[string]any
		ok   bool
	}{
		{"a completed apply", applyDoc, true},
		{"a declined apply", declineDoc, false},
		{"a closing record", closeDoc, false},
	}
	for _, k := range kinds {
		for _, member := range digestMembers {
			t.Run(k.name+" with "+member, func(t *testing.T) {
				_, err := files.ReadRecord(encode(t, k.doc(), set(member, dg('a'))))
				if k.ok {
					if err != nil {
						t.Errorf("refused: %v", err)
					}
					return
				}
				wantMember(t, err, member)
			})
		}
		t.Run(k.name+" with all three", func(t *testing.T) {
			m := k.doc()
			m["attempt_sha256"], m["births_sha256"], m["signatures_sha256"] = dg('a'), dg('b'), dg('c')
			r, err := files.ReadRecord(encode(t, m, nil))
			if k.ok {
				if err != nil || r.AttemptSHA256 != dg('a') || r.BirthsSHA256 != dg('b') || r.SignaturesSHA256 != dg('c') {
					t.Errorf("err = %v, record %+v", err, r)
				}
				return
			}
			var fe *files.FormatError
			if !errors.As(err, &fe) || !slices.Contains(digestMembers, fe.Member) || r != nil {
				t.Errorf("err = %v, record %v; want a *FormatError for one of the three members", err, r)
			}
		})
		t.Run(k.name+" with none", func(t *testing.T) {
			if _, err := files.ReadRecord(encode(t, k.doc(), nil)); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

func TestDigestsOfTheAttemptAndTheJournalsRoundTripThroughCanonical(t *testing.T) {
	r := &files.Record{Version: 1, Ceremony: "c", Command: "apply", Outcome: "completed", PlanSHA256: dg('1'), TranscriptSHA256: dg('3'),
		AttemptSHA256: dg('a'), BirthsSHA256: dg('b'), SignaturesSHA256: dg('c'),
		Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}, Artifacts: []files.FileRef{}}
	first, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// The members are written under the names of the page, in the order of RFC 8785.
	for _, want := range []string{`"attempt_sha256":"` + dg('a') + `"`, `"births_sha256":"` + dg('b') + `"`, `"signatures_sha256":"` + dg('c') + `"`} {
		if !bytes.Contains(first, []byte(want)) {
			t.Errorf("%s is not in %s", want, first)
		}
	}
	if ok, err := canonjson.IsCanonical(first); err != nil || !ok {
		t.Errorf("IsCanonical = %v, %v", ok, err)
	}
	back, err := files.ReadRecord(first)
	if err != nil || !reflect.DeepEqual(back, r) {
		t.Fatalf("round trip: %v\n%+v", err, back)
	}
	if second, _ := back.Canonical(); !bytes.Equal(first, second) {
		t.Errorf("the bytes change on the way:\n%s\n%s", first, second)
	}
	// Left empty, a member is not written.
	r.BirthsSHA256 = ""
	c, _ := r.Canonical()
	if bytes.Contains(c, []byte("births_sha256")) {
		t.Errorf("an empty digest is written: %s", c)
	}
}
