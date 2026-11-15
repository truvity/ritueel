package files_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// FuzzReadRecordRevocations feeds the reader of the ceremony record documents that hold the list
// revocations. The laws: it never panics; a refusal is of the three kinds, in printable ASCII, and
// returns no record; an accepted record holds a list in the form of the page (at most 130 entries,
// a label of one upper-case letter, one of five reasons, a digest, no pair twice), only in a
// completed apply, and its canonical bytes read back to the same record.
func FuzzReadRecordRevocations(f *testing.F) {
	for _, list := range []any{
		revList(), []any{}, nil, "A", 1, []any{revEntry("A", "retired", '1'), revEntry("A", "retired", '2')},
		[]any{map[string]any{"label": "A", "reason": "retired"}}, []any{map[string]any{"label": "A", "reason": "retired", "sha256": dg('1'), "x": 1}},
		[]any{revEntry("a", "retired", '1')}, []any{revEntry("A", "root_removal", '1')},
	} {
		for _, doc := range []map[string]any{applyDoc(), declineDoc(), closeDoc()} {
			b := encode(f, doc, set("revocations", list))
			f.Add(b)
			f.Add(b[:len(b)/2])
		}
	}
	var many []any
	for i := 0; i < 131; i++ {
		many = append(many, revEntry(string(rune('A'+i%26)), []string{"compromised", "superseded", "retired", "no-reason", "root-removal"}[i%5], '1'))
	}
	f.Add(encode(f, applyDoc(), set("revocations", many)))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := files.ReadRecord(data)
		if err != nil {
			if r != nil {
				t.Fatal("a record comes with an error")
			}
			refused(t, err)
			return
		}
		if r.Revocations != nil {
			if r.Outcome != "completed" || r.Command != "apply" {
				t.Fatalf("a list in a record of %s %s", r.Command, r.Outcome)
			}
			if len(r.Revocations) == 0 || len(r.Revocations) > files.MaxRevocations {
				t.Fatalf("a list of %d entries", len(r.Revocations))
			}
			seen := map[[2]string]bool{}
			for _, e := range r.Revocations {
				if err := files.CheckRevocationEntry(e); err != nil {
					t.Fatalf("an accepted entry %+v is refused by its own check: %v", e, err)
				}
				k := [2]string{e.Label, e.Reason}
				if seen[k] {
					t.Fatalf("the pair %v twice", k)
				}
				seen[k] = true
			}
		}
		first, err := r.Canonical()
		if err != nil {
			t.Fatalf("a record that was read cannot be written: %v", err)
		}
		back, err := files.ReadRecord(first)
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatalf("the canonical bytes read back as %+v, %v", back, err)
		}
		if second, err := back.Canonical(); err != nil || !bytes.Equal(first, second) {
			t.Fatalf("the canonical bytes change on the second turn")
		}
	})
}

// FuzzCheckRevocationEntry: an entry that is accepted has a label of one upper-case letter, one of
// the five words and a digest of 64 lower-case hexadecimal digits; a refusal is a *FormatError in
// printable ASCII.
func FuzzCheckRevocationEntry(f *testing.F) {
	f.Add("A", "retired", dg('a'))
	f.Add("A", "root-removal", dg('0'))
	f.Add("", "", "")
	f.Add("AB", "retired", dg('a'))
	f.Add("a", "no-reason", dg('A'))
	f.Add("\xff", "\x00", strings.Repeat("g", 64))
	f.Add("Z", "compromised", dg('a')[:63])
	f.Fuzz(func(t *testing.T, label, reason, digest string) {
		err := files.CheckRevocationEntry(files.RevocationEntry{Label: label, Reason: reason, SHA256: digest})
		if err != nil {
			if !printableASCII(err.Error()) {
				t.Fatalf("the error is not printable ASCII: %q", err)
			}
			return
		}
		if len(label) != 1 || label[0] < 'A' || label[0] > 'Z' {
			t.Fatalf("the label %q is accepted", label)
		}
		switch reason {
		case "compromised", "superseded", "retired", "no-reason", "root-removal":
		default:
			t.Fatalf("the reason %q is accepted", reason)
		}
		if !files.IsDigest(digest) {
			t.Fatalf("the digest %q is accepted", digest)
		}
	})
}
