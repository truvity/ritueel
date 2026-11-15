package files_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/strictjson"
)

// The member revocations of the ceremony record (docs/reference/ceremony-record.md, "The record"):
// a list of { "label", "reason", "sha256" }, the digest of each signature packet, and of each
// removal authorisation with the reason root-removal. The material itself is never in the record.

func revEntry(label, reason string, c byte) map[string]any {
	return map[string]any{"label": label, "reason": reason, "sha256": dg(c)}
}

// revList is the list of a ceremony that made two keys with their two always-made reasons and one
// removal authorisation each.
func revList() []any {
	return []any{
		revEntry("A", "root-removal", '1'), revEntry("A", "compromised", '2'), revEntry("A", "superseded", '3'),
		revEntry("B", "root-removal", '4'), revEntry("B", "compromised", '5'), revEntry("B", "superseded", '6'),
	}
}

func revRead(t *testing.T, list any) (*files.Record, error) {
	t.Helper()
	return files.ReadRecord(encode(t, applyDoc(), set("revocations", list)))
}

func TestARecordWithRevocationsReadsBackEachEntryAndWritesTheSameBytes(t *testing.T) {
	b := encode(t, applyDoc(), set("revocations", revList()))
	r, err := files.ReadRecord(b)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	want := []files.RevocationEntry{
		{Label: "A", Reason: "root-removal", SHA256: dg('1')}, {Label: "A", Reason: "compromised", SHA256: dg('2')},
		{Label: "A", Reason: "superseded", SHA256: dg('3')}, {Label: "B", Reason: "root-removal", SHA256: dg('4')},
		{Label: "B", Reason: "compromised", SHA256: dg('5')}, {Label: "B", Reason: "superseded", SHA256: dg('6')},
	}
	if !reflect.DeepEqual(r.Revocations, want) {
		t.Fatalf("revocations = %+v, want %+v", r.Revocations, want)
	}
	c, err := r.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	// The list keeps the order of the plan: it is not sorted by the writer.
	if i, j := strings.Index(string(c), `"label":"A","reason":"root-removal"`), strings.Index(string(c), `"label":"B","reason":"root-removal"`); i < 0 || j < i {
		t.Errorf("the entries are not written in the order that was given: %s", c)
	}
	// An entry has its three members, in the canonical order of RFC 8785 (label, reason, sha256).
	if !strings.Contains(string(c), `{"label":"A","reason":"root-removal","sha256":"`+dg('1')+`"}`) {
		t.Errorf("an entry is not written as the page gives it: %s", c)
	}
	back, err := files.ReadRecord(c)
	if err != nil || !reflect.DeepEqual(back, r) {
		t.Errorf("the canonical bytes read back as %+v, %v", back, err)
	}
	// The member is left out of a record that has no list.
	plain, _ := files.ReadRecord(encode(t, applyDoc(), nil))
	pc, err := plain.Canonical()
	if err != nil || strings.Contains(string(pc), "revocations") {
		t.Errorf("a record with no list writes %s, %v", pc, err)
	}
}

func TestARecordTakesEachOfTheFiveReasons(t *testing.T) {
	for _, reason := range []string{"compromised", "superseded", "retired", "no-reason", "root-removal"} {
		t.Run(reason, func(t *testing.T) {
			r, err := revRead(t, []any{revEntry("Z", reason, '9')})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Revocations) != 1 || r.Revocations[0].Reason != reason {
				t.Errorf("got %+v", r.Revocations)
			}
		})
	}
}

func TestARecordTakesTheSameReasonForTwoLabelsAndTwoReasonsForOneLabel(t *testing.T) {
	list := []any{revEntry("A", "retired", '1'), revEntry("B", "retired", '1'), revEntry("A", "no-reason", '1')}
	if _, err := revRead(t, list); err != nil {
		t.Fatalf("a pair that differs in the label or the reason is refused: %v", err)
	}
}

func TestARecordWithRevocationsThatBreakARuleIsRefusedWithTheMemberNamed(t *testing.T) {
	cases := []struct {
		name   string
		list   any
		member string
	}{
		{"an entry with no label", []any{map[string]any{"reason": "retired", "sha256": dg('1')}}, "revocations[0].label"},
		{"an entry with no reason", []any{map[string]any{"label": "A", "sha256": dg('1')}}, "revocations[0].reason"},
		{"an entry with no digest", []any{map[string]any{"label": "A", "reason": "retired"}}, "revocations[0].sha256"},
		{"an empty entry", []any{map[string]any{}}, "revocations[0].label"},
		{"an empty label", []any{revEntry("", "retired", '1')}, "revocations[0].label"},
		{"an empty reason", []any{revEntry("A", "", '1')}, "revocations[0].reason"},
		{"an empty digest", []any{map[string]any{"label": "A", "reason": "retired", "sha256": ""}}, "revocations[0].sha256"},
		{"a label of two letters", []any{revEntry("AB", "retired", '1')}, "revocations[0].label"},
		{"a label in lower case", []any{revEntry("a", "retired", '1')}, "revocations[0].label"},
		{"a label that is a digit", []any{revEntry("1", "retired", '1')}, "revocations[0].label"},
		{"a label that is a space", []any{revEntry(" ", "retired", '1')}, "revocations[0].label"},
		{"a label with a line feed", []any{revEntry("A\n", "retired", '1')}, "revocations[0].label"},
		{"a label of a name", []any{revEntry("root-a", "retired", '1')}, "revocations[0].label"},
		{"a reason in capitals", []any{revEntry("A", "Retired", '1')}, "revocations[0].reason"},
		{"a reason that is another word", []any{revEntry("A", "revoked", '1')}, "revocations[0].reason"},
		{"a reason with an underscore", []any{revEntry("A", "root_removal", '1')}, "revocations[0].reason"},
		{"a reason with a space", []any{revEntry("A", "no reason", '1')}, "revocations[0].reason"},
		{"a reason that ends in a space", []any{revEntry("A", "retired ", '1')}, "revocations[0].reason"},
		{"a reason that is the code of the signature", []any{revEntry("A", "0", '1')}, "revocations[0].reason"},
		{"a digest of 63 characters", []any{map[string]any{"label": "A", "reason": "retired", "sha256": dg('1')[:63]}}, "revocations[0].sha256"},
		{"a digest of 65 characters", []any{map[string]any{"label": "A", "reason": "retired", "sha256": dg('1') + "1"}}, "revocations[0].sha256"},
		{"a digest in upper case", []any{map[string]any{"label": "A", "reason": "retired", "sha256": strings.ToUpper(dg('a'))}}, "revocations[0].sha256"},
		{"a digest that is not hexadecimal", []any{map[string]any{"label": "A", "reason": "retired", "sha256": strings.Repeat("g", 64)}}, "revocations[0].sha256"},
		{"a digest of 40 digits, a fingerprint", []any{map[string]any{"label": "A", "reason": "retired", "sha256": strings.Repeat("a", 40)}}, "revocations[0].sha256"},
		{"a digest with a prefix", []any{map[string]any{"label": "A", "reason": "retired", "sha256": "sha256:" + dg('a')}}, "revocations[0].sha256"},
		{"the fault is in the third entry", []any{revEntry("A", "retired", '1'), revEntry("B", "retired", '1'), revEntry("c", "retired", '1')}, "revocations[2].label"},
		{"the same pair twice", []any{revEntry("A", "retired", '1'), revEntry("A", "retired", '2')}, "revocations[1]"},
		{"the same entry twice", []any{revEntry("A", "root-removal", '1'), revEntry("B", "retired", '1'), revEntry("A", "root-removal", '1')}, "revocations[2]"},
		{"an empty list", []any{}, "revocations"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := revRead(t, c.list)
			if r != nil || err == nil {
				t.Fatalf("the record is read: %+v, %v", r, err)
			}
			wantMember(t, err, c.member)
			refused(t, err)
		})
	}
}

func TestARecordWithAnEntryThatStrictjsonRefusesIsRefused(t *testing.T) {
	cases := map[string]any{
		"an unknown member":         []any{map[string]any{"label": "A", "reason": "retired", "sha256": dg('1'), "path": "x"}},
		"an unknown member, a note": []any{map[string]any{"label": "A", "reason": "retired", "sha256": dg('1'), "signature": "AAAA"}},
		"a label that is null":      []any{map[string]any{"label": nil, "reason": "retired", "sha256": dg('1')}},
		"a digest that is null":     []any{map[string]any{"label": "A", "reason": "retired", "sha256": nil}},
		"a label that is a number":  []any{map[string]any{"label": 1, "reason": "retired", "sha256": dg('1')}},
		"a reason that is a list":   []any{map[string]any{"label": "A", "reason": []any{"retired"}, "sha256": dg('1')}},
		"a digest that is a number": []any{map[string]any{"label": "A", "reason": "retired", "sha256": 1}},
		"an entry that is a string": []any{"A retired"},
		"an entry that is null":     []any{nil},
		"an entry that is a list":   []any{[]any{"A", "retired", dg('1')}},
		"an entry that is a number": []any{1},
		"null":                      nil,
		"a string":                  "A",
		"an object":                 map[string]any{"A": map[string]any{"retired": dg('1')}},
		"an object of the entry":    revEntry("A", "retired", '1'),
		"a number":                  1,
		"true":                      true,
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := revRead(t, v)
			if r != nil || err == nil {
				t.Fatalf("the record is read: %+v, %v", r, err)
			}
			refused(t, err)
		})
	}
}

func TestARecordWithAMemberOfAnEntryTwiceIsRefused(t *testing.T) {
	b := encode(t, applyDoc(), set("revocations", []any{revEntry("A", "retired", '1')}))
	for _, dup := range []string{`"label":"B"`, `"reason":"compromised"`, `"sha256":"` + dg('2') + `"`} {
		text := strings.Replace(string(b), `"label":"A"`, `"label":"A",`+dup, 1)
		r, err := files.ReadRecord([]byte(text))
		if r != nil || !errors.Is(err, strictjson.ErrMalformed) {
			t.Errorf("a member twice (%s): %+v, %v", dup, r, err)
		}
	}
}

func TestARecordTakesAtMostAHundredAndThirtyEntries(t *testing.T) {
	if files.MaxRevocations != 5*26 {
		t.Fatalf("MaxRevocations = %d, want 130: 5 for each of 26 labels", files.MaxRevocations)
	}
	all := func(n int) []any {
		var list []any
		for l := 0; l < 26 && len(list) < n; l++ {
			for _, reason := range []string{"root-removal", "compromised", "superseded", "retired", "no-reason"} {
				if len(list) == n {
					break
				}
				list = append(list, revEntry(string(rune('A'+l)), reason, byte('0'+len(list)%10)))
			}
		}
		return list
	}
	if r, err := revRead(t, all(130)); err != nil || len(r.Revocations) != 130 {
		t.Fatalf("130 entries: %v", err)
	}
	// The 131st entry is a pair that was already listed: the count is what is refused.
	over := append(all(130), revEntry("A", "root-removal", '1'))
	r, err := revRead(t, over)
	if r != nil || err == nil {
		t.Fatalf("131 entries are read: %v", err)
	}
	wantMember(t, err, "revocations")
	if !strings.Contains(err.Error(), "131") {
		t.Errorf("the error does not say the count: %v", err)
	}
	// 131 whole entries of a form that no rule of the entry refuses, one with a fault last: the
	// count is judged before an entry is looked at.
	bad := append(all(130), revEntry("a", "x", '1'))
	if _, err := revRead(t, bad); err == nil || !strings.Contains(err.Error(), "131") {
		t.Errorf("the count is not judged first: %v", err)
	}
	// Two thousand entries fit in the size that a reader takes, and are refused for their number.
	var many []any
	for i := 0; i < 2000; i++ {
		many = append(many, revEntry(string(rune('A'+i%26)), "retired", '1'))
	}
	if r, err := revRead(t, many); r != nil || err == nil {
		t.Errorf("2000 entries are read: %v", err)
	} else {
		refused(t, err)
	}
}

func TestARecordThatIsNotACompletedApplyHasNoRevocations(t *testing.T) {
	list := []any{revEntry("A", "root-removal", '1')}
	for name, doc := range map[string]map[string]any{"a declined record": declineDoc(), "a closing record": closeDoc()} {
		doc["revocations"] = list
		r, err := files.ReadRecord(encode(t, doc, nil))
		if r != nil || err == nil {
			t.Errorf("%s with a list is read: %v", name, err)
			continue
		}
		wantMember(t, err, "revocations")
		refused(t, err)
	}
	// The same through the writer: Canonical does not judge a record (the folder reads its bytes back
	// with ReadRecord before it writes them), so the bytes of such a record are refused by the reader.
	closing := &files.Record{Version: 1, Ceremony: "c-close", Command: "close", Outcome: "closed", TranscriptSHA256: dg('3'),
		Artifacts: []files.FileRef{}, Closes: &files.Closes{Ceremony: "c", AttemptSHA256: dg('6'), Reason: "stopped"},
		Revocations: []files.RevocationEntry{{Label: "A", Reason: "retired", SHA256: dg('1')}}}
	declining := &files.Record{Version: 1, Ceremony: "c", Command: "apply", Outcome: "declined", PlanSHA256: dg('1'), TranscriptSHA256: dg('3'),
		Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}, Artifacts: []files.FileRef{},
		Declined:    &files.Declined{Stem: "alice", Reason: "no"},
		Revocations: []files.RevocationEntry{{Label: "A", Reason: "retired", SHA256: dg('1')}}}
	for name, r := range map[string]*files.Record{"closing": closing, "declining": declining} {
		b, err := r.Canonical()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, err := files.ReadRecord(b); got != nil || err == nil {
			t.Errorf("%s: the reader takes %s: %v", name, b, err)
		}
	}
}

func TestTheBytesOfARecordWithABadListAreRefusedByTheReader(t *testing.T) {
	base := func(list []files.RevocationEntry) *files.Record {
		return &files.Record{Version: 1, Ceremony: "c", Command: "apply", Outcome: "completed", PlanSHA256: dg('1'), TranscriptSHA256: dg('3'),
			Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}, Artifacts: []files.FileRef{}, Revocations: list}
	}
	ok := files.RevocationEntry{Label: "A", Reason: "retired", SHA256: dg('1')}
	good, err := base([]files.RevocationEntry{ok}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := files.ReadRecord(good); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	cases := map[string][]files.RevocationEntry{
		"a missing label":  {{Reason: "retired", SHA256: dg('1')}},
		"a missing reason": {{Label: "A", SHA256: dg('1')}},
		"a missing digest": {{Label: "A", Reason: "retired"}},
		"a bad label":      {{Label: "a", Reason: "retired", SHA256: dg('1')}},
		"a bad reason":     {{Label: "A", Reason: "gone", SHA256: dg('1')}},
		"a bad digest":     {{Label: "A", Reason: "retired", SHA256: "x"}},
		"a pair twice":     {ok, ok},
		"a list too long":  make([]files.RevocationEntry, files.MaxRevocations+1),
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			b, err := base(list).Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if r, err := files.ReadRecord(b); r != nil || err == nil {
				t.Errorf("the reader takes %.200s: %v", b, err)
			}
		})
	}
}

func TestCheckRevocationEntryJudgesTheFormOfOneEntry(t *testing.T) {
	for _, reason := range []string{"compromised", "superseded", "retired", "no-reason", "root-removal"} {
		for _, label := range []string{"A", "M", "Z"} {
			if err := files.CheckRevocationEntry(files.RevocationEntry{Label: label, Reason: reason, SHA256: dg('f')}); err != nil {
				t.Errorf("label %s reason %s: %v", label, reason, err)
			}
		}
	}
	cases := []struct {
		name   string
		e      files.RevocationEntry
		member string
	}{
		{"the zero entry", files.RevocationEntry{}, "revocations.label"},
		{"no label", files.RevocationEntry{Reason: "retired", SHA256: dg('1')}, "revocations.label"},
		{"a label of two letters", files.RevocationEntry{Label: "AA", Reason: "retired", SHA256: dg('1')}, "revocations.label"},
		{"a lower-case label", files.RevocationEntry{Label: "a", Reason: "retired", SHA256: dg('1')}, "revocations.label"},
		{"a label that is a multi-byte letter", files.RevocationEntry{Label: "Ä", Reason: "retired", SHA256: dg('1')}, "revocations.label"},
		{"no reason", files.RevocationEntry{Label: "A", SHA256: dg('1')}, "revocations.reason"},
		{"a bad reason", files.RevocationEntry{Label: "A", Reason: "other", SHA256: dg('1')}, "revocations.reason"},
		{"no digest", files.RevocationEntry{Label: "A", Reason: "retired"}, "revocations.sha256"},
		{"a bad digest", files.RevocationEntry{Label: "A", Reason: "retired", SHA256: dg('A')}, "revocations.sha256"},
		{"a digest of 63 digits", files.RevocationEntry{Label: "A", Reason: "retired", SHA256: dg('a')[:63]}, "revocations.sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := files.CheckRevocationEntry(c.e)
			if err == nil {
				t.Fatal("the entry is accepted")
			}
			wantMember(t, err, c.member)
			if text := err.Error(); !printableASCII(text) {
				t.Errorf("the text holds a byte beyond printable ASCII: %q", text)
			}
		})
	}
}

func TestTheReasonWordsOfTheRevocationsAreThoseOfThePage(t *testing.T) {
	want := map[string]string{
		files.ReasonCompromised: "compromised", files.ReasonSuperseded: "superseded", files.ReasonRetired: "retired",
		files.ReasonNoReason: "no-reason", files.ReasonRootRemoval: "root-removal",
	}
	for got, w := range want {
		if got != w {
			t.Errorf("constant %q, the page says %q", got, w)
		}
	}
	if len(want) != 5 {
		t.Errorf("%d distinct words, want 5", len(want))
	}
}

func TestEveryRevocationEntryOfARecordIsOneLineOfTheRecordAndHoldsNoSignature(t *testing.T) {
	// An entry has exactly the three members of the page: a writer cannot add a place for the
	// material or the material itself (record 0007, rule 23).
	typ := reflect.TypeOf(files.RevocationEntry{})
	var tags []string
	for i := 0; i < typ.NumField(); i++ {
		tags = append(tags, typ.Field(i).Tag.Get("json"))
	}
	if !reflect.DeepEqual(tags, []string{"label", "reason", "sha256"}) {
		t.Errorf("the entry has the members %v, the page gives label, reason and sha256", tags)
	}
	r := &files.Record{Version: 1, Ceremony: "c", Command: "apply", Outcome: "completed", PlanSHA256: dg('1'), TranscriptSHA256: dg('3'),
		Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}, Artifacts: []files.FileRef{},
		Revocations: []files.RevocationEntry{{Label: "A", Reason: "retired", SHA256: dg('1')}}}
	b, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(b, []byte(`"label"`)); n != 1 {
		t.Errorf("the record holds %d labels: %s", n, b)
	}
}

// The limit of a record's list is the one that the writer of part 14e will use: 5 for each label.
func TestTheMostRevocationsAreFiveForEachOfTheTwentySixLabels(t *testing.T) {
	if got := fmt.Sprint(files.MaxRevocations); got != "130" {
		t.Errorf("MaxRevocations = %s", got)
	}
}
