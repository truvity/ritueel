package files_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/strictjson"
)

func TestReadRecordTakesTheThreeKindsOfRecord(t *testing.T) {
	t.Run("apply", func(t *testing.T) {
		r, err := files.ReadRecord(encode(t, applyDoc(), nil))
		if err != nil {
			t.Fatal(err)
		}
		if r.Version != 1 || r.Ceremony != "20261114T100000Z-apply" || r.Command != "apply" || r.Outcome != "completed" {
			t.Errorf("the head of the record is wrong: %+v", r)
		}
		if r.PlanSHA256 != dg('1') || r.PrevRecordSHA256 != dg('2') || r.TranscriptSHA256 != dg('3') {
			t.Errorf("a digest is wrong: %+v", r)
		}
		if !reflect.DeepEqual(r.Wanted, []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}) {
			t.Errorf("wanted = %+v", r.Wanted)
		}
		if !reflect.DeepEqual(r.Artifacts, []files.FileRef{{Path: "trust/1-3fa9c1d2/root-list.json", SHA256: dg('5')}}) {
			t.Errorf("artifacts = %+v", r.Artifacts)
		}
		if r.Closes != nil || r.Declined != nil {
			t.Errorf("closes or declined is set in a record that has neither: %+v", r)
		}
	})
	t.Run("close", func(t *testing.T) {
		r, err := files.ReadRecord(encode(t, closeDoc(), nil))
		if err != nil {
			t.Fatal(err)
		}
		if r.Command != "close" || r.Outcome != "closed" {
			t.Errorf("the head of the record is wrong: %+v", r)
		}
		want := &files.Closes{Ceremony: "20261114T100000Z-apply", AttemptSHA256: dg('6'), Reason: "the card was lost"}
		if !reflect.DeepEqual(r.Closes, want) {
			t.Errorf("closes = %+v, want %+v", r.Closes, want)
		}
		if r.Artifacts == nil || len(r.Artifacts) != 0 {
			t.Errorf("an empty list of artifacts is read as %#v, want an empty list that is not nil", r.Artifacts)
		}
	})
	t.Run("declined", func(t *testing.T) {
		r, err := files.ReadRecord(encode(t, declineDoc(), nil))
		if err != nil {
			t.Fatal(err)
		}
		if r.Outcome != "declined" || r.Declined == nil || r.Declined.Stem != "alice" || r.Declined.Reason != "not today" {
			t.Errorf("declined = %+v, outcome %q", r.Declined, r.Outcome)
		}
	})
}

func TestReadRecordTakesEveryMemberOfThePage(t *testing.T) {
	m := applyDoc()
	m["arguments"] = map[string]any{"with": []any{"card-a"}}
	m["started_at"] = "2026-11-14T10:00:00Z"
	m["finished_at"] = "2026-11-14T10:05:00Z"
	m["root"] = map[string]any{"label": "root-a", "store": "piv", "x509": dg('a'), "openpgp": strings.Repeat("b", 40), "test": true, "copyable": true}
	m["root_reason"] = "the card of the year was lost"
	m["slot_map_version"] = 2
	m["confirmation"] = map[string]any{"by": "typed", "at": "2026-11-14T10:01:00Z"}
	m["ran_on"] = "workstation"
	m["limit_shown"] = true
	m["requests"] = []any{map[string]any{"stem": "alice", "type": "csr"}}
	m["applied"] = []any{map[string]any{"object": "alice"}}
	m["left_out"] = []any{map[string]any{"object": "bob", "reason": "later"}}
	m["signatures"] = []any{map[string]any{"n": 1, "kind": "root-certificate"}}
	m["trust_sequence"] = 1
	m["advisory_review"] = map[string]any{"at": "2026-11-14T10:02:00Z", "note": "read them"}
	m["revocations"] = []any{map[string]any{"label": "a", "reason": "retired", "sha256": dg('c')}}
	r, err := files.ReadRecord(encode(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		ok   bool
	}{
		{"arguments", string(r.Arguments) == `{"with":["card-a"]}`},
		{"started_at", r.StartedAt == "2026-11-14T10:00:00Z"},
		{"finished_at", r.FinishedAt == "2026-11-14T10:05:00Z"},
		{"root", r.Root != nil && r.Root.Label == "root-a" && r.Root.Store == "piv" && r.Root.X509 == dg('a') && r.Root.OpenPGP == strings.Repeat("b", 40) && r.Root.Test && r.Root.Copyable},
		{"root_reason", r.RootReason == "the card of the year was lost"},
		{"slot_map_version", r.SlotMapVersion == 2},
		{"confirmation", r.Confirmation != nil && r.Confirmation.By == "typed" && r.Confirmation.At == "2026-11-14T10:01:00Z"},
		{"ran_on", r.RanOn == "workstation"},
		{"limit_shown", r.LimitShown},
		{"requests", len(r.Requests) == 1},
		{"applied", len(r.Applied) == 1},
		{"left_out", len(r.LeftOut) == 1},
		{"signatures", len(r.Signatures) == 1},
		{"trust_sequence", r.TrustSequence == 1},
		{"advisory_review", r.AdvisoryReview != nil && r.AdvisoryReview.Note == "read them" && r.AdvisoryReview.At == "2026-11-14T10:02:00Z"},
		{"revocations", len(r.Revocations) == 1},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("member %s was not read: %+v", c.name, r)
		}
	}
}

func TestReadRecordWantsEveryRequiredMember(t *testing.T) {
	cases := []struct {
		name   string
		doc    func() map[string]any
		remove string
	}{
		{"version", applyDoc, "version"},
		{"ceremony", applyDoc, "ceremony"},
		{"command", applyDoc, "command"},
		{"outcome", applyDoc, "outcome"},
		{"transcript_sha256", applyDoc, "transcript_sha256"},
		{"artifacts", applyDoc, "artifacts"},
		{"wanted of apply", applyDoc, "wanted"},
		{"closes of close", closeDoc, "closes"},
		{"ceremony of close", closeDoc, "ceremony"},
		{"outcome of close", closeDoc, "outcome"},
		{"transcript_sha256 of close", closeDoc, "transcript_sha256"},
		{"artifacts of close", closeDoc, "artifacts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := files.ReadRecord(encode(t, c.doc(), without(c.remove)))
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v (%T), want a *FormatError", err, err)
			}
			if fe.Member != c.remove || fe.What != "ceremony record" {
				t.Errorf("FormatError{What %q, Member %q}, want member %q of a ceremony record", fe.What, fe.Member, c.remove)
			}
		})
	}
}

// A member that is required and empty is a fault of that member, however the reader words it.
func TestReadRecordRefusesAnEmptyRequiredText(t *testing.T) {
	for _, name := range []string{"ceremony", "command", "outcome", "transcript_sha256"} {
		_, err := files.ReadRecord(encode(t, applyDoc(), set(name, "")))
		var fe *files.FormatError
		if !errors.As(err, &fe) || fe.Member != name {
			t.Errorf("%s = \"\": err = %v, want a *FormatError for the member", name, err)
		}
	}
}

func TestReadRecordNamesTheMemberThatBreaksARule(t *testing.T) {
	cases := []struct {
		name   string
		doc    func() map[string]any
		edit   func(map[string]any)
		member string
	}{
		// Plain names of a ceremony folder.
		{"ceremony with a space", applyDoc, set("ceremony", "a b"), "ceremony"},
		{"ceremony that is a temporary name", applyDoc, set("ceremony", ".rt-abcdefghijk"), "ceremony"},
		{"ceremony of 256 bytes", applyDoc, set("ceremony", strings.Repeat("a", 256)), "ceremony"},
		{"ceremony with a slash", applyDoc, set("ceremony", "a/b"), "ceremony"},
		{"ceremony with dot dot", applyDoc, set("ceremony", ".."), "ceremony"},
		{"ceremony with a Cyrillic look-alike", applyDoc, set("ceremony", "a"+string(rune(0x430))), "ceremony"},
		{"ceremony with an escape", applyDoc, set("ceremony", "a\x1b[31m"), "ceremony"},
		// The two commands and the three outcomes.
		{"command run", applyDoc, set("command", "run"), "command"},
		{"command in capitals", applyDoc, set("command", "Apply"), "command"},
		{"command join", applyDoc, set("command", "join"), "command"},
		{"command revoke", applyDoc, set("command", "revoke"), "command"},
		{"outcome done", applyDoc, set("outcome", "done"), "outcome"},
		{"outcome refused", applyDoc, set("outcome", "refused"), "outcome"},
		{"outcome in capitals", applyDoc, set("outcome", "Completed"), "outcome"},
		// Digests.
		{"plan digest in capitals", applyDoc, set("plan_sha256", strings.ToUpper(dg('a'))), "plan_sha256"},
		{"plan digest of 63 characters", applyDoc, set("plan_sha256", dg('a')[:63]), "plan_sha256"},
		{"prev digest of 65 characters", applyDoc, set("prev_record_sha256", dg('a')+"a"), "prev_record_sha256"},
		{"prev digest that is not hexadecimal", applyDoc, set("prev_record_sha256", strings.Repeat("g", 64)), "prev_record_sha256"},
		{"transcript digest with a prefix", applyDoc, set("transcript_sha256", "sha256:"+dg('a')[:57]), "transcript_sha256"},
		// Times.
		{"started_at with a fraction", applyDoc, set("started_at", "2026-11-14T10:00:00.5Z"), "started_at"},
		{"finished_at with an offset", applyDoc, set("finished_at", "2026-11-14T10:00:00+01:00"), "finished_at"},
		{"started_at that is a date", applyDoc, set("started_at", "2026-11-14"), "started_at"},
		{"confirmation time", applyDoc, set("confirmation", map[string]any{"by": "typed", "at": "yesterday"}), "confirmation.at"},
		{"confirmation by", applyDoc, set("confirmation", map[string]any{"by": "click", "at": "2026-11-14T10:00:00Z"}), "confirmation.by"},
		{"advisory time", applyDoc, set("advisory_review", map[string]any{"at": "2026-11-14T10:00:00", "note": "x"}), "advisory_review.at"},
		// The lists of files.
		{"artifact path up", applyDoc, setEntry("artifacts", 0, "path", "../x"), "artifacts[0].path"},
		{"artifact path absolute", applyDoc, setEntry("artifacts", 0, "path", "/etc/hosts"), "artifacts[0].path"},
		{"artifact path with a backslash", applyDoc, setEntry("artifacts", 0, "path", "a"+string(rune(0x5c))+"b"), "artifacts[0].path"},
		{"artifact path empty", applyDoc, setEntry("artifacts", 0, "path", ""), "artifacts[0].path"},
		{"artifact path missing", applyDoc, delEntry("artifacts", 0, "path"), "artifacts[0].path"},
		{"artifact digest in capitals", applyDoc, setEntry("artifacts", 0, "sha256", strings.ToUpper(dg('a'))), "artifacts[0].sha256"},
		{"artifact digest missing", applyDoc, delEntry("artifacts", 0, "sha256"), "artifacts[0].sha256"},
		{"wanted path with a temporary folder", applyDoc, setEntry("wanted", 0, "path", "a/.rt-x/b"), "wanted[0].path"},
		{"wanted path with a device name", applyDoc, setEntry("wanted", 0, "path", "aux"), "wanted[0].path"},
		{"wanted digest short", applyDoc, setEntry("wanted", 0, "sha256", "abc"), "wanted[0].sha256"},
		{"the second artifact is the bad one", applyDoc, func(m map[string]any) {
			m["artifacts"] = append(m["artifacts"].([]any), ref("a b", '8'))
		}, "artifacts[1].path"},
		// What the table says is present in some records only.
		{"declined in a completed record", applyDoc, set("declined", map[string]any{"stem": "a", "reason": "b"}), "declined"},
		{"closes in an apply record", applyDoc, set("closes", map[string]any{"ceremony": "x", "attempt_sha256": dg('a'), "reason": "r"}), "closes"},
		{"outcome closed in an apply record", applyDoc, set("outcome", "closed"), "outcome"},
		{"outcome completed in a closing record", closeDoc, set("outcome", "completed"), "outcome"},
		{"outcome declined in a closing record", closeDoc, set("outcome", "declined"), "outcome"},
		{"plan digest in a closing record", closeDoc, set("plan_sha256", dg('a')), "plan_sha256"},
		{"root in a closing record", closeDoc, set("root", map[string]any{"label": "a"}), "root"},
		{"root reason in a closing record", closeDoc, set("root_reason", "x"), "root_reason"},
		{"closes ceremony with a slash", closeDoc, setIn("closes", "ceremony", "a/b"), "closes.ceremony"},
		{"closes ceremony that is a temporary name", closeDoc, setIn("closes", "ceremony", ".RT-x"), "closes.ceremony"},
		{"closes digest in capitals", closeDoc, setIn("closes", "attempt_sha256", strings.ToUpper(dg('a'))), "closes.attempt_sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := files.ReadRecord(encode(t, c.doc(), c.edit))
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v (%T), want a *FormatError", err, err)
			}
			if fe.What != "ceremony record" || fe.Member != c.member {
				t.Errorf("FormatError{What %q, Member %q}, want member %q of a ceremony record", fe.What, fe.Member, c.member)
			}
			if fe.Reason == "" || !printableASCII(err.Error()) {
				t.Errorf("the error %q has no reason or is not printable ASCII", err)
			}
		})
	}
}

func TestReadRecordRefusesWhatTheJSONRulesRefuse(t *testing.T) {
	base := encode(t, applyDoc(), nil)
	dup := strings.Replace(string(base), "{", `{"command":"apply",`, 1)
	dupMiddle := strings.Replace(string(base), `"outcome":"completed"`, `"outcome":"completed","outcome":"completed"`, 1)
	surrogate := strings.Replace(string(base), `"ceremony":"20261114T100000Z-apply"`, `"ceremony":"`+string(rune(0x5c))+`ud800"`, 1)
	badUTF8 := bytes.Replace(base, []byte(`"20261114T100000Z-apply"`), []byte("\"a\xffb\""), 1)
	cases := map[string][]byte{
		"empty":                       nil,
		"white space only":            []byte(" \n"),
		"not JSON":                    []byte("garbage"),
		"a list":                      []byte("[]"),
		"a string":                    []byte(`"x"`),
		"null":                        []byte("null"),
		"two objects":                 append(append([]byte{}, base...), base...),
		"something after the object":  append(append([]byte{}, base...), 'x'),
		"cut short":                   base[:len(base)-1],
		"a byte order mark":           append([]byte("\xef\xbb\xbf"), base...),
		"bytes that are not UTF-8":    badUTF8,
		"a lone surrogate escape":     []byte(surrogate),
		"a repeated member":           []byte(dup),
		"a repeated member inside":    []byte(dupMiddle),
		"an unknown member":           encode(t, applyDoc(), set("extra", 1)),
		"an unknown member in a ref":  encode(t, applyDoc(), setEntry("artifacts", 0, "extra", 1)),
		"an unknown member in root":   encode(t, applyDoc(), set("root", map[string]any{"colour": "red"})),
		"a name in capitals":          encode(t, applyDoc(), set("Ceremony", "x")),
		"null for a text":             []byte(strings.Replace(string(base), `"ceremony":"20261114T100000Z-apply"`, `"ceremony":null`, 1)),
		"null for the list":           []byte(strings.Replace(string(base), `"artifacts":[{`, `"artifacts":null,"x":[{`, 1)),
		"a number for a text":         encode(t, applyDoc(), set("ceremony", 1)),
		"a text for the list":         encode(t, applyDoc(), set("artifacts", "x")),
		"an object for the list":      encode(t, applyDoc(), set("wanted", map[string]any{})),
		"a text for a bool":           encode(t, applyDoc(), set("limit_shown", "true")),
		"a number for a bool":         encode(t, applyDoc(), set("limit_shown", 1)),
		"a text for an integer":       encode(t, applyDoc(), set("trust_sequence", "1")),
		"a fraction":                  encode(t, applyDoc(), set("slot_map_version", 1.5)),
		"a fraction that is whole":    []byte(strings.Replace(string(base), `"version":1`, `"version":1,"trust_sequence":1.0`, 1)),
		"an exponent":                 []byte(strings.Replace(string(base), `"version":1`, `"version":1,"trust_sequence":1e2`, 1)),
		"2^53":                        encode(t, applyDoc(), set("trust_sequence", int64(1)<<53)),
		"minus 2^53":                  encode(t, applyDoc(), set("trust_sequence", -(int64(1)<<53))),
		"a number beyond 64 bits":     []byte(strings.Replace(string(base), `"version":1`, `"version":1,"trust_sequence":99999999999999999999`, 1)),
		"a leading zero":              []byte(strings.Replace(string(base), `"version":1`, `"version":1,"trust_sequence":01`, 1)),
		"a plus sign":                 []byte(strings.Replace(string(base), `"version":1`, `"version":1,"trust_sequence":+1`, 1)),
		"arguments that is a list":    encode(t, applyDoc(), set("arguments", []any{})),
		"arguments that is a text":    encode(t, applyDoc(), set("arguments", "x")),
		"a document of 256 KiB + 1":   padArguments(t, applyDoc(), 256<<10+1),
		"nesting of 10001 levels":     deepArguments(t, applyDoc(), 10001),
		"nesting of 20000 levels":     deepArguments(t, applyDoc(), 20000),
		"a member that is not a name": []byte(strings.Replace(string(base), `"version"`, `"ver sion"`, 1)),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := files.ReadRecord(in)
			if err == nil {
				t.Fatalf("accepted: %+v", r)
			}
			var ve *files.VersionError
			if errors.As(err, &ve) {
				t.Fatalf("a *VersionError for a document of version 1: %v", err)
			}
			if !errors.Is(err, strictjson.ErrMalformed) {
				var fe *files.FormatError
				if !errors.As(err, &fe) {
					t.Errorf("the error is %T: %v; want one that wraps ErrMalformed", err, err)
				}
			}
			if r != nil {
				t.Errorf("a record is returned with an error: %+v", r)
			}
			if !printableASCII(err.Error()) {
				t.Errorf("the error text %.200q is not printable ASCII", err)
			}
		})
	}
}

// deepArguments is a record whose member arguments nests so that the whole document is depth levels deep.
func deepArguments(t testing.TB, base map[string]any, depth int) []byte {
	t.Helper()
	enc := encode(t, base, nil)
	// The record is level 1 and the object arguments is level 2, so the chain below has depth-1 levels.
	chain := strings.Repeat(`{"a":`, depth-2) + `{}` + strings.Repeat(`}`, depth-2)
	return append(bytes.TrimSuffix(enc, []byte("}")), []byte(`,"arguments":`+chain+`}`)...)
}

func TestReadRecordSizeAndDepthLimitsHoldToTheByte(t *testing.T) {
	const size = 256 << 10
	r, err := files.ReadRecord(padArguments(t, applyDoc(), size))
	if err != nil {
		t.Fatalf("a record of exactly 256 KiB: %v", err)
	}
	if len(r.Arguments) == 0 {
		t.Error("arguments of a record of 256 KiB is empty")
	}
	if _, err := files.ReadRecord(padArguments(t, applyDoc(), size+1)); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("a record of 256 KiB + 1: err = %v, want ErrMalformed", err)
	}
	if _, err := files.ReadRecord(deepArguments(t, applyDoc(), 10000)); err != nil {
		t.Errorf("a record 10,000 levels deep: %v", err)
	}
	if _, err := files.ReadRecord(deepArguments(t, applyDoc(), 10001)); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("a record 10,001 levels deep: err = %v, want ErrMalformed", err)
	}
}

func TestReadRecordIntegersAtTheEdgeOfTheSafeRange(t *testing.T) {
	const max = 1<<53 - 1
	for _, n := range []int64{max, -max, 0, 1} {
		r, err := files.ReadRecord(encode(t, applyDoc(), set("trust_sequence", n)))
		if err != nil {
			t.Errorf("trust_sequence %d: %v", n, err)
		} else if r.TrustSequence != n {
			t.Errorf("trust_sequence %d is read as %d", n, r.TrustSequence)
		}
	}
	// The page: -0 is read as 0.
	in := strings.Replace(string(encode(t, applyDoc(), nil)), `"version":1`, `"version":1,"trust_sequence":-0`, 1)
	r, err := files.ReadRecord([]byte(in))
	if err != nil {
		t.Fatalf("-0: %v", err)
	}
	if r.TrustSequence != 0 {
		t.Errorf("-0 is read as %d", r.TrustSequence)
	}
	if ok, err := canonjson.IsCanonical([]byte(in)); err != nil || ok {
		t.Errorf("a document with -0: IsCanonical = %v, %v; want false", ok, err)
	}
}

func TestReadRecordReadsTheVersionFirstAndAlone(t *testing.T) {
	// Beside a version it does not know, a document holds what version 1 would refuse: an unknown
	// member, a repeated member, null, a wrong type, a member in the wrong form.
	v2 := func(rest string) []byte { return []byte(`{"version":2` + rest + `}`) }
	for name, in := range map[string][]byte{
		"only the version":      v2(""),
		"an unknown member":     v2(`,"x":{}`),
		"a repeated member":     v2(`,"x":1,"x":2`),
		"null":                  v2(`,"ceremony":null`),
		"a wrong type":          v2(`,"ceremony":5,"artifacts":"x"`),
		"a fraction":            v2(`,"slot_map_version":1.5`),
		"a bad digest":          v2(`,"plan_sha256":"abc"`),
		"a member of version 1": v2(`,"ceremony":"a b","command":"run"`),
		"white space around":    []byte(" \n" + `{"version":2}` + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := files.ReadRecord(in)
			var ve *files.VersionError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v (%T), want a *VersionError", err, err)
			}
			if r != nil {
				t.Errorf("a record is returned: %+v", r)
			}
			if ve.Version != 2 || ve.What != "ceremony record" {
				t.Errorf("VersionError{%q, %d}, want a ceremony record of version 2", ve.What, ve.Version)
			}
			if !strings.Contains(err.Error(), "2") {
				t.Errorf("the text %q does not name the version", err)
			}
		})
	}
}

func TestReadRecordNamesEveryVersionThatIsNotOne(t *testing.T) {
	cases := []struct {
		text string
		want int64
	}{
		{"2", 2}, {"0", 0}, {"-1", -1}, {"1000", 1000}, {"-0", 0},
		{"9007199254740991", 9007199254740991}, {"-9007199254740991", -9007199254740991},
	}
	for _, c := range cases {
		_, err := files.ReadRecord([]byte(`{"version":` + c.text + `}`))
		var ve *files.VersionError
		if !errors.As(err, &ve) || ve.Version != c.want {
			t.Errorf("version %s: err = %v, want a *VersionError for %d", c.text, err, c.want)
		}
	}
}

func TestReadRecordRefusesAVersionThatIsNotAnInteger(t *testing.T) {
	cases := map[string]string{
		"a text":                `{"version":"1"}`,
		"a fraction":            `{"version":1.0}`,
		"a half":                `{"version":1.5}`,
		"an exponent":           `{"version":1e0}`,
		"null":                  `{"version":null}`,
		"true":                  `{"version":true}`,
		"a list":                `{"version":[1]}`,
		"an object":             `{"version":{}}`,
		"2^53":                  `{"version":9007199254740992}`,
		"minus 2^53":            `{"version":-9007199254740992}`,
		"repeated":              `{"version":1,"version":1}`,
		"repeated, other value": `{"version":1,"version":2}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := files.ReadRecord([]byte(in))
			if err == nil {
				t.Fatalf("accepted: %+v", r)
			}
			var ve *files.VersionError
			if errors.As(err, &ve) {
				t.Errorf("a *VersionError (%d) for a version that is no integer", ve.Version)
			}
		})
	}
	// A missing version is a fault of the member.
	for _, in := range []string{`{}`, `{"ceremony":"a"}`} {
		_, err := files.ReadRecord([]byte(in))
		var fe *files.FormatError
		if !errors.As(err, &fe) || fe.Member != "version" {
			t.Errorf("%s: err = %v, want a *FormatError for version", in, err)
		}
	}
}

func TestReadRecordNeverHoldsRawBytesFromTheDocumentInAnError(t *testing.T) {
	hostile := []string{
		"a\x1b[31mred",
		"a" + string(rune(0x430)) + "b",
		"a" + string(rune(0x202e)) + "b",
		"line\nbreak",
		strings.Repeat("long", 200),
		"\xff\xfe",
	}
	members := []string{"ceremony", "command", "outcome", "plan_sha256", "prev_record_sha256", "started_at", "transcript_sha256"}
	for _, h := range hostile {
		for _, member := range members {
			_, err := files.ReadRecord(encode(t, applyDoc(), set(member, h)))
			if err == nil {
				t.Errorf("%s = %.20q is accepted", member, h)
				continue
			}
			if !printableASCII(err.Error()) {
				t.Errorf("%s = %.20q: the error text %.120q is not printable ASCII", member, h, err)
			}
			if len(err.Error()) > 400 {
				t.Errorf("%s = %.20q: the error text is %d bytes long; it must not repeat a long input", member, h, len(err.Error()))
			}
		}
		_, err := files.ReadRecord(encode(t, applyDoc(), setEntry("artifacts", 0, "path", h)))
		if err == nil || !printableASCII(err.Error()) || len(err.Error()) > 400 {
			t.Errorf("artifact path %.20q: err = %.120q", h, err)
		}
	}
}

func TestRecordCanonicalIsTheCanonicalFormOfThePage(t *testing.T) {
	r := &files.Record{
		Version:          1,
		Ceremony:         "c",
		Command:          "apply",
		Outcome:          "completed",
		PlanSHA256:       dg('1'),
		TranscriptSHA256: dg('3'),
		Wanted:           []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}},
		Artifacts:        []files.FileRef{{Path: "a.txt", SHA256: dg('5')}},
	}
	got, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"artifacts":[{"path":"a.txt","sha256":` + q(dg('5')) + `}],"ceremony":"c","command":"apply","outcome":"completed",` +
		`"plan_sha256":` + q(dg('1')) + `,"transcript_sha256":` + q(dg('3')) + `,"version":1,` +
		`"wanted":[{"path":"ritueel.yaml","sha256":` + q(dg('4')) + `}]}`
	if string(got) != want {
		t.Errorf("Canonical:\n got %s\nwant %s", got, want)
	}
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Error("Canonical ends with a line break")
	}
	if ok, err := canonjson.IsCanonical(got); err != nil || !ok {
		t.Errorf("IsCanonical(Canonical) = %v, %v", ok, err)
	}
}

func q(s string) string { return `"` + s + `"` }

func TestRecordCanonicalWritesAnEmptyListOfArtifactsAndLeavesOutEmptyOptionals(t *testing.T) {
	r := &files.Record{Version: 1, Ceremony: "c", Command: "close", Outcome: "closed", TranscriptSHA256: dg('3'),
		Closes: &files.Closes{Ceremony: "a", AttemptSHA256: dg('6')}}
	got, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"artifacts":[]`)) {
		t.Errorf("a nil list of artifacts is not written as an empty list: %s", got)
	}
	for _, name := range []string{"wanted", "plan_sha256", "prev_record_sha256", "root", "declined", "requests", "started_at"} {
		if bytes.Contains(got, []byte(`"`+name+`"`)) {
			t.Errorf("an empty %s is written: %s", name, got)
		}
	}
	// The record is not changed by writing it.
	if r.Artifacts != nil {
		t.Error("Canonical changed the record: Artifacts is not nil any more")
	}
	if _, err := files.ReadRecord(got); err != nil {
		t.Errorf("the canonical bytes of a closing record are not read back: %v", err)
	}
}

func TestRecordRoundTripFromCanonicalToReadRecordAndBack(t *testing.T) {
	full := &files.Record{
		Version:          1,
		Ceremony:         "20261114T100000Z-apply",
		Command:          "apply",
		Arguments:        strictjson.Raw(`{"with":["card-a"]}`),
		Outcome:          "completed",
		PlanSHA256:       dg('1'),
		PrevRecordSHA256: dg('2'),
		StartedAt:        "2026-11-14T10:00:00Z",
		FinishedAt:       "2026-11-14T10:05:00Z",
		Root:             &files.PlanRoot{Label: "root-a", Store: "piv", X509: dg('a'), OpenPGP: strings.Repeat("b", 40), Test: true, Copyable: true},
		RootReason:       "lost",
		SlotMapVersion:   2,
		Confirmation:     &files.Confirmation{By: "flag", At: "2026-11-14T10:01:00Z"},
		RanOn:            "workstation",
		LimitShown:       true,
		Requests:         []any{map[string]any{"stem": "alice", "ok": true}},
		Wanted:           []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}},
		Applied:          []any{"x"},
		LeftOut:          []any{"y"},
		Signatures:       []any{map[string]any{"kind": "root-certificate"}},
		Artifacts:        []files.FileRef{{Path: "a/b.txt", SHA256: dg('5')}, {Path: "c", SHA256: dg('6')}},
		TrustSequence:    7,
		TranscriptSHA256: dg('3'),
		AdvisoryReview:   &files.Advisory{At: "2026-11-14T10:02:00Z", Note: "read"},
		Revocations:      []any{map[string]any{"label": "a"}},
	}
	closing := &files.Record{Version: 1, Ceremony: "c-close", Command: "close", Outcome: "closed", TranscriptSHA256: dg('3'),
		Artifacts: []files.FileRef{}, Closes: &files.Closes{Ceremony: "c", AttemptSHA256: dg('6'), Reason: "stopped"}}
	declining := &files.Record{Version: 1, Ceremony: "c", Command: "apply", Outcome: "declined", PlanSHA256: dg('1'), TranscriptSHA256: dg('3'),
		Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}, Artifacts: []files.FileRef{},
		Declined: &files.Declined{Stem: "alice", Reason: "no"}}
	for name, r := range map[string]*files.Record{"full": full, "closing": closing, "declining": declining} {
		t.Run(name, func(t *testing.T) {
			first, err := r.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := canonjson.IsCanonical(first); err != nil || !ok {
				t.Fatalf("IsCanonical = %v, %v", ok, err)
			}
			back, err := files.ReadRecord(first)
			if err != nil {
				t.Fatalf("ReadRecord(Canonical): %v", err)
			}
			if !reflect.DeepEqual(back, r) {
				t.Errorf("the record changed on the way:\n got %+v\nwant %+v", back, r)
			}
			second, err := back.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, second) {
				t.Errorf("the bytes changed on the way:\n%s\n%s", first, second)
			}
			if files.Digest(first) != files.Digest(second) {
				t.Error("the digest changed on the way")
			}
		})
	}
}
