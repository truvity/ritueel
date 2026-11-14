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

func TestReadAttemptTakesEveryMemberOfThePage(t *testing.T) {
	a, err := files.ReadAttempt(encode(t, attemptDoc(), nil))
	if err != nil {
		t.Fatal(err)
	}
	want := &files.Attempt{Version: 1, Ceremony: "20261114T100000Z-apply", PlanSHA256: dg('1'), Root: "root-a", StartedAt: "2026-11-14T10:00:00Z"}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	// Only version, ceremony and plan_sha256 are required.
	a, err = files.ReadAttempt(encode(t, attemptDoc(), without("root", "started_at")))
	if err != nil {
		t.Fatalf("an attempt with the three required members: %v", err)
	}
	if a.Root != "" || a.StartedAt != "" {
		t.Errorf("optional members appeared: %+v", a)
	}
}

func TestReadAttemptWantsItsRequiredMembersAndTheirForms(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(map[string]any)
		member string
	}{
		{"no version", without("version"), "version"},
		{"no ceremony", without("ceremony"), "ceremony"},
		{"no plan digest", without("plan_sha256"), "plan_sha256"},
		{"ceremony with a space", set("ceremony", "a b"), "ceremony"},
		{"ceremony that is a temporary name", set("ceremony", ".rt-abcdefghijk"), "ceremony"},
		{"ceremony of 256 bytes", set("ceremony", strings.Repeat("c", 256)), "ceremony"},
		{"plan digest in capitals", set("plan_sha256", strings.ToUpper(dg('a'))), "plan_sha256"},
		{"plan digest of 63 characters", set("plan_sha256", dg('a')[:63]), "plan_sha256"},
		{"time with a fraction", set("started_at", "2026-11-14T10:00:00.1Z"), "started_at"},
		{"time with an offset", set("started_at", "2026-11-14T10:00:00+00:00"), "started_at"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := files.ReadAttempt(encode(t, attemptDoc(), c.edit))
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v (%T), want a *FormatError", err, err)
			}
			if fe.What != "attempt" || fe.Member != c.member {
				t.Errorf("FormatError{%q, %q}, want member %q of an attempt", fe.What, fe.Member, c.member)
			}
		})
	}
}

func TestReadAttemptRefusesWhatTheJSONRulesRefuse(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":          nil,
		"unknown member": encode(t, attemptDoc(), set("extra", "x")),
		"repeated":       []byte(strings.Replace(string(encode(t, attemptDoc(), nil)), `"version":1`, `"version":1,"root":"x","root":"y"`, 1)),
		"null":           encode(t, attemptDoc(), set("root", nil)),
		"a number":       encode(t, attemptDoc(), set("ceremony", 5)),
		"a fraction":     []byte(`{"version":1.0,"ceremony":"a","plan_sha256":"` + dg('1') + `"}`),
		"bom":            append([]byte("\xef\xbb\xbf"), encode(t, attemptDoc(), nil)...),
		"bad UTF-8":      bytes.Replace(encode(t, attemptDoc(), nil), []byte("root-a"), []byte("r\xffa"), 1),
		"256 KiB + 1":    padAttempt(t, 256<<10+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := files.ReadAttempt(in)
			if !errors.Is(err, strictjson.ErrMalformed) {
				var fe *files.FormatError
				if !errors.As(err, &fe) {
					t.Errorf("err = %v (%T), want one that wraps ErrMalformed", err, err)
				}
			}
			if err == nil || !printableASCII(err.Error()) {
				t.Errorf("err = %.120q", err)
			}
		})
	}
}

// padAttempt is an attempt of exactly n bytes: the label of its root key holds the padding.
func padAttempt(t testing.TB, n int) []byte {
	t.Helper()
	probe := encode(t, attemptDoc(), set("root", ""))
	b := encode(t, attemptDoc(), set("root", strings.Repeat("r", n-len(probe))))
	if len(b) != n {
		t.Fatalf("padAttempt made %d bytes, want %d", len(b), n)
	}
	return b
}

func TestReadAttemptSizeLimitHoldsToTheByte(t *testing.T) {
	if _, err := files.ReadAttempt(padAttempt(t, 256<<10)); err != nil {
		t.Errorf("an attempt of 256 KiB: %v", err)
	}
	if _, err := files.ReadAttempt(padAttempt(t, 256<<10+1)); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("an attempt of 256 KiB + 1: err = %v", err)
	}
}

func TestReadAttemptReadsTheVersionFirstAndAlone(t *testing.T) {
	for _, in := range []string{`{"version":2}`, `{"version":2,"x":1,"x":2,"ceremony":7}`, `{"version":0,"plan_sha256":null}`} {
		_, err := files.ReadAttempt([]byte(in))
		var ve *files.VersionError
		if !errors.As(err, &ve) || ve.What != "attempt" {
			t.Errorf("%s: err = %v, want a *VersionError of an attempt", in, err)
		}
	}
	_, err := files.ReadAttempt([]byte(`{"version":2}`))
	var ve *files.VersionError
	if errors.As(err, &ve) && ve.Version != 2 {
		t.Errorf("version %d, want 2", ve.Version)
	}
	for _, in := range []string{`{}`, `{"ceremony":"a"}`} {
		_, err := files.ReadAttempt([]byte(in))
		var fe *files.FormatError
		if !errors.As(err, &fe) || fe.Member != "version" {
			t.Errorf("%s: err = %v, want a *FormatError for version", in, err)
		}
	}
}

func TestAttemptCanonicalIsTheCanonicalFormOfThePage(t *testing.T) {
	a := &files.Attempt{Version: 1, Ceremony: "c", PlanSHA256: dg('1')}
	got, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ceremony":"c","plan_sha256":` + q(dg('1')) + `,"version":1}`; string(got) != want {
		t.Errorf("Canonical:\n got %s\nwant %s", got, want)
	}
	full := &files.Attempt{Version: 1, Ceremony: "c", PlanSHA256: dg('1'), Root: "r", StartedAt: "2026-11-14T10:00:00Z"}
	got, err = full.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ceremony":"c","plan_sha256":` + q(dg('1')) + `,"root":"r","started_at":"2026-11-14T10:00:00Z","version":1}`; string(got) != want {
		t.Errorf("Canonical:\n got %s\nwant %s", got, want)
	}
	for _, x := range []*files.Attempt{a, full} {
		c, _ := x.Canonical()
		back, err := files.ReadAttempt(c)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, x) {
			t.Errorf("round trip: got %+v, want %+v", back, x)
		}
		if ok, err := canonjson.IsCanonical(c); err != nil || !ok {
			t.Errorf("IsCanonical = %v, %v", ok, err)
		}
	}
}

func TestReadPlanTakesEveryMemberItReads(t *testing.T) {
	m := planDoc()
	m["arguments"] = map[string]any{"with": []any{"card-a"}}
	m["ritueel"] = map[string]any{"version": "0.1.0", "os_arch": "linux/amd64", "sha256": dg('8')}
	m["applies"] = []any{map[string]any{"object": "alice"}}
	m["leaves_out"] = []any{map[string]any{"object": "bob", "reason": "later"}}
	m["root"] = map[string]any{"label": "root-a", "test": true}
	m["root_reason"] = "lost"
	m["requests"] = []any{map[string]any{"stem": "alice"}}
	m["signatures"] = []any{map[string]any{"n": 1}}
	m["births"] = []any{map[string]any{"label": "a"}}
	m["touches"] = 2
	m["base_sequence"] = 2
	p, err := files.ReadPlan(encode(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Ceremony != "20261114T100000Z-apply" || p.Command != "apply" || p.TrustSequence == nil || *p.TrustSequence != 3 {
		t.Errorf("the head of the plan is wrong: %+v", p)
	}
	if p.MadeAt != "2026-11-14T09:00:00Z" || p.CeremonyTime != "2026-11-14T10:00:00Z" || p.LastRecordSHA256 != dg('2') {
		t.Errorf("a member is wrong: %+v", p)
	}
	if len(p.Wanted) != 1 || len(p.Inputs) != 1 || p.Inputs[0].Path != "requests/alice/alice.csr" {
		t.Errorf("lists of files: wanted %+v, inputs %+v", p.Wanted, p.Inputs)
	}
	if p.Touches != 2 || p.BaseSequence != 2 || len(p.Applies) != 1 || len(p.LeavesOut) != 1 || len(p.Requests) != 1 || len(p.Signatures) != 1 || len(p.Births) != 1 {
		t.Errorf("a member is missing: %+v", p)
	}
	if p.Root == nil || p.Root.Label != "root-a" || !p.Root.Test || p.RootReason != "lost" {
		t.Errorf("root: %+v, reason %q", p.Root, p.RootReason)
	}
	if len(p.Arguments) == 0 || len(p.Ritueel) == 0 {
		t.Errorf("arguments %q, ritueel %q", p.Arguments, p.Ritueel)
	}
}

func TestReadPlanWantsItsRequiredMembersAndTheirForms(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(map[string]any)
		member string
	}{
		{"no version", without("version"), "version"},
		{"no ceremony", without("ceremony"), "ceremony"},
		{"no command", without("command"), "command"},
		{"no trust sequence", without("trust_sequence"), "trust_sequence"},
		{"command close", set("command", "close"), "command"},
		{"command in capitals", set("command", "APPLY"), "command"},
		{"ceremony with a space", set("ceremony", "a b"), "ceremony"},
		{"made_at with a fraction", set("made_at", "2026-11-14T09:00:00.1Z"), "made_at"},
		{"ceremony_time with an offset", set("ceremony_time", "2026-11-14T10:00:00+01:00"), "ceremony_time"},
		{"last record digest in capitals", set("last_record_sha256", strings.ToUpper(dg('a'))), "last_record_sha256"},
		{"wanted path up", setEntry("wanted", 0, "path", "../x"), "wanted[0].path"},
		{"wanted digest short", setEntry("wanted", 0, "sha256", "ab"), "wanted[0].sha256"},
		{"input path absolute", setEntry("inputs", 0, "path", "/etc/hosts"), "inputs[0].path"},
		{"input path with a temporary folder", setEntry("inputs", 0, "path", ".RT-x/a"), "inputs[0].path"},
		{"input digest missing", delEntry("inputs", 0, "sha256"), "inputs[0].sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := files.ReadPlan(encode(t, planDoc(), c.edit))
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v (%T), want a *FormatError", err, err)
			}
			if fe.What != "plan" || fe.Member != c.member {
				t.Errorf("FormatError{%q, %q}, want member %q of a plan", fe.What, fe.Member, c.member)
			}
		})
	}
}

func TestReadPlanNeedsOnlyTheFourMembersAndTellsZeroFromMissing(t *testing.T) {
	min := func() map[string]any {
		return map[string]any{"version": 1, "ceremony": "c", "command": "apply", "trust_sequence": 4}
	}
	p, err := files.ReadPlan(encode(t, min(), nil))
	if err != nil {
		t.Fatalf("a plan with only the four members: %v", err)
	}
	if p.TrustSequence == nil || *p.TrustSequence != 4 {
		t.Errorf("trust_sequence = %v", p.TrustSequence)
	}
	// A missing member is not read as 0.
	_, err = files.ReadPlan(encode(t, min(), without("trust_sequence")))
	var fe *files.FormatError
	if !errors.As(err, &fe) || fe.Member != "trust_sequence" {
		t.Errorf("a plan with no trust_sequence: err = %v", err)
	}
	// A member that is there with the value 0 is not "missing".
	_, err = files.ReadPlan(encode(t, min(), set("trust_sequence", 0)))
	if errors.As(err, &fe) && fe.Member == "trust_sequence" && strings.Contains(fe.Reason, "missing") {
		t.Errorf("trust_sequence 0 is told as missing: %v", err)
	}
}

func TestReadPlanRefusesWhatTheJSONRulesRefuse(t *testing.T) {
	base := encode(t, planDoc(), nil)
	for name, in := range map[string][]byte{
		"empty":                   nil,
		"unknown member":          encode(t, planDoc(), set("extra", 1)),
		"repeated":                []byte(strings.Replace(string(base), `"version":1`, `"version":1,"touches":1,"touches":2`, 1)),
		"null trust_sequence":     encode(t, planDoc(), set("trust_sequence", nil)),
		"a text for the sequence": encode(t, planDoc(), set("trust_sequence", "3")),
		"a fraction":              encode(t, planDoc(), set("trust_sequence", 3.5)),
		"2^53":                    encode(t, planDoc(), set("trust_sequence", int64(1)<<53)),
		"arguments as a list":     encode(t, planDoc(), set("arguments", []any{})),
		"ritueel as a text":       encode(t, planDoc(), set("ritueel", "x")),
		"bom":                     append([]byte("\xef\xbb\xbf"), base...),
		"nesting of 10001":        deepArguments(t, planDoc(), 10001),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := files.ReadPlan(in)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, strictjson.ErrMalformed) {
				var fe *files.FormatError
				if !errors.As(err, &fe) {
					t.Errorf("err = %v (%T), want one that wraps ErrMalformed", err, err)
				}
			}
			if !printableASCII(err.Error()) {
				t.Errorf("not printable ASCII: %.120q", err)
			}
		})
	}
	if _, err := files.ReadPlan(deepArguments(t, planDoc(), 10000)); err != nil {
		t.Errorf("a plan 10,000 levels deep: %v", err)
	}
}

func TestReadPlanReadsTheVersionFirstAndAlone(t *testing.T) {
	for _, in := range []string{`{"version":2}`, `{"version":2,"trust_sequence":"x","trust_sequence":null}`, `{"version":3,"command":"revoke"}`} {
		_, err := files.ReadPlan([]byte(in))
		var ve *files.VersionError
		if !errors.As(err, &ve) || ve.What != "plan" {
			t.Errorf("%s: err = %v, want a *VersionError of a plan", in, err)
		}
	}
	_, err := files.ReadPlan([]byte(`{"version":3}`))
	var ve *files.VersionError
	if !errors.As(err, &ve) || ve.Version != 3 {
		t.Errorf("version 3: err = %v", err)
	}
	_, err = files.ReadPlan([]byte(`{"ceremony":"a"}`))
	var fe *files.FormatError
	if !errors.As(err, &fe) || fe.Member != "version" {
		t.Errorf("no version: err = %v", err)
	}
}

func TestPlanCanonicalIsTheCanonicalFormOfThePage(t *testing.T) {
	three := int64(3)
	p := &files.Plan{Version: 1, Ceremony: "c", Command: "apply", TrustSequence: &three,
		LastRecordSHA256: dg('2'), Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}}
	got, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ceremony":"c","command":"apply","last_record_sha256":` + q(dg('2')) + `,"trust_sequence":3,"version":1,` +
		`"wanted":[{"path":"ritueel.yaml","sha256":` + q(dg('4')) + `}]}`
	if string(got) != want {
		t.Errorf("Canonical:\n got %s\nwant %s", got, want)
	}
	zero := int64(0)
	p0 := &files.Plan{Version: 1, Ceremony: "c", Command: "apply", TrustSequence: &zero}
	got0, err := p0.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ceremony":"c","command":"apply","trust_sequence":0,"version":1}`; string(got0) != want {
		t.Errorf("a plan with trust_sequence 0 is written %s, want %s", got0, want)
	}
	for _, x := range []*files.Plan{p, p0} {
		c, _ := x.Canonical()
		back, err := files.ReadPlan(c)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, x) {
			t.Errorf("round trip: got %+v, want %+v", back, x)
		}
		again, _ := back.Canonical()
		if !bytes.Equal(c, again) {
			t.Errorf("the bytes changed on the way: %s -> %s", c, again)
		}
	}
}

func TestErrorTextsNameWhatIsWrongAndStayPrintable(t *testing.T) {
	ve := &files.VersionError{What: "ceremony record", Version: 7}
	if !strings.Contains(ve.Error(), "ceremony record") || !strings.Contains(ve.Error(), "7") {
		t.Errorf("VersionError text %q names neither the file nor the version", ve)
	}
	fe := &files.FormatError{What: "plan", Member: "wanted[2].path", Reason: "is wrong"}
	for _, want := range []string{"plan", "wanted[2].path", "is wrong"} {
		if !strings.Contains(fe.Error(), want) {
			t.Errorf("FormatError text %q lacks %q", fe, want)
		}
	}
}
