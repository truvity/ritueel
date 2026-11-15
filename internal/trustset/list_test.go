package trustset_test

import (
	"bytes"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/trustset"
)

// checkWritten holds the laws of every list that MarshalList returns: the reader of the page
// accepts it, it is in the canonical form, it has no trailing newline, and it reads back as the
// spec (roots and removals in label order).
func checkWritten(t testing.TB, spec trustset.ListSpec, out []byte) *rootlist.List {
	t.Helper()
	l, err := rootlist.ParseList(out)
	if err != nil {
		t.Fatalf("rootlist.ParseList: %v", err)
	}
	if ok, err := canonjson.IsCanonical(out); err != nil || !ok {
		t.Fatalf("the list is not canonical (%v): %s", err, out)
	}
	if bytes.HasSuffix(out, []byte("\n")) {
		t.Fatalf("the list has a trailing newline")
	}
	if len(out) > trustset.MaxBytes {
		t.Fatalf("the list has %d bytes", len(out))
	}
	if l.Sequence != spec.Sequence || l.LastRecordSHA256 != spec.LastRecordSHA256 {
		t.Fatalf("sequence %d and anchor %q read back as %d and %q", spec.Sequence, spec.LastRecordSHA256, l.Sequence, l.LastRecordSHA256)
	}
	if !l.SignedAt.Equal(spec.SignedAt) {
		t.Fatalf("signed_at %v reads back as %v", spec.SignedAt, l.SignedAt)
	}
	if want := rootlist.ExpiresFor(spec.SignedAt); !l.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at is %v, want %v", l.ExpiresAt, want)
	}
	byLabel := func(a, b trustset.Root) int { return strings.Compare(a.Label, b.Label) }
	want := slices.Clone(spec.Roots)
	slices.SortFunc(want, byLabel)
	if len(l.Roots) != len(want) {
		t.Fatalf("%d roots read back, want %d", len(l.Roots), len(want))
	}
	for i := range want {
		if l.Roots[i] != rootlist.Root(want[i]) {
			t.Fatalf("root %d reads back as %+v, want %+v", i, l.Roots[i], want[i])
		}
	}
	if len(l.Removals) != len(spec.Removals) {
		t.Fatalf("%d removals read back, want %d", len(l.Removals), len(spec.Removals))
	}
	wantRem := slices.Clone(spec.Removals)
	slices.SortFunc(wantRem, func(a, b trustset.Removal) int { return strings.Compare(a.Label, b.Label) })
	for i := range wantRem {
		if l.Removals[i] != rootlist.Removal(wantRem[i]) {
			t.Fatalf("removal %d reads back as %+v, want %+v", i, l.Removals[i], wantRem[i])
		}
	}
	return l
}

// The page's example, with the members in the order that the canonical form gives: the exact bytes
// of one small list, written out by hand.
func TestMarshalListExactBytes(t *testing.T) {
	a, b := fakeRoot("A", true), fakeRoot("B", true)
	anchor := hexOf("end of history")
	spec := trustset.ListSpec{
		Sequence:         7,
		SignedAt:         time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC),
		Roots:            []trustset.Root{a, b},
		LastRecordSHA256: anchor,
	}
	want := `{"expires_at":"2027-12-15T12:00:00Z","last_record_sha256":"` + anchor + `",` +
		`"roots":[{"label":"A","openpgp_fingerprint":"` + a.OpenPGPFingerprint + `","x509_spki_sha256":"` + a.X509SPKISHA256 + `"},` +
		`{"label":"B","openpgp_fingerprint":"` + b.OpenPGPFingerprint + `","x509_spki_sha256":"` + b.X509SPKISHA256 + `"}],` +
		`"sequence":7,"signed_at":"2026-11-15T12:00:00Z","version":1}`
	got, err := trustset.MarshalList(spec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestMarshalListExactBytesFirstListWithRemovalsAndNoFingerprint(t *testing.T) {
	a, c := fakeRoot("A", false), fakeRoot("C", false)
	// The first list: no last_record_sha256 and no fingerprints.
	first := trustset.ListSpec{Sequence: 1, SignedAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), Roots: []trustset.Root{c, a}}
	want := `{"expires_at":"2027-02-01T00:00:00Z","roots":[{"label":"A","x509_spki_sha256":"` + a.X509SPKISHA256 + `"},` +
		`{"label":"C","x509_spki_sha256":"` + c.X509SPKISHA256 + `"}],"sequence":1,"signed_at":"2026-01-01T00:00:00Z","version":1}`
	got, err := trustset.MarshalList(first)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}

	// A list with removals: the member sits between last_record_sha256 and roots, and the entries
	// are in label order whatever order they were given in.
	anchor := hexOf("anchor")
	spec := trustset.ListSpec{
		Sequence:         3,
		SignedAt:         time.Date(2026, time.March, 31, 8, 30, 15, 0, time.UTC),
		Roots:            []trustset.Root{fakeRoot("B", false)},
		LastRecordSHA256: anchor,
		Removals: []trustset.Removal{
			{Label: "D", X509SPKISHA256: hexOf("pin D"), Authorisation: "d.d.d"},
			{Label: "A", X509SPKISHA256: hexOf("pin A"), Authorisation: "a.a.a"},
		},
	}
	want = `{"expires_at":"2027-04-30T08:30:15Z","last_record_sha256":"` + anchor + `",` +
		`"removals":[{"authorisation":"a.a.a","label":"A","x509_spki_sha256":"` + hexOf("pin A") + `"},` +
		`{"authorisation":"d.d.d","label":"D","x509_spki_sha256":"` + hexOf("pin D") + `"}],` +
		`"roots":[{"label":"B","x509_spki_sha256":"` + hexOf("pin B") + `"}],"sequence":3,"signed_at":"2026-03-31T08:30:15Z","version":1}`
	got, err = trustset.MarshalList(spec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestMarshalListAccepted(t *testing.T) {
	all := func(withPrint bool, n int) []trustset.Root {
		var rs []trustset.Root
		for i := 0; i < n; i++ {
			rs = append(rs, fakeRoot(string(rune('A'+i)), withPrint))
		}
		return rs
	}
	withRemovals := fakeSpec()
	withRemovals.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: hexOf("pin C"), Authorisation: "x.y.z"}}
	manyRemovals := fakeSpec()
	for i := 0; i < trustset.MaxRoots; i++ {
		l := string(rune('A' + i))
		manyRemovals.Removals = append(manyRemovals.Removals, trustset.Removal{Label: l, X509SPKISHA256: hexOf("removed " + l), Authorisation: "x.y.z"})
	}
	first := fakeSpec()
	first.Sequence, first.LastRecordSHA256 = 1, ""
	top := fakeSpec()
	top.Sequence = strictjson.MaxSafeInt

	for _, c := range []struct {
		name string
		spec func() trustset.ListSpec
	}{
		{"one root", func() trustset.ListSpec { s := fakeSpec(); s.Roots = all(true, 1); return s }},
		{"26 roots", func() trustset.ListSpec { s := fakeSpec(); s.Roots = all(true, 26); return s }},
		{"no fingerprint on any", func() trustset.ListSpec { s := fakeSpec(); s.Roots = all(false, 3); return s }},
		{"a fingerprint on all", func() trustset.ListSpec { s := fakeSpec(); s.Roots = all(true, 3); return s }},
		{"the first list", func() trustset.ListSpec { return first }},
		{"a list with a removal", func() trustset.ListSpec { return withRemovals }},
		{"a list with 26 removals", func() trustset.ListSpec { return manyRemovals }},
		{"the highest sequence", func() trustset.ListSpec { return top }},
		{"a zone other than UTC", func() trustset.ListSpec {
			s := fakeSpec()
			s.SignedAt = time.Date(2026, time.November, 15, 14, 0, 0, 0, time.FixedZone("CEST", 2*3600))
			return s
		}},
		{"an authorisation of the longest size", func() trustset.ListSpec {
			s := fakeSpec()
			s.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: hexOf("pin C"), Authorisation: strings.Repeat("a", 100000)}}
			return s
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			spec := c.spec()
			out, err := trustset.MarshalList(spec)
			if err != nil {
				t.Fatal(err)
			}
			checkWritten(t, spec, out)
		})
	}
}

func TestMarshalListInAnyZoneIsTheSameBytes(t *testing.T) {
	utc := fakeSpec()
	want, err := trustset.MarshalList(utc)
	if err != nil {
		t.Fatal(err)
	}
	for _, loc := range []*time.Location{time.FixedZone("A", 2*3600), time.FixedZone("B", -9*3600-30*60), time.FixedZone("C", 14*3600)} {
		s := fakeSpec()
		s.SignedAt = utc.SignedAt.In(loc)
		got, err := trustset.MarshalList(s)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("zone %v gives other bytes:\n%s\n%s", loc, got, want)
		}
	}
}

func TestMarshalListRefusals(t *testing.T) {
	pin := func(l string) string { return hexOf("pin " + l) }
	bad := func(mut func(*trustset.ListSpec)) trustset.ListSpec {
		s := fakeSpec()
		mut(&s)
		return s
	}
	rootsOf := func(rs ...trustset.Root) func(*trustset.ListSpec) {
		return func(s *trustset.ListSpec) { s.Roots = rs }
	}
	manyRoots := func(n int) []trustset.Root {
		var rs []trustset.Root
		for i := 0; i < n; i++ {
			rs = append(rs, fakeRoot(string(rune('A'+i%26)), true))
		}
		return rs
	}
	a := fakeRoot("A", true)
	withPin := func(p string) trustset.Root { r := a; r.X509SPKISHA256 = p; return r }
	withPrint := func(p string) trustset.Root { r := a; r.OpenPGPFingerprint = p; return r }
	withLabel := func(l string) trustset.Root { r := a; r.Label = l; return r }
	removalOf := func(label, p, auth string) trustset.Removal {
		return trustset.Removal{Label: label, X509SPKISHA256: p, Authorisation: auth}
	}
	// The refusal is for the reason of the case, so that a check that is gone is not hidden by
	// another that happens to refuse the same input (the read-back of the written bytes).
	reasons := map[string]string{
		"sequence 0":                      "is not an integer from 1 to",
		"sequence -1":                     "is not an integer from 1 to",
		"sequence above the safe range":   "is not an integer from 1 to",
		"no root":                         "at least one root key",
		"nil roots":                       "at least one root key",
		"27 roots":                        "at most 26 root keys",
		"label a":                         "root 0: the label is not one upper-case letter",
		"label AB":                        "root 0: the label is not one upper-case letter",
		"empty label":                     "root 0: the label is not one upper-case letter",
		"label 1":                         "root 0: the label is not one upper-case letter",
		"label with a space":              "root 0: the label is not one upper-case letter",
		"label with a newline":            "root 0: the label is not one upper-case letter",
		"label of a letter outside ASCII": "root 0: the label is not one upper-case letter",
		"label twice":                     "appears twice",
		"pin twice":                       "root B: the pin appears twice",
		"pin in upper case":               "the pin is not 64",
		"pin of 63 digits":                "the pin is not 64",
		"pin of 65 digits":                "the pin is not 64",
		"pin with 0x":                     "the pin is not 64",
		"empty pin":                       "the pin is not 64",
		"pin with a NUL":                  "the pin is not 64",
		"fingerprint in upper case":       "the fingerprint is not 40",
		"fingerprint of 39 digits":        "the fingerprint is not 40",
		"fingerprint of 41 digits":        "the fingerprint is not 40",
		"fingerprint of 64 digits":        "the fingerprint is not 40",
		"fingerprint twice":               "the fingerprint appears twice",
		"one entry with a fingerprint and one without":        "some roots have an OpenPGP fingerprint",
		"one entry without a fingerprint and one with":        "some roots have an OpenPGP fingerprint",
		"last_record_sha256 of 63 digits":                     "last_record_sha256 is required",
		"last_record_sha256 of 65 digits":                     "last_record_sha256 is required",
		"last_record_sha256 in upper case":                    "last_record_sha256 is required",
		"a later list without last_record_sha256":             "last_record_sha256 is required",
		"the first list with last_record_sha256":              "the first list has no last_record_sha256",
		"an empty authorisation":                              "the authorisation is empty",
		"a pin twice in removals":                             "removal D: the pin appears twice",
		"a removal label a":                                   "removal 0: the label is not one upper-case letter",
		"a removal with an empty label":                       "removal 0: the label is not one upper-case letter",
		"a removal pin in upper case":                         "the pin is not 64",
		"27 removals":                                         "at most 26 removals",
		"a label twice in removals":                           "removal C: the label appears twice in removals",
		"a label twice in removals, pins in another order":    "removal C: the label appears twice in removals",
		"the pin of the first root in removals":               "removal C: the pin is also the pin of a root key of the list",
		"the pin of the last root in removals":                "removal C: the pin is also the pin of a root key of the list",
		"the pin of a root under another label in removals":   "removal Q: the pin is also the pin of a root key of the list",
		"the pin of a root as the last of three removals":     "removal Z: the pin is also the pin of a root key of the list",
		"signed_at is the zero time":                          "signed_at is not given",
		"signed_at is the zero time in a zone east of UTC":    "signed_at is not given",
		"signed_at is the zero time in a zone west of UTC":    "signed_at is not given",
		"signed_at is the zero time in the local zone":        "signed_at is not given",
		"signed_at is the zero time after UTC()":              "signed_at is not given",
		"an authorisation over the limit":                     "removal C: the authorisation is longer than",
		"half a second":                                       "fraction of a second",
		"one nanosecond":                                      "fraction of a second",
		"the year 0":                                          "signed_at is outside the years 1 to 9999",
		"the year -5":                                         "signed_at is outside the years 1 to 9999",
		"the year 10000":                                      "signed_at is outside the years 1 to 9999",
		"the year 9999, whose expiry passes 9999":             "expires_at is outside",
		"the year 9999 in November, whose expiry passes 9999": "expires_at is outside",
		"a time that ends the year 9999 in another zone":      "signed_at is outside the years 1 to 9999",
	}
	for _, c := range []struct {
		name string
		spec trustset.ListSpec
	}{
		{"sequence 0", bad(func(s *trustset.ListSpec) { s.Sequence = 0 })},
		{"sequence -1", bad(func(s *trustset.ListSpec) { s.Sequence = -1 })},
		{"sequence above the safe range", bad(func(s *trustset.ListSpec) { s.Sequence = strictjson.MaxSafeInt + 1 })},
		{"no root", bad(rootsOf())},
		{"nil roots", bad(func(s *trustset.ListSpec) { s.Roots = nil })},
		{"27 roots", bad(func(s *trustset.ListSpec) { s.Roots = manyRoots(27) })},
		{"label a", bad(rootsOf(withLabel("a")))},
		{"label AB", bad(rootsOf(withLabel("AB")))},
		{"empty label", bad(rootsOf(withLabel("")))},
		{"label 1", bad(rootsOf(withLabel("1")))},
		{"label with a space", bad(rootsOf(withLabel(" ")))},
		{"label with a newline", bad(rootsOf(withLabel("A\n")))},
		{"label of a letter outside ASCII", bad(rootsOf(withLabel("\u00c4")))},
		{"label twice", bad(rootsOf(fakeRoot("A", true), func() trustset.Root { r := fakeRoot("B", true); r.Label = "A"; return r }()))},
		{"pin twice", bad(rootsOf(fakeRoot("A", true), func() trustset.Root { r := fakeRoot("B", true); r.X509SPKISHA256 = pin("A"); return r }()))},
		{"pin in upper case", bad(rootsOf(withPin(strings.ToUpper(pin("A")))))},
		{"pin of 63 digits", bad(rootsOf(withPin(pin("A")[:63])))},
		{"pin of 65 digits", bad(rootsOf(withPin(pin("A") + "0")))},
		{"pin with 0x", bad(rootsOf(withPin("0x" + pin("A")[:62])))},
		{"empty pin", bad(rootsOf(withPin("")))},
		{"pin with a NUL", bad(rootsOf(withPin(pin("A")[:63] + "\x00")))},
		{"fingerprint in upper case", bad(rootsOf(withPrint(strings.ToUpper(a.OpenPGPFingerprint))))},
		{"fingerprint of 39 digits", bad(rootsOf(withPrint(a.OpenPGPFingerprint[:39])))},
		{"fingerprint of 41 digits", bad(rootsOf(withPrint(a.OpenPGPFingerprint + "0")))},
		{"fingerprint of 64 digits", bad(rootsOf(withPrint(hexOf("x"))))},
		{"fingerprint twice", bad(rootsOf(fakeRoot("A", true), func() trustset.Root {
			r := fakeRoot("B", true)
			r.OpenPGPFingerprint = fakeRoot("A", true).OpenPGPFingerprint
			return r
		}()))},
		{"one entry with a fingerprint and one without", bad(rootsOf(fakeRoot("A", true), fakeRoot("B", false)))},
		{"one entry without a fingerprint and one with", bad(rootsOf(fakeRoot("A", false), fakeRoot("B", true)))},
		{"last_record_sha256 of 63 digits", bad(func(s *trustset.ListSpec) { s.LastRecordSHA256 = s.LastRecordSHA256[:63] })},
		{"last_record_sha256 of 65 digits", bad(func(s *trustset.ListSpec) { s.LastRecordSHA256 += "0" })},
		{"last_record_sha256 in upper case", bad(func(s *trustset.ListSpec) { s.LastRecordSHA256 = strings.ToUpper(s.LastRecordSHA256) })},
		{"a later list without last_record_sha256", bad(func(s *trustset.ListSpec) { s.LastRecordSHA256 = "" })},
		{"the first list with last_record_sha256", bad(func(s *trustset.ListSpec) { s.Sequence = 1 })},
		{"an empty authorisation", bad(func(s *trustset.ListSpec) { s.Removals = []trustset.Removal{removalOf("C", pin("C"), "")} })},
		{"a pin twice in removals", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", pin("C"), "a.b.c"), removalOf("D", pin("C"), "a.b.c")}
		})},
		{"a removal label a", bad(func(s *trustset.ListSpec) { s.Removals = []trustset.Removal{removalOf("c", pin("C"), "a.b.c")} })},
		{"a removal with an empty label", bad(func(s *trustset.ListSpec) { s.Removals = []trustset.Removal{removalOf("", pin("C"), "a.b.c")} })},
		{"a removal pin in upper case", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", strings.ToUpper(pin("C")), "a.b.c")}
		})},
		{"27 removals", bad(func(s *trustset.ListSpec) {
			for i := 0; i < 27; i++ {
				s.Removals = append(s.Removals, removalOf(string(rune('A'+i%26)), hexOf("removed "+string(rune('a'+i))), "a.b.c"))
			}
		})},
		{"an authorisation over the limit", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", pin("C"), strings.Repeat("a", trustset.MaxBytes+1))}
		})},
		{"a label twice in removals", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", hexOf("removed one"), "a.b.c"), removalOf("C", hexOf("removed two"), "d.e.f")}
		})},
		{"a label twice in removals, pins in another order", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", hexOf("removed two"), "d.e.f"), removalOf("C", hexOf("removed one"), "a.b.c")}
		})},
		{"the pin of the first root in removals", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", pin("A"), "a.b.c")}
		})},
		{"the pin of the last root in removals", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", pin("B"), "a.b.c")}
		})},
		{"the pin of a root under another label in removals", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{removalOf("C", hexOf("removed C"), "a.b.c"), removalOf("Q", pin("B"), "a.b.c")}
		})},
		{"the pin of a root as the last of three removals", bad(func(s *trustset.ListSpec) {
			s.Removals = []trustset.Removal{
				removalOf("Z", pin("A"), "z.z.z"), removalOf("C", hexOf("removed C"), "c.c.c"), removalOf("D", hexOf("removed D"), "d.d.d"),
			}
		})},
		{"signed_at is the zero time", bad(func(s *trustset.ListSpec) { s.SignedAt = time.Time{} })},
		{"signed_at is the zero time in a zone east of UTC", bad(func(s *trustset.ListSpec) {
			s.SignedAt = time.Time{}.In(time.FixedZone("E", 5*3600))
		})},
		{"signed_at is the zero time in a zone west of UTC", bad(func(s *trustset.ListSpec) {
			s.SignedAt = time.Time{}.In(time.FixedZone("W", -5*3600))
		})},
		{"signed_at is the zero time in the local zone", bad(func(s *trustset.ListSpec) { s.SignedAt = time.Time{}.In(time.Local) })},
		{"signed_at is the zero time after UTC()", bad(func(s *trustset.ListSpec) { s.SignedAt = time.Time{}.UTC() })},
		{"half a second", bad(func(s *trustset.ListSpec) { s.SignedAt = s.SignedAt.Add(500 * time.Millisecond) })},
		{"one nanosecond", bad(func(s *trustset.ListSpec) { s.SignedAt = s.SignedAt.Add(time.Nanosecond) })},
		{"the year 0", bad(func(s *trustset.ListSpec) { s.SignedAt = time.Date(0, time.June, 1, 0, 0, 0, 0, time.UTC) })},
		{"the year -5", bad(func(s *trustset.ListSpec) { s.SignedAt = time.Date(-5, time.June, 1, 0, 0, 0, 0, time.UTC) })},
		{"the year 10000", bad(func(s *trustset.ListSpec) { s.SignedAt = time.Date(10000, time.June, 1, 0, 0, 0, 0, time.UTC) })},
		{"the year 9999, whose expiry passes 9999", bad(func(s *trustset.ListSpec) { s.SignedAt = time.Date(9999, time.January, 1, 0, 0, 0, 0, time.UTC) })},
		{"the year 9999 in November, whose expiry passes 9999", bad(func(s *trustset.ListSpec) {
			s.SignedAt = time.Date(9999, time.November, 30, 0, 0, 0, 0, time.UTC)
		})},
		{"a time that ends the year 9999 in another zone", bad(func(s *trustset.ListSpec) {
			s.SignedAt = time.Date(9999, time.December, 31, 23, 0, 0, 0, time.FixedZone("Z", -3600))
		})},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := trustset.MarshalList(c.spec)
			if err == nil {
				t.Fatalf("accepted: %s", out)
			}
			if out != nil {
				t.Errorf("%d bytes come with the error", len(out))
			}
			wantParams(t, err)
			if why, ok := reasons[c.name]; ok && !strings.Contains(err.Error(), why) {
				t.Errorf("the refusal %q does not say %q", err, why)
			}
			if _, ok := reasons[c.name]; !ok {
				t.Errorf("no reason is given for the case %q", c.name)
			}
		})
	}
}

// The boundaries of the years 1 to 9999.
func TestMarshalListYearBoundaries(t *testing.T) {
	for _, c := range []struct {
		name     string
		signed   time.Time
		expires  string
		accepted bool
	}{
		{"the first second after year 1 begins", time.Date(1, time.January, 1, 0, 0, 1, 0, time.UTC), "0002-02-01T00:00:01Z", true},
		{"9998-11-30", time.Date(9998, time.November, 30, 23, 59, 59, 0, time.UTC), "9999-12-30T23:59:59Z", true},
		{"9998-11-01 gives the first of 9999-12", time.Date(9998, time.November, 1, 0, 0, 0, 0, time.UTC), "9999-12-01T00:00:00Z", true},
		{"9998-12-01 passes 9999", time.Date(9998, time.December, 1, 0, 0, 0, 0, time.UTC), "", false},
		{"9998-12-31 passes 9999", time.Date(9998, time.December, 31, 23, 59, 59, 0, time.UTC), "", false},
		{"9999-01-01 passes 9999", time.Date(9999, time.January, 1, 0, 0, 0, 0, time.UTC), "", false},
	} {
		spec := fakeSpec()
		spec.SignedAt = c.signed
		out, err := trustset.MarshalList(spec)
		if !c.accepted {
			if err == nil {
				t.Errorf("%s: accepted: %s", c.name, out)
			} else {
				wantParams(t, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		l := checkWritten(t, spec, out)
		if got := l.ExpiresAt.Format(rootlist.TimeLayout); got != c.expires {
			t.Errorf("%s: expires_at %s, want %s", c.name, got, c.expires)
		}
	}
}

// Roots and removals that are given out of order come out in label order, and the input is not
// changed by the call.
func TestMarshalListSortsAndDoesNotTouchTheInput(t *testing.T) {
	spec := fakeSpec()
	spec.Roots = []trustset.Root{fakeRoot("D", true), fakeRoot("B", true), fakeRoot("Z", true), fakeRoot("A", true)}
	spec.Removals = []trustset.Removal{
		{Label: "M", X509SPKISHA256: hexOf("removed M"), Authorisation: "m.m.m"},
		{Label: "C", X509SPKISHA256: hexOf("removed C"), Authorisation: "c.c.c"},
		{Label: "X", X509SPKISHA256: hexOf("removed X"), Authorisation: "x.x.x"},
	}
	rootsBefore := slices.Clone(spec.Roots)
	removalsBefore := slices.Clone(spec.Removals)
	out, err := trustset.MarshalList(spec)
	if err != nil {
		t.Fatal(err)
	}
	l := checkWritten(t, spec, out)
	var labels, removed string
	for _, r := range l.Roots {
		labels += r.Label
	}
	for _, r := range l.Removals {
		removed += r.Label
	}
	if labels != "ABDZ" || removed != "CMX" {
		t.Errorf("roots %s and removals %s are not in label order", labels, removed)
	}
	if !slices.Equal(spec.Roots, rootsBefore) || !slices.Equal(spec.Removals, removalsBefore) {
		t.Errorf("MarshalList changed the slices it was given")
	}
	// The order that the caller gave does not change the bytes.
	slices.Reverse(spec.Roots)
	again, err := trustset.MarshalList(spec)
	if err != nil || !bytes.Equal(out, again) {
		t.Errorf("another order of the same roots gives other bytes (%v)", err)
	}
}

// The writer takes 13 months from the one function of the page, for every day of seven years and
// for the last second of a leap day, and the function agrees with the one that the certificates use.
func TestMarshalListWritesTheThirteenMonths(t *testing.T) {
	check := func(signed time.Time) {
		spec := fakeSpec()
		spec.SignedAt = signed
		out, err := trustset.MarshalList(spec)
		if err != nil {
			t.Fatalf("%v: %v", signed, err)
		}
		l, err := rootlist.ParseList(out)
		if err != nil {
			t.Fatalf("%v: %v", signed, err)
		}
		want, err := pki.AddMonths(signed, 13)
		if err != nil {
			t.Fatal(err)
		}
		if !l.ExpiresAt.Equal(want) || !l.ExpiresAt.Equal(rootlist.ExpiresFor(signed)) {
			t.Fatalf("signed %v: expires_at %v, pki.AddMonths %v, rootlist.ExpiresFor %v", signed, l.ExpiresAt, want, rootlist.ExpiresFor(signed))
		}
		if !strings.Contains(string(out), `"expires_at":"`+want.Format(rootlist.TimeLayout)+`"`) {
			t.Fatalf("signed %v: the bytes do not hold %s", signed, want.Format(rootlist.TimeLayout))
		}
	}
	days := 0
	for d := time.Date(2024, time.January, 1, 12, 0, 0, 0, time.UTC); d.Year() <= 2030; d = d.AddDate(0, 0, 1) {
		check(d)
		days++
	}
	if days < 2500 {
		t.Fatalf("only %d days were checked", days)
	}
	check(time.Date(2028, time.February, 29, 23, 59, 59, 0, time.UTC))
}

// The examples of the page and of the vectors: the end of the month.
func TestMarshalListEndOfTheMonth(t *testing.T) {
	for _, c := range []struct{ signed, expires string }{
		{"2026-01-31T00:00:00Z", "2027-02-28T00:00:00Z"},
		{"2027-01-30T00:00:00Z", "2028-02-29T00:00:00Z"},
		{"2028-02-29T00:00:00Z", "2029-03-29T00:00:00Z"},
		{"2026-11-15T12:00:00Z", "2027-12-15T12:00:00Z"},
		{"2026-12-31T23:59:59Z", "2028-01-31T23:59:59Z"},
		{"2026-03-31T00:00:00Z", "2027-04-30T00:00:00Z"},
		{"2025-10-31T01:02:03Z", "2026-11-30T01:02:03Z"},
	} {
		signed, err := time.Parse(rootlist.TimeLayout, c.signed)
		if err != nil {
			t.Fatal(err)
		}
		spec := fakeSpec()
		spec.SignedAt = signed
		out, err := trustset.MarshalList(spec)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), `"expires_at":"`+c.expires+`"`) {
			t.Errorf("signed_at %s: %s", c.signed, out)
		}
	}
}

// The writer reads no clock: a list signed "in the future" is written as it is asked.
func TestMarshalListReadsNoClock(t *testing.T) {
	spec := fakeSpec()
	spec.SignedAt = time.Date(2999, time.January, 1, 0, 0, 0, 0, time.UTC)
	out, err := trustset.MarshalList(spec)
	if err != nil {
		t.Fatal(err)
	}
	checkWritten(t, spec, out)
}

// Input that is made to break the writer: very long values, bytes that are not UTF-8, control
// characters and characters that JSON has to escape. Each is refused or written in a form that the
// reader reads back, and none is echoed in full in an error.
func TestMarshalListHostileValues(t *testing.T) {
	huge := strings.Repeat("a", 4<<20)
	hostile := []string{
		huge, "\x00", "\xff", "\xc3\x28", "\xed\xa0\x80", "A\u202eB", "A\u2028", "\"", "\\", "\n", "\r\n", "A\x00",
		"\U0001F600", "\uff21\uff22", "\ufeff", strings.Repeat("\xff", 1000),
	}
	for _, h := range hostile {
		for field := 0; field < 6; field++ {
			spec := fakeSpec()
			spec.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: hexOf("pin C"), Authorisation: "a.b.c"}}
			switch field {
			case 0:
				spec.Roots[0].Label = h
			case 1:
				spec.Roots[0].X509SPKISHA256 = h
			case 2:
				spec.Roots[0].OpenPGPFingerprint = h
			case 3:
				spec.LastRecordSHA256 = h
			case 4:
				spec.Removals[0].Label = h
			case 5:
				spec.Removals[0].X509SPKISHA256 = h
			}
			out, err := trustset.MarshalList(spec)
			if err == nil {
				t.Errorf("field %d, value %.20q: accepted %.80s", field, h, out)
				continue
			}
			if out != nil {
				t.Errorf("field %d: bytes come with the error", field)
			}
			wantParams(t, err)
		}
	}
	// The authorisation is free text to the writer; it is written whole or refused, never changed.
	for _, auth := range []string{"a.b.c", "\"quoted\"", "back\\slash", "line\nbreak", "tab\t", "\u2028\u2029", "\U0001F600", "<>&", "a b"} {
		spec := fakeSpec()
		spec.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: hexOf("pin C"), Authorisation: auth}}
		out, err := trustset.MarshalList(spec)
		if err != nil {
			t.Errorf("authorisation %+q: %v", auth, err)
			continue
		}
		l := checkWritten(t, spec, out)
		if l.Removals[0].Authorisation != auth {
			t.Errorf("authorisation %+q reads back as %+q", auth, l.Removals[0].Authorisation)
		}
	}
	// Bytes that are not UTF-8 would be changed by a JSON writer; the list refuses them.
	for _, auth := range []string{"ab\xffcd", "\xc3\x28", "\xed\xa0\x80", "\xf4\x90\x80\x80"} {
		spec := fakeSpec()
		spec.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: hexOf("pin C"), Authorisation: auth}}
		out, err := trustset.MarshalList(spec)
		if err == nil {
			t.Errorf("authorisation %+q accepted: %s", auth, out)
			continue
		}
		wantParams(t, err)
	}
}

// Every removal may be long, and all together pass the limit of the file.
func TestMarshalListOutputOverTheLimit(t *testing.T) {
	spec := fakeSpec()
	for i := 0; i < trustset.MaxRoots; i++ {
		l := string(rune('A' + i))
		spec.Removals = append(spec.Removals, trustset.Removal{Label: l, X509SPKISHA256: hexOf("removed " + l), Authorisation: strings.Repeat("a", 10100)})
	}
	out, err := trustset.MarshalList(spec)
	if err == nil {
		t.Fatalf("a list of %d bytes was written", len(out))
	}
	if out != nil {
		t.Errorf("bytes come with the error")
	}
	wantParams(t, err)
	// (The canonical writer has the same limit and says it first.)
	if !strings.Contains(err.Error(), "longer than 262144 bytes") {
		t.Errorf("the refusal %q does not say that the list is too long", err)
	}
	// Just under the limit is written: 26 removals of 9,900 bytes.
	for i := range spec.Removals {
		spec.Removals[i].Authorisation = strings.Repeat("a", 9900)
	}
	out, err = trustset.MarshalList(spec)
	if err != nil {
		t.Fatalf("a list under the limit: %v", err)
	}
	if len(out) > trustset.MaxBytes {
		t.Errorf("%d bytes", len(out))
	}
}

// A list is always written with the same bytes for the same spec.
func TestMarshalListIsDeterministicAndSafeToShare(t *testing.T) {
	spec := fakeSpec()
	spec.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: hexOf("pin C"), Authorisation: "a.b.c"}}
	want, err := trustset.MarshalList(spec)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([][]byte, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = trustset.MarshalList(spec)
		}()
	}
	close(start)
	wg.Wait()
	for i := range results {
		if errs[i] != nil || !bytes.Equal(results[i], want) {
			t.Errorf("worker %d: %v, %s", i, errs[i], results[i])
		}
	}
}

// The page says that the writer serialises the list so that the same bundle gives the same bytes,
// and that a label names a key and is never reused. Two removals with one label are refused in
// both orders, so one set of entries never gives two byte strings.
func TestMarshalListRefusesALabelTwiceInRemovalsInEveryOrder(t *testing.T) {
	one := trustset.Removal{Label: "C", X509SPKISHA256: hexOf("removed one"), Authorisation: "a.b.c"}
	two := trustset.Removal{Label: "C", X509SPKISHA256: hexOf("removed two"), Authorisation: "d.e.f"}
	same := trustset.Removal{Label: "C", X509SPKISHA256: one.X509SPKISHA256, Authorisation: "a.b.c"}
	for _, c := range []struct {
		name     string
		removals []trustset.Removal
		why      string
	}{
		{"forward", []trustset.Removal{one, two}, "the label appears twice in removals"},
		{"back", []trustset.Removal{two, one}, "the label appears twice in removals"},
		{"the same entry twice", []trustset.Removal{one, one}, "the label appears twice in removals"},
		{"the same label and pin, another authorisation", []trustset.Removal{one, same}, "the label appears twice in removals"},
		{"a third entry between", []trustset.Removal{one, {Label: "D", X509SPKISHA256: hexOf("removed D"), Authorisation: "x.y.z"}, two}, "the label appears twice in removals"},
	} {
		t.Run(c.name, func(t *testing.T) {
			spec := fakeSpec()
			spec.Removals = c.removals
			out, err := trustset.MarshalList(spec)
			if err == nil {
				t.Fatalf("accepted: %s", out)
			}
			if out != nil {
				t.Errorf("bytes come with the error")
			}
			wantParams(t, err)
			if !strings.Contains(err.Error(), c.why) {
				t.Errorf("the refusal %q does not say %q", err, c.why)
			}
		})
	}
}

// Removals with different labels and different pins are accepted in every order and give the same
// bytes, in label order.
func TestMarshalListRemovalsInEveryOrderGiveTheSameBytes(t *testing.T) {
	removals := []trustset.Removal{
		{Label: "C", X509SPKISHA256: hexOf("removed C"), Authorisation: "c.c.c"},
		{Label: "D", X509SPKISHA256: hexOf("removed D"), Authorisation: "d.d.d"},
		{Label: "E", X509SPKISHA256: hexOf("removed E"), Authorisation: "e.e.e"},
		{Label: "F", X509SPKISHA256: hexOf("removed F"), Authorisation: "f.f.f"},
	}
	var want []byte
	n := 0
	var permute func(k int, a []trustset.Removal)
	permute = func(k int, a []trustset.Removal) {
		if k == len(a) {
			spec := fakeSpec()
			spec.Removals = slices.Clone(a)
			out, err := trustset.MarshalList(spec)
			if err != nil {
				t.Fatalf("%v: %v", a, err)
			}
			if want == nil {
				want = out
			}
			if !bytes.Equal(out, want) {
				t.Errorf("an order of the removals gives other bytes:\n%s\n%s", out, want)
			}
			n++
			return
		}
		for i := k; i < len(a); i++ {
			a[k], a[i] = a[i], a[k]
			permute(k+1, a)
			a[k], a[i] = a[i], a[k]
		}
	}
	permute(0, slices.Clone(removals))
	if n != 24 {
		t.Errorf("%d orders tried, want 24", n)
	}
	l, err := rootlist.ParseList(want)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, r := range l.Removals {
		got += r.Label
	}
	if got != "CDEF" {
		t.Errorf("removals are in the order %s", got)
	}
}

// A removal whose pin differs from every root pin is accepted even when its label is that of no
// root, and a removal for a key that is not on the list at all is the normal case.
func TestMarshalListAcceptsARemovalOfAKeyThatIsNotOnTheList(t *testing.T) {
	spec := fakeSpec()
	spec.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: hexOf("removed C"), Authorisation: "c.c.c"}}
	out, err := trustset.MarshalList(spec)
	if err != nil {
		t.Fatal(err)
	}
	checkWritten(t, spec, out)
	// A pin that differs from a root pin in the last digit only is another key.
	near := fakeRoot("A", true).X509SPKISHA256
	last := byte('0')
	if near[len(near)-1] == '0' {
		last = '1'
	}
	spec.Removals = []trustset.Removal{{Label: "C", X509SPKISHA256: near[:len(near)-1] + string(last), Authorisation: "c.c.c"}}
	out, err = trustset.MarshalList(spec)
	if err != nil {
		t.Fatalf("a pin that differs in its last digit: %v", err)
	}
	checkWritten(t, spec, out)
}

// The zero time is refused in every zone, and the first instant after it, the Unix epoch and a
// time in year 1 that is not the zero instant are not.
func TestMarshalListTheZeroTimeAndItsNeighbours(t *testing.T) {
	for _, c := range []struct {
		name   string
		signed time.Time
		ok     bool
	}{
		{"the zero time", time.Time{}, false},
		{"the zero time in a zone", time.Time{}.In(time.FixedZone("X", 3600)), false},
		{"the zero time written out", time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC), false},
		{"the zero instant written in another zone", time.Date(1, time.January, 1, 3, 0, 0, 0, time.FixedZone("E", 3*3600)), false},
		{"one second after the zero time", time.Date(1, time.January, 1, 0, 0, 1, 0, time.UTC), true},
		{"the Unix epoch", time.Unix(0, 0), true},
		{"the Unix epoch in a zone", time.Unix(0, 0).In(time.FixedZone("W", -7*3600)), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			spec := fakeSpec()
			spec.SignedAt = c.signed
			out, err := trustset.MarshalList(spec)
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				checkWritten(t, spec, out)
				return
			}
			if err == nil {
				t.Fatalf("accepted: %s", out)
			}
			wantParams(t, err)
			if !strings.Contains(err.Error(), "signed_at is not given") {
				t.Errorf("the refusal %q does not say that signed_at is not given", err)
			}
		})
	}
}

// A list with several faults shows the first of them, in the order: sequence, time, roots,
// anchor, removals. The order is part of what a caller can rely on, so a fault is never hidden
// behind one that is found earlier by chance.
func TestMarshalListShowsTheFirstFaultInOrder(t *testing.T) {
	spec := func() trustset.ListSpec {
		s := fakeSpec()
		s.Sequence = 0
		s.SignedAt = time.Time{}
		s.Roots = nil
		s.LastRecordSHA256 = "x"
		s.Removals = []trustset.Removal{{Label: "c", X509SPKISHA256: "x", Authorisation: ""}}
		return s
	}
	steps := []struct {
		fix func(*trustset.ListSpec)
		why string
	}{
		{func(s *trustset.ListSpec) { s.Sequence = 3 }, "signed_at is not given"},
		{func(s *trustset.ListSpec) { s.SignedAt = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }, "at least one root key"},
		{func(s *trustset.ListSpec) { s.Roots = []trustset.Root{fakeRoot("A", true)} }, "last_record_sha256 is required"},
		{func(s *trustset.ListSpec) { s.LastRecordSHA256 = hexOf("last") }, "removal 0: the label is not one upper-case letter"},
	}
	s := spec()
	_, err := trustset.MarshalList(s)
	wantParams(t, err)
	if !strings.Contains(err.Error(), "is not an integer from 1 to") {
		t.Fatalf("the first refusal is %q", err)
	}
	for i, st := range steps {
		st.fix(&s)
		_, err := trustset.MarshalList(s)
		wantParams(t, err)
		if !strings.Contains(err.Error(), st.why) {
			t.Fatalf("after step %d the refusal is %q, want %q", i, err, st.why)
		}
	}
	// Within removals, the label is read before the pin and the authorisation, the authorisation
	// before a label twice, a label twice before a pin twice, a pin twice before a pin in roots.
	rem := func(rs ...trustset.Removal) trustset.ListSpec {
		x := fakeSpec()
		x.Removals = rs
		return x
	}
	pinA := fakeRoot("A", true).X509SPKISHA256
	for _, c := range []struct {
		name string
		spec trustset.ListSpec
		why  string
	}{
		{"label before pin", rem(trustset.Removal{Label: "c", X509SPKISHA256: "x", Authorisation: ""}), "removal 0: the label"},
		{"pin before authorisation", rem(trustset.Removal{Label: "C", X509SPKISHA256: "x", Authorisation: ""}), "removal C: the pin is not 64"},
		{"authorisation before the label twice", rem(
			trustset.Removal{Label: "C", X509SPKISHA256: hexOf("one"), Authorisation: "a.b.c"},
			trustset.Removal{Label: "C", X509SPKISHA256: hexOf("two"), Authorisation: ""}), "removal C: the authorisation is empty"},
		{"label twice before pin twice", rem(
			trustset.Removal{Label: "C", X509SPKISHA256: hexOf("one"), Authorisation: "a.b.c"},
			trustset.Removal{Label: "C", X509SPKISHA256: hexOf("one"), Authorisation: "a.b.c"}), "the label appears twice in removals"},
		{"pin twice before a pin in roots", rem(
			trustset.Removal{Label: "C", X509SPKISHA256: hexOf("one"), Authorisation: "a.b.c"},
			trustset.Removal{Label: "D", X509SPKISHA256: hexOf("one"), Authorisation: "a.b.c"},
			trustset.Removal{Label: "E", X509SPKISHA256: pinA, Authorisation: "a.b.c"}), "removal D: the pin appears twice"},
		{"the first removal that is in roots is named", rem(
			trustset.Removal{Label: "C", X509SPKISHA256: hexOf("kept out"), Authorisation: "a.b.c"},
			trustset.Removal{Label: "D", X509SPKISHA256: pinA, Authorisation: "a.b.c"}), "removal D: the pin is also the pin of a root key"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := trustset.MarshalList(c.spec)
			wantParams(t, err)
			if !strings.Contains(err.Error(), c.why) {
				t.Errorf("the refusal is %q, want %q", err, c.why)
			}
		})
	}
}
