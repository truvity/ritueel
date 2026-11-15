package trustset_test

import (
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/trustset"
)

// abc is a chain of one list that holds the root keys A, B and C; the next list has sequence 2.
func abc(t *testing.T) *chain {
	t.Helper()
	c := newChain(t)
	c.add(next{labels: []string{"A", "B", "C"}})
	return c
}

// Every change that is not one of the five kinds is ErrParams (list page, "Who signs"; record
// 0006, rule 18; record 0007, rule 9). Each case builds the input and shows that no draft comes.
func TestWhoSignsRefusals(t *testing.T) {
	type tc struct {
		name   string
		labels []string
		deps   func() []trustset.Departure
		change func(*trustset.Input)
		want   string
	}
	deps := func(ds ...trustset.Departure) func() []trustset.Departure {
		return func() []trustset.Departure { return ds }
	}
	cases := []tc{
		{name: "add and remove in one list", labels: []string{"A", "B", "D"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "C")} }, want: "not both"},
		{name: "add and revoke in one list", labels: []string{"A", "B", "D"}, deps: func() []trustset.Departure { return []trustset.Departure{revoke(t, "C")} }, want: "not both"},
		{name: "retire and revoke in one list", labels: []string{"A"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "B"), revoke(t, "C")} }, want: "retires root keys or revokes"},
		{name: "retire and a revoke with no authorisation in one list", labels: []string{"A"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "B"), revokeLost(t, "C")} }, want: "retires root keys or revokes"},
		{name: "removed key with no departure", labels: []string{"A", "B"}, deps: deps(), want: "no departure is given for it"},
		{name: "one of two removed keys has no departure", labels: []string{"A"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "B")} }, want: "no departure is given for it"},
		{name: "departure for a key that stays in a retire", labels: []string{"A", "B"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "C"), retire(t, "A")} }, want: "not removed"},
		{name: "departure for a key that stays in a renewal", labels: []string{"A", "B", "C"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "C")} }, want: "not removed"},
		{name: "departure for a key that stays in an add", labels: []string{"A", "B", "C", "D"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "C")} }, want: "not removed"},
		{name: "departure for a key that was never on the list", labels: []string{"A", "B"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "C"), retire(t, "Z")} }, want: "not removed"},
		{name: "departure twice", labels: []string{"A", "B"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "C"), retire(t, "C")} }, want: "appears twice"},
		{name: "retire with an authorisation", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			d := retire(t, "C")
			d.Authorisation = newRoot(t, "C", true).removal(t)
			return []trustset.Departure{d}
		}, want: "no authorisation"},
		{name: "way of leaving not given", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin}}
		}, want: "way of leaving"},
		{name: "way of leaving 3", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin, Leave: 3}}
		}, want: "way of leaving"},
		{name: "way of leaving negative", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin, Leave: -1}}
		}, want: "way of leaving"},
		{name: "pin of a departure in upper case", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: strings.ToUpper(newRoot(t, "C", true).Pin), Leave: trustset.LeaveRetired}}
		}, want: "64 lower-case"},
		{name: "pin of a departure short", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin[:63], Leave: trustset.LeaveRetired}}
		}, want: "64 lower-case"},
		{name: "pin of a departure empty", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{Leave: trustset.LeaveRetired}}
		}, want: "64 lower-case"},
		{name: "authorisation over the limit", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin, Leave: trustset.LeaveRevoked, Authorisation: strings.Repeat("a", trustset.MaxBytes+1)}}
		}, want: "longer than"},
		{name: "authorisation that is not one", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin, Leave: trustset.LeaveRevoked, Authorisation: "not.a.jws"}}
		}, want: "stored authorisation of root key C"},
		{name: "authorisation of another key", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin, Leave: trustset.LeaveRevoked, Authorisation: newRoot(t, "A", true).removal(t)}}
		}, want: "stored authorisation of root key C"},
		{name: "authorisation that is a signed list", labels: []string{"A", "B"}, deps: func() []trustset.Departure {
			return []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin, Leave: trustset.LeaveRevoked, Authorisation: strings.Repeat("A", 40) + "." + strings.Repeat("B", 40) + "." + strings.Repeat("C", 128)}}
		}, want: "stored authorisation of root key C"},
		{name: "twenty-seven departures", labels: []string{"A"}, change: func(in *trustset.Input) {
			in.Departures = nil
			for i := 0; i < trustset.MaxRoots+1; i++ {
				in.Departures = append(in.Departures, trustset.Departure{X509SPKISHA256: hexOf(string(rune('a' + i))), Leave: trustset.LeaveRetired})
			}
		}, want: "at most 26 departures"},
		{name: "kept key with another label", labels: []string{"A", "B", "D"}, change: func(in *trustset.Input) {
			for i := range in.Roots {
				if in.Roots[i].Label == "D" {
					in.Roots[i].X509SPKISHA256 = newRoot(t, "C", true).Pin
					in.Roots[i].OpenPGPFingerprint = newRoot(t, "C", true).Print
				}
			}
		}, want: "label or its fingerprint"},
		{name: "kept key with another fingerprint", labels: []string{"A", "B", "C"}, change: func(in *trustset.Input) {
			in.Roots[2].OpenPGPFingerprint = hexOf("another")[:40]
		}, want: "label or its fingerprint"},
		{name: "retire of a key and a changed fingerprint of a kept one", labels: []string{"A", "B"}, deps: func() []trustset.Departure { return []trustset.Departure{retire(t, "C")} }, change: func(in *trustset.Input) {
			in.Roots[0].OpenPGPFingerprint = hexOf("another")[:40]
		}, want: "label or its fingerprint"},
		{name: "no root left", labels: nil, deps: func() []trustset.Departure {
			return []trustset.Departure{retire(t, "A"), retire(t, "B"), retire(t, "C")}
		}, want: "at least one root key"},
		{name: "signed one second before the previous list", labels: []string{"A", "B", "C"}, change: func(in *trustset.Input) {
			in.SignedAt = firstCeremony.Add(-time.Second)
		}, want: "earlier than signed_at of the previous"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := abc(t)
			n := next{labels: tc.labels, change: tc.change}
			if tc.deps != nil {
				n.deps = tc.deps()
			}
			refuses(t, c.input(n), tc.want)
		})
	}
}

// A kept key whose fingerprint appears or goes away is a change of the entry, which a host reads as
// a change of the root keys (check 10).
func TestKeptKeyFingerprintAppearsOrGoesAway(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}, noPrint: true})
	refuses(t, c.input(next{labels: []string{"A", "B"}}), "label or its fingerprint")
	other := newChain(t)
	other.add(next{labels: []string{"A", "B"}})
	refuses(t, other.input(next{labels: []string{"A", "B"}, noPrint: true}), "label or its fingerprint")
}

// Entries of the new list that the roots rule refuses: mixed fingerprints, a label or a pin twice,
// a bad form, too many.
func TestRootsOfTheNewListAreChecked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*trustset.Input)
		want   string
	}{
		{"mixed fingerprints", func(in *trustset.Input) { in.Roots[1].OpenPGPFingerprint = "" }, "some roots have"},
		{"label twice", func(in *trustset.Input) { in.Roots[1].Label = "A" }, "appears twice"},
		{"pin twice", func(in *trustset.Input) { in.Roots[1].X509SPKISHA256 = in.Roots[0].X509SPKISHA256 }, "appears twice"},
		{"fingerprint twice", func(in *trustset.Input) { in.Roots[1].OpenPGPFingerprint = in.Roots[0].OpenPGPFingerprint }, "appears twice"},
		{"label in lower case", func(in *trustset.Input) { in.Roots[0].Label = "a" }, "upper-case letter"},
		{"label of two letters", func(in *trustset.Input) { in.Roots[0].Label = "AB" }, "upper-case letter"},
		{"label empty", func(in *trustset.Input) { in.Roots[0].Label = "" }, "upper-case letter"},
		{"pin in upper case", func(in *trustset.Input) { in.Roots[0].X509SPKISHA256 = strings.ToUpper(in.Roots[0].X509SPKISHA256) }, "64 lower-case"},
		{"pin with 0x", func(in *trustset.Input) { in.Roots[0].X509SPKISHA256 = "0x" + in.Roots[0].X509SPKISHA256[2:] }, "64 lower-case"},
		{"fingerprint of 39 digits", func(in *trustset.Input) { in.Roots[0].OpenPGPFingerprint = in.Roots[0].OpenPGPFingerprint[:39] }, "40 lower-case"},
		{"fingerprint in upper case", func(in *trustset.Input) {
			in.Roots[0].OpenPGPFingerprint = strings.ToUpper(in.Roots[0].OpenPGPFingerprint)
		}, "40 lower-case"},
		{"no roots", func(in *trustset.Input) { in.Roots = nil; in.Certificates = nil }, "at least one"},
		{"27 roots", func(in *trustset.Input) {
			in.Roots = nil
			for i := 0; i < 27; i++ {
				in.Roots = append(in.Roots, trustset.Root{Label: string(rune('A' + i%26)), X509SPKISHA256: hexOf(string(rune('a' + i)))})
			}
		}, "at most 26"},
		{"27 certificates", func(in *trustset.Input) {
			in.Certificates = map[string][]byte{}
			for i := 0; i < 27; i++ {
				in.Certificates[strings.Repeat("A", i+1)] = []byte{1}
			}
		}, "at most 26"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newChain(t)
			refuses(t, c.input(next{labels: []string{"A", "B"}, change: tc.change}), tc.want)
		})
	}
}

// The sequence, the time, the anchor.
func TestSequenceTimeAndAnchor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*trustset.Input)
		want   string
	}{
		{"sequence 0", func(in *trustset.Input) { in.Sequence = 0 }, "sequence"},
		{"sequence -1", func(in *trustset.Input) { in.Sequence = -1 }, "sequence"},
		{"sequence over the safe integers", func(in *trustset.Input) { in.Sequence = 9007199254740992 }, "sequence"},
		{"time not given", func(in *trustset.Input) { in.SignedAt = time.Time{} }, "signed_at"},
		{"half a second", func(in *trustset.Input) { in.SignedAt = in.SignedAt.Add(500 * time.Millisecond) }, "fraction"},
		{"year 0", func(in *trustset.Input) { in.SignedAt = time.Date(0, 6, 1, 0, 0, 0, 0, time.UTC) }, "years 1 to 9999"},
		{"year 9999", func(in *trustset.Input) { in.SignedAt = time.Date(9999, 6, 1, 0, 0, 0, 0, time.UTC) }, "years 1 to 9999"},
		{"first list with an anchor", func(in *trustset.Input) { in.LastRecordSHA256 = hexOf("x") }, "no last_record_sha256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newChain(t)
			refuses(t, c.input(next{labels: []string{"A", "B"}, change: tc.change}), tc.want)
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*trustset.Input)
	}{
		{"missing", func(in *trustset.Input) { in.LastRecordSHA256 = "" }},
		{"63 digits", func(in *trustset.Input) { in.LastRecordSHA256 = in.LastRecordSHA256[:63] }},
		{"upper case", func(in *trustset.Input) { in.LastRecordSHA256 = strings.ToUpper(in.LastRecordSHA256) }},
	} {
		t.Run("anchor "+tc.name, func(t *testing.T) {
			c := abc(t)
			refuses(t, c.input(next{labels: []string{"A", "B", "C"}, change: tc.change}), "last_record_sha256")
		})
	}
}

// A signing time equal to the previous one is allowed; one second later is allowed too.
func TestSignedAtAgainstThePrevious(t *testing.T) {
	c := abc(t)
	for _, d := range []time.Duration{0, time.Second, 24 * time.Hour} {
		if _, err := c.draft(next{labels: []string{"A", "B", "C"}, at: firstCeremony.Add(d)}); err != nil {
			t.Errorf("signed_at %v after the previous: %v", d, err)
		}
	}
	refuses(t, c.input(next{labels: []string{"A", "B", "C"}, at: firstCeremony.Add(-time.Second)}), "earlier than")
}

// The order of the roots in the input does not matter, and the order of the departures does not
// either: the draft is the same.
func TestOrderOfTheInputDoesNotMatter(t *testing.T) {
	c := abc(t)
	rb, rc := revoke(t, "B"), revoke(t, "C")
	x, err := c.draft(next{labels: []string{"A"}, deps: []trustset.Departure{rb, rc}})
	if err != nil {
		t.Fatal(err)
	}
	y, err := c.draft(next{labels: []string{"A"}, deps: []trustset.Departure{rc, rb}})
	if err != nil {
		t.Fatal(err)
	}
	if string(x.ListJSON()) != string(y.ListJSON()) || x.ListSHA256() != y.ListSHA256() {
		t.Error("the order of the departures changes the list")
	}
}
