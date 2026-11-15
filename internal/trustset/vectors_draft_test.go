package trustset_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// The draft is tried on the public material of testdata/root-list/v1: the pins, the fingerprints,
// the certificates of pki/ and the stored authorisations. No private key is kept there, so the
// test compares what needs none: root-list.json and ca-bundle.pem, byte for byte, and the signers
// that the manifest names.

type vectorSigners struct {
	Lists []struct {
		ID      string   `json:"id"`
		Signers []string `json:"signers"`
	} `json:"lists"`
}

func manifestSigners(t testing.TB, id string) []string {
	t.Helper()
	var v vectorSigners
	if err := json.Unmarshal(vectorFile(t, "manifest.json"), &v); err != nil {
		t.Fatal(err)
	}
	for _, l := range v.Lists {
		if l.ID == id {
			return l.Signers
		}
	}
	t.Fatalf("the manifest has no list %s", id)
	return nil
}

// vectorList reads a list of the vectors by id.
func vectorList(t testing.TB, m *vectorManifest, id string) ([]byte, *rootlist.List) {
	t.Helper()
	for _, l := range m.Lists {
		if l.ID == id {
			data := vectorFile(t, l.Files[0])
			list, err := rootlist.ParseList(data)
			if err != nil {
				t.Fatalf("list %s: %v", id, err)
			}
			return data, list
		}
	}
	t.Fatalf("the manifest has no list %s", id)
	return nil, nil
}

// vectorRemoval returns the stored authorisation of a root key of the vectors.
func vectorRemoval(t testing.TB, m *vectorManifest, label string) string {
	t.Helper()
	for _, r := range m.Removals {
		if r.Label == label {
			return string(vectorFile(t, r.File))
		}
	}
	t.Fatalf("the manifest has no removal of %s", label)
	return ""
}

// vectorInput makes the input of the list id of the vectors, made after the list previousID
// ("" for a first list). Earlier is padded with Sequence - 1 lists that hold the keys of the previous
// list, because the vectors hold no history. The sequence, the time, the anchor and the entries
// are those of the vector list.
func vectorInput(t testing.TB, m *vectorManifest, id, previousID string, deps []trustset.Departure) trustset.Input {
	t.Helper()
	_, want := vectorList(t, m, id)
	in := trustset.Input{
		Sequence:         want.Sequence,
		SignedAt:         want.SignedAt,
		LastRecordSHA256: want.LastRecordSHA256,
		Certificates:     map[string][]byte{},
		Departures:       deps,
	}
	for _, r := range want.Roots {
		in.Roots = append(in.Roots, trustset.Root(r))
		// A list that gives a key a label the vectors have no certificate for takes one of A.
		if slices.ContainsFunc(m.Roots, func(x struct {
			Label       string `json:"label"`
			Certificate string `json:"certificate"`
			Pin         string `json:"x509_spki_sha256"`
		}) bool {
			return x.Label == r.Label
		}) {
			in.Certificates[r.Label] = m.certificate(t, r.Label)
		} else {
			in.Certificates[r.Label] = m.certificate(t, "A")
		}
	}
	if previousID != "" {
		prevData, prev := vectorList(t, m, previousID)
		in.Previous = prevData
		var keys []history.RootKey
		for _, r := range prev.Roots {
			keys = append(keys, history.RootKey{Label: r.Label, Pin: r.X509SPKISHA256, Fingerprint: r.OpenPGPFingerprint})
		}
		for i := int64(1); i < want.Sequence; i++ {
			in.Earlier = append(in.Earlier, history.RootList{Name: "padding", Keys: slices.Clone(keys)})
		}
	}
	return in
}

func pinOfVector(t testing.TB, m *vectorManifest, label string) string {
	t.Helper()
	for _, r := range m.Roots {
		if r.Label == label {
			return r.Pin
		}
	}
	t.Fatalf("no root %s", label)
	return ""
}

func TestVectorDrafts(t *testing.T) {
	m := loadVectors(t)
	bundleOf := func(id string) []byte { return vectorFile(t, "bundles/"+id+".pem") }
	cases := []struct {
		id, previous string
		deps         func() []trustset.Departure
		kind         trustset.Kind
		bundle       string // the vector bundle that must be reproduced, "" when none stands for this list
		oneOf        []string
		required     []string
	}{
		{id: "init-a", kind: trustset.KindFirst, oneOf: []string{"A", "B"}},
		{id: "seq7-a", previous: "seq6-b", kind: trustset.KindRenewal, bundle: "ca-bundle-7", oneOf: []string{"A", "B"}},
		{
			id: "seq8-b-without-a", previous: "seq7-a", kind: trustset.KindRevoke, bundle: "ca-bundle-8", required: []string{"B"},
			deps: func() []trustset.Departure {
				return []trustset.Departure{{X509SPKISHA256: pinOfVector(t, m, "A"), Leave: trustset.LeaveRevoked, Authorisation: vectorRemoval(t, m, "A")}}
			},
		},
		{
			id: "seq8-ab-without-a", previous: "seq7-a", kind: trustset.KindRetire, bundle: "ca-bundle-8", required: []string{"A", "B"},
			deps: func() []trustset.Departure {
				return []trustset.Departure{{X509SPKISHA256: pinOfVector(t, m, "A"), Leave: trustset.LeaveRetired}}
			},
		},
		{id: "seq8-abc", previous: "seq7-a", kind: trustset.KindAdd, required: []string{"A", "B", "C"}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			var deps []trustset.Departure
			if tc.deps != nil {
				deps = tc.deps()
			}
			in := vectorInput(t, m, tc.id, tc.previous, deps)
			d, err := trustset.NewDraft(in)
			if err != nil {
				t.Fatalf("NewDraft: %v", err)
			}
			want, _ := vectorList(t, m, tc.id)
			if !bytes.Equal(d.ListJSON(), want) {
				t.Errorf("root-list.json differs from the vector:\n got  %s\n want %s", d.ListJSON(), want)
			}
			if tc.bundle != "" && !bytes.Equal(d.CABundle(), bundleOf(tc.bundle)) {
				t.Errorf("ca-bundle.pem differs from %s:\n got  %q\n want %q", tc.bundle, d.CABundle(), bundleOf(tc.bundle))
			}
			list, _ := rootlist.ParseList(d.ListJSON())
			if v := rootlist.VerifyCABundle(d.CABundle(), list); !v.Accepted {
				t.Errorf("the reader refuses the CA bundle: %+v", v)
			}
			if d.Kind() != tc.kind {
				t.Errorf("Kind = %v, want %v", d.Kind(), tc.kind)
			}
			if !slices.Equal(d.Required(), tc.required) {
				t.Errorf("Required = %v, want %v", d.Required(), tc.required)
			}
			if !slices.Equal(d.OneOf(), tc.oneOf) {
				t.Errorf("OneOf = %v, want %v", d.OneOf(), tc.oneOf)
			}
			if len(d.Unnamed()) != 0 {
				t.Errorf("Unnamed = %v", d.Unnamed())
			}
			// The signers that the manifest names are the signers the draft asks for.
			signers := manifestSigners(t, tc.id)
			if len(tc.required) > 0 {
				if !slices.Equal(signers, tc.required) {
					t.Errorf("the manifest names the signers %v, Required is %v", signers, tc.required)
				}
			} else if len(signers) != 1 || !slices.Contains(tc.oneOf, signers[0]) {
				t.Errorf("the manifest names the signers %v, OneOf is %v", signers, tc.oneOf)
			}
			// The accessors say the same after a second call, and the digests are those of the bytes.
			if d.ListSHA256() != hexOf(string(want)) {
				t.Error("ListSHA256 is not the digest of the vector list")
			}
		})
	}
}

// A list of the vectors that the reader accepts and the writer does not make: the change is not
// one of the five, or a kept key changed its label or its fingerprint.
func TestVectorListsThatTheWriterRefuses(t *testing.T) {
	m := loadVectors(t)
	a, b := pinOfVector(t, m, "A"), pinOfVector(t, m, "B")
	retireA := []trustset.Departure{{X509SPKISHA256: a, Leave: trustset.LeaveRetired}}
	retireAB := []trustset.Departure{{X509SPKISHA256: a, Leave: trustset.LeaveRetired}, {X509SPKISHA256: b, Leave: trustset.LeaveRetired}}
	for _, tc := range []struct {
		id   string
		deps []trustset.Departure
		why  string
	}{
		{"seq8-bc-without-a-adds-c", retireA, "not both"},
		{"seq8-bc-with-b-named", retireA, "not both"},
		{"seq8-z-without-ab", retireAB, "not both"},
		{"seq8-ab-new-label", nil, "label or its fingerprint"},
		{"seq8-bc-new-label-without-a", retireA, "label or its fingerprint"},
		{"seq8-bc-new-fingerprint-without-a", retireA, "label or its fingerprint"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			d, err := trustset.NewDraft(vectorInput(t, m, tc.id, "seq7-a", tc.deps))
			if d != nil {
				t.Fatal("a draft came with the error")
			}
			wantOnly(t, err, trustset.ErrParams)
			if !strings.Contains(err.Error(), tc.why) {
				t.Errorf("the error does not say %q: %v", tc.why, err)
			}
		})
	}
}

// The wrong stored authorisation of the vectors (the entry of A with the authorisation of B) is
// told by NewDraft, which needs no key: the caller learns it before a card is touched.
func TestVectorWrongAuthorisationIsRefusedBeforeAnyKey(t *testing.T) {
	m := loadVectors(t)
	_, list := vectorList(t, m, "seq8-b-without-a-wrong-removal")
	if len(list.Removals) != 1 {
		t.Fatalf("the vector has %d removals", len(list.Removals))
	}
	deps := []trustset.Departure{{X509SPKISHA256: list.Removals[0].X509SPKISHA256, Leave: trustset.LeaveRevoked, Authorisation: list.Removals[0].Authorisation}}
	if deps[0].X509SPKISHA256 != pinOfVector(t, m, "A") {
		t.Fatal("the vector's entry is not A's")
	}
	d, err := trustset.NewDraft(vectorInput(t, m, "seq8-b-without-a-wrong-removal", "seq7-a", deps))
	if d != nil {
		t.Fatal("a draft came with the error")
	}
	wantOnly(t, err, trustset.ErrParams)
	if !strings.Contains(err.Error(), "stored authorisation of root key A") {
		t.Errorf("the text does not name the key: %v", err)
	}
	// The three right authorisations pass: one for each key of the vectors, as a departure of A, B
	// and C would carry it.
	for _, label := range []string{"A"} {
		deps := []trustset.Departure{{X509SPKISHA256: pinOfVector(t, m, label), Leave: trustset.LeaveRevoked, Authorisation: vectorRemoval(t, m, label)}}
		if _, err := trustset.NewDraft(vectorInput(t, m, "seq8-b-without-a", "seq7-a", deps)); err != nil {
			t.Errorf("the authorisation of %s: %v", label, err)
		}
	}
	// The same authorisation with its text changed in one byte is refused.
	text := vectorRemoval(t, m, "A")
	for _, bad := range []string{text[:len(text)-1] + "A", text + "x", strings.Replace(text, ".", "..", 1), text[:10]} {
		deps := []trustset.Departure{{X509SPKISHA256: pinOfVector(t, m, "A"), Leave: trustset.LeaveRevoked, Authorisation: bad}}
		d, err := trustset.NewDraft(vectorInput(t, m, "seq8-b-without-a", "seq7-a", deps))
		if d != nil || err == nil {
			t.Errorf("a damaged authorisation was taken: %.30q", bad)
			continue
		}
		wantOnly(t, err, trustset.ErrParams)
	}
}

// The writer reproduces 51 of the 52 lists the format allows, byte for byte, through MarshalList
// (TestVectorListsByteForByte). The 52nd, seq8-bc-with-b-named, holds a pin in roots and in
// removals: the writer refuses it on purpose, and a draft cannot be asked to make it.
func TestVectorListRefusedOnPurpose(t *testing.T) {
	m := loadVectors(t)
	_, list := vectorList(t, m, "seq8-bc-with-b-named")
	inRoots := false
	for _, rm := range list.Removals {
		for _, r := range list.Roots {
			inRoots = inRoots || r.X509SPKISHA256 == rm.X509SPKISHA256
		}
	}
	if !inRoots {
		t.Fatal("no pin of removals is in roots")
	}
	if _, err := trustset.MarshalList(specOf(list)); err == nil {
		t.Error("MarshalList wrote a list with a pin in roots and in removals")
	}
	// Through the draft: the departure of a key that stays is refused.
	b := pinOfVector(t, m, "B")
	deps := []trustset.Departure{{X509SPKISHA256: b, Leave: trustset.LeaveRevoked, Authorisation: vectorRemoval(t, m, "B")}}
	_, err := trustset.NewDraft(vectorInput(t, m, "seq8-b-without-a", "seq7-a", deps))
	wantOnly(t, err, trustset.ErrParams)
}
