package trustset_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/testrepo"
	"ritueel.id/ritueel/internal/trustset"
)

// The vectors of testdata/root-list/v1 hold no private key, so the part that needs one is not
// compared: the .jws. What is compared is every byte of root-list.json and of ca-bundle.pem. The
// test holds no pin, digest or byte string of the vectors: they are read from the files, and the
// vectors may be made again with new keys.

const vectorDir = "testdata/root-list/v1"

func vectorFile(t testing.TB, rel string) []byte { return testrepo.Read(t, vectorDir, rel) }

type vectorManifest struct {
	Roots []struct {
		Label       string `json:"label"`
		Certificate string `json:"certificate"`
		Pin         string `json:"x509_spki_sha256"`
		OpenPGP     string `json:"openpgp"`
		Fingerprint string `json:"openpgp_fingerprint"`
	} `json:"roots"`
	Removals []struct {
		Label string `json:"label"`
		File  string `json:"file"`
	} `json:"removals"`
	Lists []struct {
		ID    string   `json:"id"`
		Files []string `json:"files"`
		Flaw  string   `json:"flaw"`
	} `json:"lists"`
	Bundles []struct {
		ID       string   `json:"id"`
		File     string   `json:"file"`
		Sequence int64    `json:"sequence"`
		Roots    []string `json:"roots"`
		Flaw     string   `json:"flaw"`
	} `json:"bundles"`
}

func loadVectors(t testing.TB) *vectorManifest {
	t.Helper()
	var m vectorManifest
	if err := json.Unmarshal(vectorFile(t, "manifest.json"), &m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if len(m.Lists) == 0 || len(m.Roots) == 0 || len(m.Bundles) == 0 {
		t.Fatal("the manifest has no lists, roots or bundles")
	}
	return &m
}

// primary returns the public certificate of the vector primary with the fingerprint, read from its
// file of the set, or nil when the manifest has no primary with it.
func (m *vectorManifest) primary(t testing.TB, fingerprint string) []byte {
	t.Helper()
	for _, r := range m.Roots {
		if r.Fingerprint == fingerprint && r.OpenPGP != "" {
			return vectorFile(t, r.OpenPGP)
		}
	}
	return nil
}

// certificate returns the DER certificate of a vector root, read from its PEM file.
func (m *vectorManifest) certificate(t testing.TB, label string) []byte {
	t.Helper()
	for _, r := range m.Roots {
		if r.Label == label {
			block, _ := pem.Decode(vectorFile(t, r.Certificate))
			if block == nil || block.Type != "CERTIFICATE" {
				t.Fatalf("%s is not a PEM certificate", r.Certificate)
			}
			return block.Bytes
		}
	}
	t.Fatalf("the manifest has no root %s", label)
	return nil
}

// specOf turns a list that the reader accepts into the spec that gives it again.
func specOf(l *rootlist.List) trustset.ListSpec {
	spec := trustset.ListSpec{Sequence: l.Sequence, SignedAt: l.SignedAt, LastRecordSHA256: l.LastRecordSHA256}
	for _, r := range l.Roots {
		spec.Roots = append(spec.Roots, trustset.Root(r))
	}
	for _, r := range l.Removals {
		spec.Removals = append(spec.Removals, trustset.Removal(r))
	}
	return spec
}

// looseSpec reads a list with encoding/json and no rule of the page, so that a list that the
// reader refuses can still be turned into a spec. The version is not carried: the writer writes
// version 1 only.
func looseSpec(t testing.TB, data []byte) trustset.ListSpec {
	t.Helper()
	var raw struct {
		SignedAt         string `json:"signed_at"`
		LastRecordSHA256 string `json:"last_record_sha256"`
		Sequence         int64  `json:"sequence"`
		Roots            []struct {
			Label       string `json:"label"`
			Fingerprint string `json:"openpgp_fingerprint"`
			Pin         string `json:"x509_spki_sha256"`
		} `json:"roots"`
		Removals []struct {
			Authorisation string `json:"authorisation"`
			Label         string `json:"label"`
			Pin           string `json:"x509_spki_sha256"`
		} `json:"removals"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("a list with a plain JSON reader: %v", err)
	}
	signed, err := time.Parse(rootlist.TimeLayout, raw.SignedAt)
	if err != nil {
		t.Fatalf("signed_at: %v", err)
	}
	spec := trustset.ListSpec{Sequence: raw.Sequence, SignedAt: signed, LastRecordSHA256: raw.LastRecordSHA256}
	for _, r := range raw.Roots {
		spec.Roots = append(spec.Roots, trustset.Root{Label: r.Label, X509SPKISHA256: r.Pin, OpenPGPFingerprint: r.Fingerprint})
	}
	for _, r := range raw.Removals {
		spec.Removals = append(spec.Removals, trustset.Removal{Label: r.Label, X509SPKISHA256: r.Pin, Authorisation: r.Authorisation})
	}
	return spec
}

// skipped are the lists that the byte for byte test does not reproduce, each with its reason: the
// twelve that the manifest marks with a flaw and the two that the reader refuses for another
// reason. A vector that is neither compared nor named here fails the test, so a new list that the
// writer cannot reproduce is not skipped by being new.
var skipped = map[string]string{
	"seq7-a-expires-13m1s":                          "flaw: expires_at is not 13 months",
	"seq7-a-expires-12m":                            "flaw: expires_at is not 13 months",
	"seq7-a-signed-in-the-future":                   "flaw: signed_at is after the clock of the case",
	"seq7-a-signed-2026-01-31-plain-month-addition": "flaw: expires_at by plain month addition",
	"seq7-a-signed-2027-01-30-plain-month-addition": "flaw: expires_at by plain month addition",
	"seq7-a-label-twice":                            "flaw: a label twice",
	"seq7-a-pin-twice":                              "flaw: a pin twice",
	"seq7-a-fingerprint-wrong-form":                 "flaw: a fingerprint of the wrong form",
	"seq7-a-last-record-digest-wrong-form":          "flaw: a digest of the wrong form",
	"seq0-a":                                        "flaw: sequence 0",
	"seq8-b-without-a-removal-twice":                "flaw: a pin twice in removals",
	"seq8-b-without-a-empty-authorisation":          "flaw: an empty authorisation",
	"seq8-a-version-2":                              "the reader refuses it: version 2",
	"seq8-a-unknown-member":                         "the reader refuses it: a member the page does not define",
}

// writerRefuses are the lists that the reader accepts and the writer refuses, each with the words
// of its refusal. The hosts refuse them too, when they hold a list (check 9: the removed key is
// "not on this list"), so the writer does not make them.
var writerRefuses = map[string]string{
	"seq8-bc-with-b-named": "the pin is also the pin of a root key of the list",
}

func TestVectorListsByteForByte(t *testing.T) {
	m := loadVectors(t)
	compared := 0
	var notCompared []string
	for _, l := range m.Lists {
		var jsonFile string
		for _, f := range l.Files {
			if strings.HasSuffix(f, ".json") {
				jsonFile = f
			}
		}
		if jsonFile == "" {
			t.Errorf("list %s has no .json file", l.ID)
			continue
		}
		data := vectorFile(t, jsonFile)
		parsed, perr := rootlist.ParseList(data)
		reason, named := skipped[l.ID]
		if why, ok := writerRefuses[l.ID]; ok {
			if named || l.Flaw != "" || perr != nil {
				t.Errorf("list %s is named for a refusal of the writer, but it has a flaw or the reader refuses it", l.ID)
				continue
			}
			if _, err := trustset.MarshalList(specOf(parsed)); err == nil || !errors.Is(err, trustset.ErrParams) || !strings.Contains(err.Error(), why) {
				t.Errorf("list %s: MarshalList gave %v, want ErrParams with %q", l.ID, err, why)
			}
			notCompared = append(notCompared, l.ID+": the writer refuses it: "+why)
			continue
		}
		if l.Flaw != "" || perr != nil {
			if !named {
				t.Errorf("list %s (flaw %q, ParseList: %v) is neither reproduced nor named in the skip list", l.ID, l.Flaw, perr)
			}
			notCompared = append(notCompared, l.ID+": "+reason)
			continue
		}
		if named {
			t.Errorf("list %s is named in the skip list (%s) but it has no flaw and the reader accepts it", l.ID, reason)
		}
		got, err := trustset.MarshalList(specOf(parsed))
		if err != nil {
			t.Errorf("list %s: MarshalList: %v", l.ID, err)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("list %s differs from the vector:\n got  %s\n want %s", l.ID, got, data)
			continue
		}
		compared++
	}
	for id := range writerRefuses {
		found := false
		for _, l := range m.Lists {
			found = found || l.ID == id
		}
		if !found {
			t.Errorf("the writer-refuses list names %s, which the manifest does not have", id)
		}
	}
	for id := range skipped {
		found := false
		for _, l := range m.Lists {
			found = found || l.ID == id
		}
		if !found {
			t.Errorf("the skip list names %s, which the manifest does not have", id)
		}
	}
	sort.Strings(notCompared)
	t.Logf("compared %d lists byte for byte; not compared %d:", compared, len(notCompared))
	for _, n := range notCompared {
		t.Logf("  %s", n)
	}
	if compared < 51 {
		t.Errorf("only %d lists were compared, the vectors hold at least 51 that the format allows", compared)
	}
	if compared+len(notCompared) != len(m.Lists) {
		t.Errorf("compared %d, not compared %d, the manifest has %d lists", compared, len(notCompared), len(m.Lists))
	}
}

// Roots and removals in another order give the bytes of the vector.
func TestVectorListsWhateverTheOrderOfTheEntries(t *testing.T) {
	m := loadVectors(t)
	n := 0
	for _, l := range m.Lists {
		if _, skip := skipped[l.ID]; skip {
			continue
		}
		if _, skip := writerRefuses[l.ID]; skip {
			continue
		}
		data := vectorFile(t, l.Files[0])
		parsed, err := rootlist.ParseList(data)
		if err != nil {
			continue
		}
		spec := specOf(parsed)
		if len(spec.Roots) < 2 && len(spec.Removals) < 2 {
			continue
		}
		slices.Reverse(spec.Roots)
		slices.Reverse(spec.Removals)
		got, err := trustset.MarshalList(spec)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("list %s in reverse order: %v", l.ID, err)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no vector list has two entries to put in another order")
	}
}

// The writer and the reader refuse the same flaws: a flawed list whose flaw the writer can see is
// ErrParams.
func TestVectorFlawedListsAreRefusedByWriterAndReader(t *testing.T) {
	m := loadVectors(t)
	refused := []string{
		"seq0-a", "seq7-a-label-twice", "seq7-a-pin-twice", "seq7-a-fingerprint-wrong-form",
		"seq7-a-last-record-digest-wrong-form", "seq8-b-without-a-removal-twice", "seq8-b-without-a-empty-authorisation",
	}
	for _, id := range refused {
		var file string
		for _, l := range m.Lists {
			if l.ID == id {
				file = l.Files[0]
			}
		}
		if file == "" {
			t.Errorf("the manifest has no list %s", id)
			continue
		}
		data := vectorFile(t, file)
		if _, err := rootlist.ParseList(data); err == nil {
			t.Errorf("%s: the reader accepts it", id)
		}
		out, err := trustset.MarshalList(looseSpec(t, data))
		if err == nil {
			t.Errorf("%s: the writer wrote %s", id, out)
			continue
		}
		if out != nil {
			t.Errorf("%s: bytes come with the error", id)
		}
		wantParams(t, err)
	}
}

// The date flaws: the writer writes the expiry of the page, not the one in the vector. The list
// that is signed "in the future" is a flaw of the case, not of the file: the writer reads no clock
// and writes it.
func TestVectorDateFlawsAreNotReproduced(t *testing.T) {
	m := loadVectors(t)
	for _, id := range []string{
		"seq7-a-expires-13m1s", "seq7-a-expires-12m",
		"seq7-a-signed-2026-01-31-plain-month-addition", "seq7-a-signed-2027-01-30-plain-month-addition",
	} {
		var file string
		for _, l := range m.Lists {
			if l.ID == id {
				file = l.Files[0]
			}
		}
		if file == "" {
			t.Errorf("the manifest has no list %s", id)
			continue
		}
		data := vectorFile(t, file)
		parsed, err := rootlist.ParseList(data)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		got, err := trustset.MarshalList(specOf(parsed))
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if bytes.Equal(got, data) {
			t.Errorf("%s: the writer wrote the flawed expiry of the vector", id)
		}
		again, err := rootlist.ParseList(got)
		if err != nil {
			t.Fatal(err)
		}
		if want := rootlist.ExpiresFor(parsed.SignedAt); !again.ExpiresAt.Equal(want) || again.ExpiresAt.Equal(parsed.ExpiresAt) {
			t.Errorf("%s: expires_at %v, the vector has %v, the page says %v", id, again.ExpiresAt, parsed.ExpiresAt, want)
		}
	}
	for _, l := range m.Lists {
		if l.ID != "seq7-a-signed-in-the-future" {
			continue
		}
		data := vectorFile(t, l.Files[0])
		parsed, err := rootlist.ParseList(data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := trustset.MarshalList(specOf(parsed))
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("the list signed after the clock of its case is written as it is: %v", err)
		}
	}
}

// A list that the reader refuses for a member the page does not define: the writer has no such
// member to write, so what it writes from the rest is a list that the reader accepts and that
// differs from the file.
func TestVectorUnknownMemberIsNotWritten(t *testing.T) {
	m := loadVectors(t)
	for _, l := range m.Lists {
		if l.ID != "seq8-a-unknown-member" && l.ID != "seq8-a-version-2" {
			continue
		}
		data := vectorFile(t, l.Files[0])
		out, err := trustset.MarshalList(looseSpec(t, data))
		if err != nil {
			t.Errorf("%s: %v", l.ID, err)
			continue
		}
		if bytes.Equal(out, data) {
			t.Errorf("%s: the writer wrote the file with its flaw", l.ID)
		}
		if _, err := rootlist.ParseList(out); err != nil {
			t.Errorf("%s: %v", l.ID, err)
		}
	}
}

func TestVectorBundlesByteForByte(t *testing.T) {
	m := loadVectors(t)
	reproduced := 0
	for _, b := range m.Bundles {
		if b.Flaw != "" {
			continue
		}
		data := vectorFile(t, b.File)
		list := vectorBundleList(t, m, b.Sequence, b.Roots)
		var certs [][]byte
		for _, label := range b.Roots {
			certs = append(certs, m.certificate(t, label))
		}
		got, err := trustset.MarshalCABundle(b.Sequence, list, certs)
		if err != nil {
			t.Errorf("%s: %v", b.ID, err)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s differs from the vector:\n got  %q\n want %q", b.ID, got, data)
			continue
		}
		reproduced++
		t.Logf("reproduced %s byte for byte (%d bytes)", b.ID, len(got))
	}
	if reproduced != 2 {
		t.Errorf("%d bundles were reproduced, the vectors hold two without a flaw", reproduced)
	}
}

// vectorBundleList is the roots of a bundle: the labels of the vector with their pins.
func vectorBundleList(t testing.TB, m *vectorManifest, _ int64, labels []string) []trustset.Root {
	t.Helper()
	var out []trustset.Root
	for _, label := range labels {
		found := false
		for _, r := range m.Roots {
			if r.Label == label {
				out = append(out, trustset.Root{Label: label, X509SPKISHA256: r.Pin})
				found = true
			}
		}
		if !found {
			t.Fatalf("the manifest has no root %s", label)
		}
	}
	return out
}

// The flawed bundles are refused by the writer, as the reader of the page refuses them.
func TestVectorFlawedBundlesAreRefused(t *testing.T) {
	m := loadVectors(t)
	refused, named := 0, map[string]bool{}
	var goodRoots []string
	for _, b := range m.Bundles {
		if b.ID == "ca-bundle-7" {
			goodRoots = b.Roots
		}
	}
	if len(goodRoots) != 2 {
		t.Fatalf("the manifest's bundle 7 has the roots %v", goodRoots)
	}
	for _, b := range m.Bundles {
		if b.Flaw == "" {
			continue
		}
		named[b.ID] = true
		if b.ID == "ca-bundle-8-of-list-7" {
			// A bundle of the right certificates under the wrong sequence line: the writer
			// writes the line it is given, so there is nothing to refuse. The reader refuses it.
			continue
		}
		data := vectorFile(t, b.File)
		var certs [][]byte
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			certs = append(certs, block.Bytes)
		}
		// The roots are those of the list that the bundle is meant for, which is list 7 for every
		// flawed bundle here (the manifest names the roots that the file holds).
		list := vectorBundleList(t, m, b.Sequence, goodRoots)
		out, err := trustset.MarshalCABundle(b.Sequence, list, certs)
		if err == nil {
			t.Errorf("%s (%s): the writer wrote %q", b.ID, b.Flaw, out)
			continue
		}
		if out != nil {
			t.Errorf("%s: bytes come with the error", b.ID)
		}
		wantParams(t, err)
		refused++
	}
	for _, id := range []string{
		"ca-bundle-7-signed-by-another-key", "ca-bundle-7-not-a-ca", "ca-bundle-7-issuer-is-another-name",
		"ca-bundle-7-extra-certificate", "ca-bundle-7-missing-certificate", "ca-bundle-7-wrong-order", "ca-bundle-8-of-list-7",
	} {
		if !named[id] {
			t.Errorf("the manifest has no flawed bundle %s", id)
		}
	}
	if refused < 6 {
		t.Errorf("%d flawed bundles were refused, want 6", refused)
	}
}

// The three authorisations of the vectors are valid under the check that the host runs, and the
// writer's own authorisations have the shape of theirs.
func TestVectorRemovalsAreValid(t *testing.T) {
	m := loadVectors(t)
	if len(m.Removals) == 0 {
		t.Fatal("no removal in the manifest")
	}
	for _, r := range m.Removals {
		var pin string
		for _, root := range m.Roots {
			if root.Label == r.Label {
				pin = root.Pin
			}
		}
		text := string(vectorFile(t, r.File))
		entry := rootlist.Removal{Label: r.Label, X509SPKISHA256: pin, Authorisation: text}
		if err := rootlist.CheckRemoval(entry, nil, []string{pin}); err != nil {
			t.Errorf("the vector authorisation of %s: %v", r.Label, err)
		}
	}
}
