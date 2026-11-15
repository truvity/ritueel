package trustset_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// A draft whose X.509 roots and OpenPGP primaries carry the same mark, or that has no keyring file,
// gives the bytes that it gave before the two marks were compared. The files of testdata/same-mark
// were written by the code that did not compare the marks, from the certificates held in the same
// folder: a family of test roots with test primaries and a family of real roots with real
// primaries, each as a first list, as a renewal of it, and as a first list that pins no primary.
// The signature file of a list is made with a fresh random value each time, so it cannot be compared
// byte for byte: the file that was written then is judged by the reader of the page against the list
// that is written now.

type goldenRoot struct {
	Label       string `json:"label"`
	Pin         string `json:"x509_spki_sha256"`
	Fingerprint string `json:"openpgp_fingerprint"`
}

func goldenFile(t testing.TB, family, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "same-mark", family, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func goldenBase64(t testing.TB, family, name string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(goldenFile(t, family, name))))
	if err != nil {
		t.Fatalf("%s/%s: %v", family, name, err)
	}
	return out
}

// goldenInput is the input of the list, first or second, of a family, with or without the
// fingerprints of the primaries.
func goldenInput(t testing.TB, family string, second, withPrimaries bool) trustset.Input {
	t.Helper()
	var entries []goldenRoot
	if err := json.Unmarshal(goldenFile(t, family, "input.json"), &entries); err != nil {
		t.Fatal(err)
	}
	in := trustset.Input{
		Sequence:     1,
		SignedAt:     firstCeremony,
		Certificates: map[string][]byte{},
	}
	var earlier []trustset.Root
	for _, e := range entries {
		block, _ := pem.Decode(goldenFile(t, family, "root-"+e.Label+".crt"))
		if block == nil {
			t.Fatalf("%s: no certificate for %s", family, e.Label)
		}
		in.Certificates[e.Label] = block.Bytes
		root := trustset.Root{Label: e.Label, X509SPKISHA256: e.Pin}
		if withPrimaries {
			root.OpenPGPFingerprint = e.Fingerprint
			if in.OpenPGPCertificates == nil {
				in.OpenPGPCertificates = map[string][]byte{}
			}
			in.OpenPGPCertificates[e.Label] = goldenBase64(t, family, "primary-"+e.Label+".b64")
		}
		in.Roots = append(in.Roots, root)
		earlier = append(earlier, root)
	}
	if second {
		in.Sequence = 2
		in.SignedAt = firstCeremony.Add(time.Hour)
		in.LastRecordSHA256 = lastRecord(2)
		in.Previous = goldenFile(t, family, "first-root-list.json")
		in.Earlier = []history.RootList{historyList("trust/1-golden", earlier)}
	}
	return in
}

// judge asks the reader of the page about a signature file that was written before, with the list
// that the draft writes now.
func judge(t testing.TB, d *trustset.Draft, jwsFile, previous []byte, at time.Time) {
	t.Helper()
	var trust rootlist.Trust
	if previous == nil {
		list, err := rootlist.ParseList(d.ListJSON())
		if err != nil {
			t.Fatal(err)
		}
		if trust, err = rootlist.PinTrust(list.Pins()); err != nil {
			t.Fatal(err)
		}
	} else {
		held, err := rootlist.ParseHeld(previous)
		if err != nil {
			t.Fatal(err)
		}
		trust = rootlist.HeldTrust(held)
	}
	v := rootlist.Verify(rootlist.Signed{JSON: d.ListJSON(), JWS: jwsFile}, trust, at)
	if !v.Accepted {
		t.Errorf("the reader of the page refuses the signature file of before against the list of now: %+v", v)
	}
}

func TestSameMarkGivesTheBytesOfBefore(t *testing.T) {
	for _, family := range []string{"test", "real"} {
		isTest := family == "test"
		// The fixture is what it says: the common names and the user IDs carry the mark or none does.
		for _, l := range []string{"A", "B", "C"} {
			block, _ := pem.Decode(goldenFile(t, family, "root-"+l+".crt"))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.HasSuffix(cert.Subject.CommonName, "(TEST ONLY)"); got != isTest {
				t.Fatalf("%s root %s: the mark of its name is %v", family, l, got)
			}
			if got := bytes.Contains(goldenBase64(t, family, "primary-"+l+".b64"), []byte(" (TEST ONLY) <")); got != isTest {
				t.Fatalf("%s primary %s: the mark of its user ID is %v", family, l, got)
			}
		}
		t.Run(family+" first list with the keyring file", func(t *testing.T) {
			in := goldenInput(t, family, false, true)
			d, err := trustset.NewDraft(in)
			if err != nil {
				t.Fatal(err)
			}
			wantKeyring := goldenBase64(t, family, "first-keyring.b64")
			if !bytes.Equal(d.ListJSON(), goldenFile(t, family, "first-root-list.json")) {
				t.Error("root-list.json differs from the bytes of before")
			}
			if !bytes.Equal(d.CABundle(), goldenFile(t, family, "first-ca-bundle.crt")) {
				t.Error("ca-bundle.pem differs from the bytes of before")
			}
			if !bytes.Equal(d.Keyring(), wantKeyring) {
				t.Error("keyring.gpg differs from the bytes of before")
			}
			if d.KeyringSHA256() != hexOfBytes(wantKeyring) {
				t.Error("the digest of the keyring file differs")
			}
			judge(t, d, goldenFile(t, family, "first-root-list.jws"), nil, in.SignedAt)
		})
		t.Run(family+" renewal with the keyring file", func(t *testing.T) {
			in := goldenInput(t, family, true, true)
			d, err := trustset.NewDraft(in)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(d.ListJSON(), goldenFile(t, family, "second-root-list.json")) {
				t.Error("root-list.json differs from the bytes of before")
			}
			if !bytes.Equal(d.CABundle(), goldenFile(t, family, "second-ca-bundle.crt")) {
				t.Error("ca-bundle.pem differs from the bytes of before")
			}
			if !bytes.Equal(d.Keyring(), goldenBase64(t, family, "second-keyring.b64")) {
				t.Error("keyring.gpg differs from the bytes of before")
			}
			judge(t, d, goldenFile(t, family, "second-root-list.jws"), goldenFile(t, family, "first-root-list.json"), in.SignedAt)
		})
		t.Run(family+" list that pins no primary", func(t *testing.T) {
			in := goldenInput(t, family, false, false)
			d, err := trustset.NewDraft(in)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(d.ListJSON(), goldenFile(t, family, "bare-root-list.json")) {
				t.Error("root-list.json differs from the bytes of before")
			}
			if !bytes.Equal(d.CABundle(), goldenFile(t, family, "bare-ca-bundle.crt")) {
				t.Error("ca-bundle.pem differs from the bytes of before")
			}
			if d.Keyring() != nil || d.KeyringSHA256() != "" {
				t.Error("a keyring file for a list that pins no primary")
			}
			judge(t, d, goldenFile(t, family, "bare-root-list.jws"), nil, in.SignedAt)
		})
	}
}

func hexOfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
