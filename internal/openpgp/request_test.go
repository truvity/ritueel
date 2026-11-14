package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// These tests read the exported reader of a subkey request (docs/reference/hand-off-contract.md,
// "OpenPGP subkey", "The request"): the file that holds one Public-Subkey packet and one
// back-signature for each listed primary. Each expectation is what the page says. The fixtures are
// the vector files and keys made in memory.

// vectorSubkeyFiles are the request files of the vector set that hold an OpenPGP subkey, with the
// number of packets that follow the subkey in each.
var vectorSubkeyFiles = []struct {
	name       string
	signatures int
}{
	{"pgp-backsig-missing", 0},
	{"pgp-backsig-missing-one", 1},
	{"pgp-backsig-no-key-id", 2},
	{"pgp-backsig-tampered", 2},
	{"pgp-backsig-wrong-primary", 2},
	{"pgp-backsig-wrong-type", 2},
	{"pgp-capabilities-two", 2},
	{"pgp-capability-encrypt", 2},
	{"pgp-ed25519", 2},
	{"pgp-kms-valid", 2},
	{"pgp-openpgp-card-authenticate", 2},
	{"pgp-openpgp-card-untrusted-chain", 2},
	{"pgp-openpgp-card-valid", 2},
	{"pgp-piv-key-mismatch", 2},
	{"pgp-piv-valid", 2},
	{"pgp-primaries-incomplete", 1},
	{"pgp-response-request", 2},
	{"pgp-software-valid", 2},
	{"pgp-unknown-primary", 2},
	{"pgp-version-2", 2},
}

// validPairs are the vector requests whose two back-signatures are the ones the page gives, for the
// primaries A and B in this order.
var validPairs = []string{
	"pgp-software-valid", "pgp-response-request", "pgp-piv-valid", "pgp-kms-valid",
	"pgp-openpgp-card-valid", "pgp-openpgp-card-authenticate", "pgp-openpgp-card-untrusted-chain",
	"pgp-piv-key-mismatch", "pgp-version-2", "pgp-capabilities-two", "pgp-capability-encrypt",
}

func subkeyFile(t testing.TB, name string) []byte {
	t.Helper()
	return vector(t, "requests", name+".subkey.pgp")
}

// primaryOf makes the primary of a vector label ("a" or "b") by the function under test.
func primaryOf(t testing.TB, label string) *openpgp.PrimaryKey {
	t.Helper()
	pub, _ := vectorPrimary(t, label)
	p, err := openpgp.NewPrimaryKey(pub, created)
	if err != nil {
		t.Fatalf("NewPrimaryKey(%s): %v", label, err)
	}
	return p
}

// fingerprintOfBody is the version 4 fingerprint of a key packet body, by the standard: SHA-1 over
// 0x99, the two-byte length and the body.
func fingerprintOfBody(body []byte) string {
	h := sha1.New() //nolint:gosec // see the import
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// vectorPrimaryFingerprints are the fingerprints of the primaries A and B as the vector set names
// them: the proof of a request lists the primaries that it is bound to, in the order A, B. They are
// written by the generator and are not computed by the package, so a new run of the generator, which
// makes new keys, changes them and the tests with them.
func vectorPrimaryFingerprints(t testing.TB) (a, b string) {
	t.Helper()
	var proof struct {
		Primaries []string `json:"primaries"`
	}
	if err := json.Unmarshal(vector(t, "requests", "pgp-software-valid.proof.json"), &proof); err != nil {
		t.Fatalf("the proof of pgp-software-valid: %v", err)
	}
	if len(proof.Primaries) != 2 {
		t.Fatalf("the proof of pgp-software-valid lists %d primaries, want 2 (A and B)", len(proof.Primaries))
	}
	for _, fp := range proof.Primaries {
		if len(fp) != 40 || strings.Trim(fp, "0123456789abcdef") != "" {
			t.Fatalf("the proof names the primary %q: not 40 lower-case hexadecimal digits", fp)
		}
	}
	if proof.Primaries[0] == proof.Primaries[1] {
		t.Fatal("the proof names one fingerprint for both primaries")
	}
	return proof.Primaries[0], proof.Primaries[1]
}

// boundSubkeyFingerprints are the fingerprints that the vector set gives to the subkeys of two
// requests, by a second file: the answer to a request starts with the same subkey packet, and its
// fingerprint is taken from that packet by the standard (fingerprintOfBody), with no package code.
func boundSubkeyFingerprints(t testing.TB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for request, response := range map[string]string{
		"pgp-software-valid":   "pgp-software-valid",
		"pgp-response-request": "pgp-response-other-primary",
	} {
		ps := splitPackets(t, vector(t, "responses", response+".bound.pgp"))
		if len(ps) == 0 || ps[0].Tag != tagSubkey {
			t.Fatalf("the answer %s does not start with a subkey packet", response)
		}
		if !bytes.Equal(ps[0].Raw, splitPackets(t, subkeyFile(t, request))[0].Raw) {
			t.Fatalf("the answer %s starts with another subkey than the request %s", response, request)
		}
		out[request] = fingerprintOfBody(ps[0].Body)
	}
	return out
}

// isRequestError tells whether err is one of the three kinds of a faulty request and is also an
// ErrRequest and no ErrParams.
func isRequestError(err error, kind error) bool {
	return errors.Is(err, kind) && errors.Is(err, openpgp.ErrRequest) && !errors.Is(err, openpgp.ErrParams)
}

func TestTheVectorDirectoryHoldsExactlyTheTwentyRequestsOfTheTable(t *testing.T) {
	entries, err := os.ReadDir(testrepo.Path(t, "testdata", "hand-off", "v1", "requests"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, "pgp-") && strings.HasSuffix(n, ".subkey.pgp") {
			have[strings.TrimSuffix(n, ".subkey.pgp")] = true
		}
	}
	if len(have) != len(vectorSubkeyFiles) {
		t.Errorf("the directory holds %d subkey files, the table %d", len(have), len(vectorSubkeyFiles))
	}
	for _, f := range vectorSubkeyFiles {
		if !have[f.name] {
			t.Errorf("%s is in the table and not in the directory", f.name)
		}
	}
}

func TestSplitSubkeyFileSplitsEveryVectorRequestIntoTheSubkeyAndItsBackSignatures(t *testing.T) {
	for _, f := range vectorSubkeyFiles {
		t.Run(f.name, func(t *testing.T) {
			file := subkeyFile(t, f.name)
			ps := splitPackets(t, file)
			subkey, sigs, err := openpgp.SplitSubkeyFile(file, 16)
			if err != nil {
				t.Fatalf("SplitSubkeyFile: %v", err)
			}
			if ps[0].Tag != tagSubkey || ps[0].HeaderLen != 6 {
				t.Fatalf("the vector's first packet has tag %d and a header of %d bytes, want 14 and 6", ps[0].Tag, ps[0].HeaderLen)
			}
			if !bytes.Equal(subkey, ps[0].Raw) {
				t.Error("the subkey is not the first packet with its header")
			}
			if len(sigs) != f.signatures || len(ps)-1 != f.signatures {
				t.Fatalf("%d packets after the subkey (the independent reader sees %d), want %d", len(sigs), len(ps)-1, f.signatures)
			}
			whole := bytes.Clone(subkey)
			for i, s := range sigs {
				if !bytes.Equal(s, ps[i+1].Raw) {
					t.Errorf("packet %d is not the packet of the file at that place", i+1)
				}
				whole = append(whole, s...)
			}
			if !bytes.Equal(whole, file) {
				t.Error("the packets, joined, are not the file")
			}
		})
	}
}

func TestReadSubkeyReadsTheSubkeyOfEveryVectorRequestThatHasAP384Key(t *testing.T) {
	want := boundSubkeyFingerprints(t)
	read := 0
	for _, f := range vectorSubkeyFiles {
		if f.name == "pgp-ed25519" {
			continue
		}
		t.Run(f.name, func(t *testing.T) {
			ps := splitPackets(t, subkeyFile(t, f.name))
			sub, err := openpgp.ReadSubkey(ps[0].Raw)
			if err != nil {
				t.Fatalf("ReadSubkey: %v", err)
			}
			read++
			body := ps[0].Body
			fp := fingerprintOfBody(body)
			if got := sub.Fingerprint(); got != fp {
				t.Errorf("Fingerprint = %q, the standard gives %q", got, fp)
			}
			if w, ok := want[f.name]; ok && sub.Fingerprint() != w {
				t.Errorf("Fingerprint = %q, want %q", sub.Fingerprint(), w)
			}
			wantAt := time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0).UTC()
			if got := sub.Created(); !got.Equal(wantAt) || got.Location() != time.UTC {
				t.Errorf("Created = %v, want %v in UTC", got, wantAt)
			}
			if f.name == "pgp-software-valid" || f.name == "pgp-response-request" {
				if got := sub.Created().Unix(); got != 1792454400 {
					t.Errorf("Created = %d, want 1792454400", got)
				}
			}
			if got := point(sub.PublicKey()); !bytes.Equal(got, body[len(body)-97:]) {
				t.Error("PublicKey is not the point of the packet")
			}
			// A second reader of the packet agrees: go-crypto reads the same key and fingerprint.
			p, err := gopacket.Read(bytes.NewReader(ps[0].Raw))
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(p.(*gopacket.PublicKey).Fingerprint); got != sub.Fingerprint() {
				t.Errorf("go-crypto reads the fingerprint %s, ReadSubkey %s", got, sub.Fingerprint())
			}
		})
	}
	if read != 19 {
		t.Errorf("%d subkeys read, want 19: a check that finds nothing to check fails", read)
	}
}

func TestReadSubkeyRefusesTheEd25519VectorAsAnAlgorithmAndNotAsAForm(t *testing.T) {
	ps := splitPackets(t, subkeyFile(t, "pgp-ed25519"))
	if ps[0].Body[0] != 4 || ps[0].Body[5] != 22 {
		t.Fatalf("the vector holds version %d, algorithm %d, want 4 and 22", ps[0].Body[0], ps[0].Body[5])
	}
	sub, err := openpgp.ReadSubkey(ps[0].Raw)
	if sub != nil {
		t.Error("a Subkey came back with the error")
	}
	if !isRequestError(err, openpgp.ErrAlgorithm) {
		t.Fatalf("error = %v, want an ErrAlgorithm that is an ErrRequest", err)
	}
	if errors.Is(err, openpgp.ErrForm) || errors.Is(err, openpgp.ErrBackSignature) {
		t.Errorf("error %v is also another kind", err)
	}
}

// The page: each back-signature "verifies with the subkey over that primary and the subkey, and
// carries the issuer fingerprint and the issuer key ID of the subkey"; one that is missing, of
// another type, over another primary, without the key ID or damaged is refused.
func TestVerifyBackSignatureAcceptsTheValidVectorsOnlyForTheirOwnPrimaryAndInOrder(t *testing.T) {
	primaries := []*openpgp.PrimaryKey{primaryOf(t, "a"), primaryOf(t, "b")}
	if primaries[0].Fingerprint() == primaries[1].Fingerprint() {
		t.Fatal("the two primaries are the same")
	}
	for _, name := range validPairs {
		t.Run(name, func(t *testing.T) {
			file := subkeyFile(t, name)
			subRaw, sigs, err := openpgp.SplitSubkeyFile(file, 16)
			if err != nil || len(sigs) != 2 {
				t.Fatalf("split: %d signatures, %v", len(sigs), err)
			}
			sub, err := openpgp.ReadSubkey(subRaw)
			if err != nil {
				t.Fatal(err)
			}
			for i, sig := range sigs {
				for j, p := range primaries {
					err := openpgp.VerifyBackSignature(sig, p, sub, ceremony)
					if i == j && err != nil {
						t.Errorf("signature %d for primary %d: %v, want it accepted", i+1, j+1, err)
					}
					if i != j && !isRequestError(err, openpgp.ErrBackSignature) {
						t.Errorf("signature %d for primary %d: %v, want an ErrBackSignature", i+1, j+1, err)
					}
				}
			}
		})
	}
}

// The four faults that the page names, as vector files. For each, the request as a whole (signature
// i for primary i, in order, exactly two of them) is not accepted, and every refusal is an
// ErrBackSignature.
func TestVerifyBackSignatureRefusesTheFaultyVectorsTheWayThePageSaysAndAgreesWithAnIndependentReader(t *testing.T) {
	primaries := []*openpgp.PrimaryKey{primaryOf(t, "a"), primaryOf(t, "b")}
	pubs := []*ecdsa.PublicKey{}
	for _, l := range []string{"a", "b"} {
		pub, _ := vectorPrimary(t, l)
		pubs = append(pubs, pub)
	}
	faulty := map[string]bool{
		"pgp-backsig-no-key-id": true, "pgp-backsig-tampered": true, "pgp-backsig-wrong-primary": true,
		"pgp-backsig-wrong-type": true, "pgp-backsig-missing": true, "pgp-backsig-missing-one": true,
		"pgp-primaries-incomplete": true,
	}
	for _, f := range vectorSubkeyFiles {
		if f.name == "pgp-ed25519" {
			continue
		}
		t.Run(f.name, func(t *testing.T) {
			file := subkeyFile(t, f.name)
			subRaw, sigs, err := openpgp.SplitSubkeyFile(file, 16)
			if err != nil {
				t.Fatal(err)
			}
			sub, err := openpgp.ReadSubkey(subRaw)
			if err != nil {
				t.Fatal(err)
			}
			okInOrder := len(sigs) == 2
			for i, sig := range sigs {
				for j, p := range primaries {
					err := openpgp.VerifyBackSignature(sig, p, sub, ceremony)
					// The tests' own reader of the page decides the same.
					oracle := pageAcceptsBackSig(t, pubs[j], created, subRaw, sig)
					if (err == nil) != oracle {
						t.Errorf("signature %d for primary %d: error %v, the independent reader says accepted=%v", i+1, j+1, err, oracle)
					}
					if err != nil && !isRequestError(err, openpgp.ErrBackSignature) {
						t.Errorf("signature %d for primary %d: error %v is not an ErrBackSignature", i+1, j+1, err)
					}
					if i < len(primaries) && i == j && err != nil {
						okInOrder = false
					}
				}
			}
			if len(sigs) > 2 {
				okInOrder = false
			}
			if faulty[f.name] && okInOrder {
				t.Errorf("a request the page refuses is accepted: signature i verifies for primary i, in order")
			}
		})
	}
}

func TestEachBackSignatureOfTheFaultyVectorsFailsForTheReasonTheFileNames(t *testing.T) {
	a, b := primaryOf(t, "a"), primaryOf(t, "b")
	check := func(name string, index int, p *openpgp.PrimaryKey, want string) {
		t.Helper()
		subRaw, sigs, err := openpgp.SplitSubkeyFile(subkeyFile(t, name), 16)
		if err != nil {
			t.Fatal(err)
		}
		sub, err := openpgp.ReadSubkey(subRaw)
		if err != nil {
			t.Fatal(err)
		}
		err = openpgp.VerifyBackSignature(sigs[index], p, sub, ceremony)
		if !isRequestError(err, openpgp.ErrBackSignature) {
			t.Fatalf("%s signature %d: %v, want an ErrBackSignature", name, index+1, err)
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s signature %d: %q does not say %q", name, index+1, err, want)
		}
	}
	// A back-signature over another primary: it is whole, and the two bytes that it holds as the
	// start of its digest are not the start of the digest over this primary.
	check("pgp-software-valid", 0, b, "hash tag")
	check("pgp-software-valid", 1, a, "hash tag")
	// Without the issuer key ID, in the second place.
	check("pgp-backsig-no-key-id", 1, b, "no issuer key ID")
}

func TestTheStandardLibraryAgreesWithTheFingerprintOfThePrimaries(t *testing.T) {
	fa, fb := vectorPrimaryFingerprints(t)
	for label, want := range map[string]string{"a": fa, "b": fb} {
		pub, ps := vectorPrimary(t, label)
		p := primaryOf(t, label)
		if got := p.Fingerprint(); got != want {
			t.Errorf("primary %s: Fingerprint = %s, want %s", label, got, want)
		}
		if got := fingerprintOf(t, pub, created); got != want {
			t.Errorf("primary %s: openpgp.Fingerprint = %s, want %s", label, got, want)
		}
		if got := fingerprintOfBody(ps[0].Body); got != want {
			t.Errorf("primary %s: the standard gives %s, want %s", label, got, want)
		}
		g, err := gopacket.Read(bytes.NewReader(ps[0].Raw))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(g.(*gopacket.PublicKey).Fingerprint); got != want {
			t.Errorf("primary %s: go-crypto reads %s, want %s", label, got, want)
		}
		if !p.Created().Equal(created) || p.Created().Location() != time.UTC {
			t.Errorf("primary %s: Created = %v, want %v in UTC", label, p.Created(), created)
		}
		if !p.PublicKey().Equal(pub) {
			t.Errorf("primary %s: PublicKey is not the key it was made from", label)
		}
	}
}

// The three kinds of a fault of a request are each an ErrRequest, and no kind is another.
func TestTheKindsOfFaultAreRequestErrorsAndDifferFromEachOther(t *testing.T) {
	kinds := []struct {
		name string
		err  error
	}{{"ErrForm", openpgp.ErrForm}, {"ErrAlgorithm", openpgp.ErrAlgorithm}, {"ErrBackSignature", openpgp.ErrBackSignature}}
	seen := map[string]bool{}
	for _, k := range kinds {
		if !errors.Is(k.err, openpgp.ErrRequest) {
			t.Errorf("%s is not an ErrRequest", k.name)
		}
		if errors.Is(k.err, openpgp.ErrParams) || errors.Is(k.err, openpgp.ErrSignature) {
			t.Errorf("%s is an ErrParams or an ErrSignature", k.name)
		}
		//nolint:staticcheck // the reverse direction is the point: the plain error is not a narrower kind
		if errors.Is(openpgp.ErrRequest, k.err) {
			t.Errorf("the plain ErrRequest is taken for %s", k.name)
		}
		if !errors.Is(fmt.Errorf("outer: %w", k.err), k.err) || !errors.Is(fmt.Errorf("outer: %w", k.err), openpgp.ErrRequest) {
			t.Errorf("%s does not survive wrapping", k.name)
		}
		if msg := k.err.Error(); !strings.HasPrefix(msg, "openpgp: ") || seen[msg] {
			t.Errorf("%s has the text %q: it must start with the package name and differ from the others", k.name, msg)
		} else {
			seen[msg] = true
		}
		for _, o := range kinds {
			if o.name != k.name && errors.Is(k.err, o.err) {
				t.Errorf("%s is also %s", k.name, o.name)
			}
		}
	}
	if errors.Is(openpgp.ErrParams, openpgp.ErrRequest) || errors.Is(openpgp.ErrSignature, openpgp.ErrRequest) {
		t.Error("ErrParams or ErrSignature is an ErrRequest")
	}
}

// Every function of the reader that fails returns a request error of one kind and never another.
func TestEachFaultOfTheReaderIsOfOneKindOnly(t *testing.T) {
	cases := []struct {
		name string
		err  error
		kind error
	}{
		{"an empty file", second(openpgp.SplitSubkeyFile(nil, 16)), openpgp.ErrForm},
		{"an empty packet", errOf(openpgp.ReadSubkey(nil)), openpgp.ErrForm},
		{"an empty back-signature", openpgp.VerifyBackSignature(nil, primaryOf(t, "a"), mustSubkey(t, "pgp-software-valid"), ceremony), openpgp.ErrBackSignature},
		{"a back-signature that is a subkey", openpgp.VerifyBackSignature(subkeyFile(t, "pgp-software-valid")[:117], primaryOf(t, "a"), mustSubkey(t, "pgp-software-valid"), ceremony), openpgp.ErrBackSignature},
		{"a key that is Ed25519", errOf(openpgp.ReadSubkey(splitPackets(t, subkeyFile(t, "pgp-ed25519"))[0].Raw)), openpgp.ErrAlgorithm},
	}
	kinds := []error{openpgp.ErrForm, openpgp.ErrAlgorithm, openpgp.ErrBackSignature}
	for _, c := range cases {
		if !isRequestError(c.err, c.kind) {
			t.Errorf("%s: error %v, want an %v", c.name, c.err, c.kind)
		}
		for _, k := range kinds {
			if !errors.Is(c.kind, k) && errors.Is(c.err, k) {
				t.Errorf("%s: error %v is also %v", c.name, c.err, k)
			}
		}
	}
}

func second(_ []byte, _ [][]byte, err error) error { return err }

func errOf[T any](_ T, err error) error { return err }

func mustSubkey(t testing.TB, name string) *openpgp.Subkey {
	t.Helper()
	sub, err := openpgp.ReadSubkey(splitPackets(t, subkeyFile(t, name))[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

// subkeyBody is the body of a subkey packet of a fresh key, created at subAt: 111 bytes.
func subkeyBody(t testing.TB) []byte {
	t.Helper()
	b := keyBody(&genKey(t).PublicKey, subAt)
	if len(b) != 111 {
		t.Fatalf("the body of a subkey is %d bytes, want 111", len(b))
	}
	return b
}

// bodyWith returns a copy of body changed by f.
func bodyWith(body []byte, f func(b []byte) []byte) []byte { return f(bytes.Clone(body)) }

var (
	oidP256       = []byte{8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	oidP521       = []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x23}
	oidSecp224r1  = []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x21}
	oidSecp256k1  = []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x0A}
	oidBrainpool  = []byte{9, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B}
	oidP384Padded = []byte{6, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x00}
)

// withOID replaces the curve identifier (the 6 bytes from offset 6) of a P-384 subkey body.
func withOID(oid []byte) func(b []byte) []byte {
	return func(b []byte) []byte { return append(append(b[:6:6], oid...), b[12:]...) }
}

func setByte(i int, v byte) func(b []byte) []byte {
	return func(b []byte) []byte { b[i] = v; return b }
}

func TestReadSubkeyRefusesAKeyThatIsNotAVersion4EcdsaKeyOnP384AsAnAlgorithmWhateverFollows(t *testing.T) {
	body := subkeyBody(t)
	cases := []struct {
		name string
		body []byte
	}{
		{"version 0", bodyWith(body, setByte(0, 0))},
		{"version 1", bodyWith(body, setByte(0, 1))},
		{"version 2", bodyWith(body, setByte(0, 2))},
		{"version 3", bodyWith(body, setByte(0, 3))},
		{"version 5", bodyWith(body, setByte(0, 5))},
		{"version 6", bodyWith(body, setByte(0, 6))},
		{"version 255", bodyWith(body, setByte(0, 255))},
		{"version 6 with a body of one byte", []byte{6}},
		{"version 3 with a body of two bytes", []byte{3, 0}},
		{"version 5 with garbage after it", append([]byte{5}, bytes.Repeat([]byte{0xA5}, 200)...)},
		{"RSA (algorithm 1)", bodyWith(body, setByte(5, 1))},
		{"RSA encrypt-only (2)", bodyWith(body, setByte(5, 2))},
		{"algorithm 0", bodyWith(body, setByte(5, 0))},
		{"algorithm 16", bodyWith(body, setByte(5, 16))},
		{"algorithm 17 (DSA)", bodyWith(body, setByte(5, 17))},
		{"ECDH (18)", bodyWith(body, setByte(5, 18))},
		{"EdDSA (22)", bodyWith(body, setByte(5, 22))},
		{"X25519 (25)", bodyWith(body, setByte(5, 25))},
		{"algorithm 27", bodyWith(body, setByte(5, 27))},
		{"algorithm 28", bodyWith(body, setByte(5, 28))},
		{"algorithm 255", bodyWith(body, setByte(5, 255))},
		{"version 4, algorithm 22 and garbage after it", append([]byte{4, 0, 0, 0, 1, 22}, bytes.Repeat([]byte{0xFF}, 300)...)},
		{"version 4, algorithm 22, a body of six bytes", []byte{4, 0, 0, 0, 1, 22}},
		{"ECDSA on P-256", bodyWith(body, withOID(oidP256))},
		{"ECDSA on P-521", bodyWith(body, withOID(oidP521))},
		{"ECDSA on secp224r1", bodyWith(body, withOID(oidSecp224r1))},
		{"ECDSA on secp256k1", bodyWith(body, withOID(oidSecp256k1))},
		{"ECDSA on brainpoolP384r1", bodyWith(body, withOID(oidBrainpool))},
		{"ECDSA on P-384 with an identifier of seven bytes", bodyWith(body, withOID(oidP384Padded))},
		{"ECDSA on P-521 and nothing else", []byte{4, 0, 0, 0, 1, 19, 5, 0x2B, 0x81, 0x04, 0x00, 0x23}},
		{"ECDSA, an identifier of nine bytes that is not P-384, cut short", []byte{4, 0, 0, 0, 1, 19, 9, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B}},
	}
	for _, c := range cases {
		for _, form := range []struct {
			name string
			pkt  []byte
		}{{"new format", wrap(tagSubkey, c.body)}, {"old format", oldHeader(tagSubkey, c.body)}, {"five-octet length", wrapLong(tagSubkey, c.body)}} {
			t.Run(c.name+", "+form.name, func(t *testing.T) {
				sub, err := openpgp.ReadSubkey(form.pkt)
				if sub != nil {
					t.Error("a Subkey came back with the error")
				}
				if !isRequestError(err, openpgp.ErrAlgorithm) || errors.Is(err, openpgp.ErrForm) {
					t.Errorf("error = %v, want an ErrAlgorithm and not an ErrForm", err)
				}
			})
		}
	}
}

func TestReadSubkeyRefusesAPacketThatIsNotWholeOrNotOfTheFormOfTheProfileAsAForm(t *testing.T) {
	k := genKey(t)
	body := keyBody(&k.PublicKey, subAt)
	pointAt := 14 // the first byte of the point
	// A compressed point, in the one MPI form: parity byte and the 48 bytes of x.
	compressed := append([]byte{2 + byte(k.Y.Bit(0))}, point(&k.PublicKey)[1:49]...)
	compressedBody := append(bytes.Clone(body[:12]), mpi(new(big.Int).SetBytes(compressed))...)
	offCurveBody := bodyWith(body, func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b })
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), offCurveBody[pointAt:]); err == nil {
		t.Fatal("the point of the control is still on the curve")
	}
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"no bytes", nil},
		{"one byte", []byte{0xCE}},
		{"a header with no length", []byte{0xCE}},
		{"a packet that is cut in its body", wrap(tagSubkey, body)[:60]},
		{"a packet that is cut by one byte", wrap(tagSubkey, body)[:len(wrap(tagSubkey, body))-1]},
		{"a length that leaves the packet", append([]byte{0xCE, 0xFF, 0, 0, 0xFF, 0xFF}, body...)},
		{"a length of 4 GiB", append([]byte{0xCE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, body...)},
		{"a partial length", append([]byte{0xCE, 0xE0}, body...)},
		{"an indeterminate length in the old format", append([]byte{0x80 | tagSubkey<<2 | 3}, body...)},
		{"a header without the high bit", append([]byte{0x4E, byte(len(body))}, body...)},
		{"a primary key packet (tag 6)", wrap(tagPublicKey, body)},
		{"a user ID packet (tag 13)", wrap(tagUserID, body)},
		{"a signature packet (tag 2)", wrap(tagSignature, body)},
		{"tag 0", wrap(0, body)},
		{"tag 63", wrap(63, body)},
		{"an empty body", wrap(tagSubkey, nil)},
		{"a body of one byte (version 4)", wrap(tagSubkey, []byte{4})},
		{"a body of five bytes (version 4)", wrap(tagSubkey, body[:5])},
		{"a body of six bytes (version 4, ECDSA)", wrap(tagSubkey, body[:6])},
		{"a body of seven bytes (an identifier of five bytes missing)", wrap(tagSubkey, body[:7])},
		{"an identifier of no bytes", wrap(tagSubkey, bodyWith(body, setByte(6, 0)))},
		{"an identifier of 255 bytes", wrap(tagSubkey, bodyWith(body, setByte(6, 0xFF)))},
		{"a body that stops one byte after the identifier", wrap(tagSubkey, body[:13])},
		{"an identifier that leaves the body by one byte", wrap(tagSubkey, bodyWith(body[:11], setByte(6, 5)))},
		{"no number after the identifier", wrap(tagSubkey, body[:12])},
		{"a number of one byte of its length", wrap(tagSubkey, body[:13])},
		{"a number with the bit count one too high", wrap(tagSubkey, bodyWith(body, func(b []byte) []byte { b[13]++; return b }))},
		{"a number with the bit count one too low", wrap(tagSubkey, bodyWith(body, func(b []byte) []byte { b[13]--; return b }))},
		{"a number with a bit count of zero", wrap(tagSubkey, bodyWith(body, func(b []byte) []byte { b[12], b[13] = 0, 0; return b }))},
		{"a number with the bit count of the maximum", wrap(tagSubkey, bodyWith(body, func(b []byte) []byte { b[12], b[13] = 0xFF, 0xFF; return b }))},
		{"a number with a leading zero byte that the bit count does not count", wrap(tagSubkey, append(bytes.Clone(body[:14]), append([]byte{0}, body[14:]...)...))},
		{"a number with a leading zero byte that the bit count counts", wrap(tagSubkey, append(append(bytes.Clone(body[:12]), 0x03, body[13]+8), append([]byte{0}, body[14:]...)...))},
		{"a compressed point", wrap(tagSubkey, compressedBody)},
		{"a point of the form 0x00", wrap(tagSubkey, bodyWith(body, setByte(pointAt, 0)))},
		{"a point of the form 0x05", wrap(tagSubkey, bodyWith(body, setByte(pointAt, 5)))},
		{"an uncompressed point that is not on the curve", wrap(tagSubkey, offCurveBody)},
		{"a point of zeros", wrap(tagSubkey, append(bytes.Clone(body[:pointAt]), append([]byte{4}, make([]byte, 96)...)...))},
		{"one byte after the point", wrap(tagSubkey, append(bytes.Clone(body), 0))},
		{"sixteen bytes after the point", wrap(tagSubkey, append(bytes.Clone(body), make([]byte, 16)...))},
		{"a creation time of zero", wrap(tagSubkey, bodyWith(body, func(b []byte) []byte { copy(b[1:5], []byte{0, 0, 0, 0}); return b }))},
		{"a packet and one byte after it", append(wrap(tagSubkey, body), 0)},
		{"a packet and a second whole packet", append(wrap(tagSubkey, body), wrap(tagSubkey, body)...)},
		{"a packet and a header that is cut", append(wrap(tagSubkey, body), 0xC2)},
		{"a subkey with zero bytes in front of it", append([]byte{0}, wrap(tagSubkey, body)...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sub, err := openpgp.ReadSubkey(c.pkt)
			if sub != nil {
				t.Error("a Subkey came back with the error")
			}
			if !isRequestError(err, openpgp.ErrForm) || errors.Is(err, openpgp.ErrAlgorithm) {
				t.Errorf("error = %v, want an ErrForm and not an ErrAlgorithm", err)
			}
		})
	}
}

// The same body in each form of the header gives the same Subkey: the reader reads the packet, not
// its header. The extreme creation times of four bytes are whole times too.
func TestReadSubkeyGivesTheSameSubkeyForEveryFormOfTheHeader(t *testing.T) {
	k := genKey(t)
	body := keyBody(&k.PublicKey, subAt)
	forms := []struct {
		name string
		pkt  []byte
	}{
		{"the shortest new format", wrap(tagSubkey, body)},
		{"the new format with five octets", wrapLong(tagSubkey, body)},
		{"the old format with one octet", oldHeader(tagSubkey, body)},
		{"the old format with two octets", append([]byte{0x80 | tagSubkey<<2 | 1, 0, byte(len(body))}, body...)},
		{"the old format with four octets", append([]byte{0x80 | tagSubkey<<2 | 2, 0, 0, 0, byte(len(body))}, body...)},
	}
	want := fingerprintOfBody(body)
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			sub, err := openpgp.ReadSubkey(f.pkt)
			if err != nil {
				t.Fatalf("ReadSubkey: %v", err)
			}
			if sub.Fingerprint() != want {
				t.Errorf("Fingerprint = %s, want %s", sub.Fingerprint(), want)
			}
			if !sub.Created().Equal(subAt) || !sub.PublicKey().Equal(&k.PublicKey) {
				t.Errorf("Created = %v, PublicKey equal = %v", sub.Created(), sub.PublicKey().Equal(&k.PublicKey))
			}
		})
	}
	for _, at := range []int64{1, 2, 1<<31 - 1, 1 << 31, 1<<32 - 1} {
		sub, err := openpgp.ReadSubkey(wrap(tagSubkey, keyBody(&k.PublicKey, time.Unix(at, 0))))
		if err != nil {
			t.Errorf("a creation time of %d: %v", at, err)
			continue
		}
		if sub.Created().Unix() != at {
			t.Errorf("a creation time of %d read as %d", at, sub.Created().Unix())
		}
	}
}

// The Subkey holds its own copy: a caller that changes the packet it passed changes nothing in it.
func TestASubkeyDoesNotShareMemoryWithThePacketItWasReadFrom(t *testing.T) {
	file := bytes.Clone(subkeyFile(t, "pgp-software-valid"))
	subRaw, sigs, err := openpgp.SplitSubkeyFile(file, 2)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := openpgp.ReadSubkey(subRaw)
	if err != nil {
		t.Fatal(err)
	}
	fp, at := sub.Fingerprint(), sub.Created()
	a := primaryOf(t, "a")
	// Changing the returned byte lists, the packet and the file changes neither the Subkey nor the check.
	for _, b := range append([][]byte{subRaw, file}, sigs[1:]...) {
		for i := range b {
			b[i] ^= 0xFF
		}
	}
	if sub.Fingerprint() != fp || !sub.Created().Equal(at) {
		t.Error("the Subkey changed with the packet it was read from")
	}
	// The first back-signature is a copy as well: it is still the one of the vector.
	if err := openpgp.VerifyBackSignature(sigs[0], a, sub, ceremony); err != nil {
		t.Errorf("VerifyBackSignature of a copy that nobody touched: %v", err)
	}
}

func TestSplitSubkeyFileRefusesAFileThatIsNotASubkeyAndItsBackSignaturesAsAForm(t *testing.T) {
	m := newSubkey(t, &genKey(t).PublicKey, created, subAt)
	sub, sig := m.Packet, m.BackSig
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	_, a := vectorPrimary(t, "a")
	primaryFile := vector(t, "pki", "test-primary-a.pgp")
	cases := []struct {
		name string
		file []byte
		max  int
	}{
		{"a nil file", nil, 16},
		{"an empty file", []byte{}, 16},
		{"one byte", []byte{0xCE}, 16},
		{"two bytes that are not a header", []byte{0x00, 0x00}, 16},
		{"a file of zeros", make([]byte, 400), 16},
		{"the certificate of a primary (it starts with tag 6)", primaryFile, 16},
		{"a signature first", cat(sig, sub), 16},
		{"a user ID first", cat(wrap(tagUserID, []byte("Example Test")), sub), 16},
		{"a primary key packet first", cat(a[0].Raw, sig), 16},
		{"a first packet that is cut", sub[:len(sub)-1], 16},
		{"a first packet whose header is cut", sub[:1], 16},
		{"a subkey and a signature that is cut by one byte", cat(sub, sig[:len(sig)-1]), 16},
		{"a subkey and a header that is cut", cat(sub, []byte{0xC2}), 16},
		{"a subkey and a partial length", cat(sub, []byte{0xC2, 0xE0, 1, 2, 3}), 16},
		{"a subkey and a partial length of the largest kind", cat(sub, []byte{0xC2, 0xFE, 1, 2, 3}), 16},
		{"a subkey and an indeterminate length (old format)", cat(sub, []byte{0x80 | tagSignature<<2 | 3}, sig[6:]), 16},
		{"a subkey and a length that leaves the file", cat(sub, []byte{0xC2, 0x80}, make([]byte, 10)), 16},
		{"a subkey and a two-octet length that leaves the file", cat(sub, []byte{0xC2, 0xC5, 0x00}, make([]byte, 10)), 16},
		{"a subkey and a length of 4 GiB on a short file", cat(sub, []byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, make([]byte, 20)), 16},
		{"a subkey and a length of 2 GiB", cat(sub, []byte{0xC2, 0xFF, 0x80, 0, 0, 0}, make([]byte, 20)), 16},
		{"an old-format length of 4 GiB", cat(sub, []byte{0x80 | tagSignature<<2 | 2, 0xFF, 0xFF, 0xFF, 0xFF}, make([]byte, 20)), 16},
		{"a subkey and one stray zero byte", cat(sub, sig, []byte{0}), 16},
		{"a subkey and one stray byte that looks like a header", cat(sub, sig, []byte{0xC2}), 16},
		{"a subkey and bytes of text", cat(sub, []byte("not a packet")), 16},
		{"a subkey and bytes that are not UTF-8", cat(sub, []byte{0xFF, 0xFE, 0xFD, 0xC3, 0x28}), 16},
		{"a subkey and 200 more packets, the bound is 16", cat(append([][]byte{sub}, repeatBytes(sig, 200)...)...), 16},
		{"a subkey and one signature, the bound is 0", cat(sub, sig), 0},
		{"a subkey and three signatures, the bound is 2", cat(sub, sig, sig, sig), 2},
		{"a subkey and 17 signatures, the bound is 16", cat(append([][]byte{sub}, repeatBytes(sig, 17)...)...), 16},
		{"a subkey and a second subkey after the bound", cat(sub, sub), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := bytes.Clone(c.file)
			subkey, sigs, err := openpgp.SplitSubkeyFile(c.file, c.max)
			if subkey != nil || sigs != nil {
				t.Errorf("bytes came back with the error: %d bytes, %d packets", len(subkey), len(sigs))
			}
			if !isRequestError(err, openpgp.ErrForm) {
				t.Errorf("error = %v, want an ErrForm", err)
			}
			if !bytes.Equal(before, c.file) {
				t.Error("the file was changed")
			}
		})
	}
}

func repeatBytes(b []byte, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSplitSubkeyFileAcceptsTheFilesThatHoldTheSubkeyAndAtMostTheBoundOfPackets(t *testing.T) {
	m := newSubkey(t, &genKey(t).PublicKey, created, subAt)
	sub, sig := m.Packet, m.BackSig
	oldSub := oldHeader(tagSubkey, m.body())
	oldSig := oldHeader(tagSignature, splitPackets(t, sig)[0].Body)
	file := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	foreign := wrap(tagUserID, []byte("Example Test"))
	cases := []struct {
		name string
		file []byte
		max  int
		want [][]byte
	}{
		{"the subkey alone", sub, 16, nil},
		{"the subkey alone, the bound is 0", sub, 0, nil},
		{"the subkey alone in the old format", oldSub, 4, nil},
		{"the subkey and one signature", file(sub, sig), 1, [][]byte{sig}},
		{"the subkey and one signature, the bound is 16", file(sub, sig), 16, [][]byte{sig}},
		{"the subkey and two signatures, the bound is 2", file(sub, sig, sig), 2, [][]byte{sig, sig}},
		{"the subkey and 16 signatures, the bound is 16", file(append([][]byte{sub}, repeatBytes(sig, 16)...)...), 16, repeatBytes(sig, 16)},
		{"the subkey and one signature in the old format", file(oldSub, oldSig), 1, [][]byte{oldSig}},
		{"a subkey in the old format and a signature in the new", file(oldSub, sig), 1, [][]byte{sig}},
		{"the subkey and a packet of another tag, which is returned whatever its tag", file(sub, foreign), 1, [][]byte{foreign}},
		{"the subkey and a second subkey, which is returned as a packet", file(sub, sub), 1, [][]byte{sub}},
		{"the subkey and a packet with an empty body", file(sub, []byte{0xC2, 0x00}), 1, [][]byte{{0xC2, 0x00}}},
		{"the subkey and a packet with a five-octet length of zero", file(sub, []byte{0xC2, 0xFF, 0, 0, 0, 0}), 1, [][]byte{{0xC2, 0xFF, 0, 0, 0, 0}}},
		{"the subkey and a signature of 5000 bytes", file(sub, wrap(tagSignature, make([]byte, 5000))), 1, [][]byte{wrap(tagSignature, make([]byte, 5000))}},
		{"the subkey and a signature of 200000 bytes", file(sub, wrap(tagSignature, make([]byte, 200000))), 1, [][]byte{wrap(tagSignature, make([]byte, 200000))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := bytes.Clone(c.file)
			subkey, sigs, err := openpgp.SplitSubkeyFile(c.file, c.max)
			if err != nil {
				t.Fatalf("SplitSubkeyFile: %v", err)
			}
			if sigs == nil {
				t.Error("the list of signatures is nil, want an empty list that is not nil")
			}
			first := splitPackets(t, c.file)[0]
			if !bytes.Equal(subkey, first.Raw) {
				t.Error("the subkey is not the first packet")
			}
			if len(sigs) != len(c.want) {
				t.Fatalf("%d packets after the subkey, want %d", len(sigs), len(c.want))
			}
			for i := range sigs {
				if !bytes.Equal(sigs[i], c.want[i]) {
					t.Errorf("packet %d is not the expected packet", i+1)
				}
			}
			// The returned bytes are copies: changing them changes nothing in the file, and the other way.
			for _, b := range append([][]byte{subkey}, sigs...) {
				for i := range b {
					b[i] ^= 0xFF
				}
			}
			if !bytes.Equal(before, c.file) {
				t.Error("changing the returned byte lists changed the file")
			}
		})
	}
}

func TestSplitSubkeyFileReturnsCopiesThatDoNotShareMemoryWithTheFileOrWithEachOther(t *testing.T) {
	m := newSubkey(t, &genKey(t).PublicKey, created, subAt)
	file := append(bytes.Clone(m.Packet), m.BackSig...)
	subkey, sigs, err := openpgp.SplitSubkeyFile(file, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := bytes.Clone(file)
	// Writing past the length of a returned value into its capacity must not reach the file.
	subkey = append(subkey[:len(subkey):cap(subkey)], 0xAA)
	_ = sigs
	file[0] ^= 0xFF
	if subkey[0] != snapshot[0] {
		t.Error("the subkey follows the file: it is not a copy")
	}
	file[0] ^= 0xFF
	if !bytes.Equal(file, snapshot) {
		t.Error("the file was changed by appending to the subkey")
	}
}

func TestSplitSubkeyFileRefusesABoundBelowZeroAsAParameterAndNotAsARequest(t *testing.T) {
	m := newSubkey(t, &genKey(t).PublicKey, created, subAt)
	for _, max := range []int{-1, -2, math.MinInt} {
		subkey, sigs, err := openpgp.SplitSubkeyFile(m.Packet, max)
		if subkey != nil || sigs != nil {
			t.Errorf("bound %d: bytes came back with the error", max)
		}
		if !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrRequest) {
			t.Errorf("bound %d: error = %v, want an ErrParams that is not an ErrRequest", max, err)
		}
	}
	// A bound below zero is a fault of the caller even when the file is not a subkey file.
	if _, _, err := openpgp.SplitSubkeyFile(nil, -1); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("an empty file with a negative bound: %v, want an ErrParams", err)
	}
	// The largest bound is a bound like any other.
	if _, sigs, err := openpgp.SplitSubkeyFile(m.Packet, math.MaxInt); err != nil || sigs == nil || len(sigs) != 0 {
		t.Errorf("the largest bound: %d packets, %v", len(sigs), err)
	}
}

// A hostile count costs no more than the bound: the walk stops when the bound is passed, so a file
// of a hundred thousand packets does the work of one of twenty.
func TestSplitSubkeyFileStopsAtTheBoundAndDoesNotWalkAHostileCount(t *testing.T) {
	m := newSubkey(t, &genKey(t).PublicKey, created, subAt)
	build := func(n int) []byte {
		out := bytes.Clone(m.Packet)
		for range n {
			out = append(out, 0xC2, 0x00)
		}
		return out
	}
	small, big := build(20), build(200000)
	for _, f := range [][]byte{small, big} {
		if _, _, err := openpgp.SplitSubkeyFile(f, 16); !isRequestError(err, openpgp.ErrForm) {
			t.Fatalf("a file of %d bytes: error = %v, want an ErrForm", len(f), err)
		}
	}
	a := testing.AllocsPerRun(5, func() { _, _, _ = openpgp.SplitSubkeyFile(small, 16) })
	b := testing.AllocsPerRun(5, func() { _, _, _ = openpgp.SplitSubkeyFile(big, 16) })
	// The two costs are the same up to the noise of the race detector, which counts a few more
	// allocations; a walk over the whole file would cost 200000.
	if b > a+4 {
		t.Errorf("a file of 20 packets costs %v allocations and one of 200000 packets %v: the walk does not stop at the bound", a, b)
	}
	// A bound of zero allocates for the subkey and for the error only.
	if c := testing.AllocsPerRun(5, func() { _, _, _ = openpgp.SplitSubkeyFile(big, 0) }); c > a {
		t.Errorf("the bound 0 costs %v allocations, more than the bound 16 (%v)", c, a)
	}
}

func TestEveryFunctionOfTheReaderRefusesANilAndAZeroValueWithoutPanicking(t *testing.T) {
	a := primaryOf(t, "a")
	sub := mustSubkey(t, "pgp-software-valid")
	_, sigs, _ := openpgp.SplitSubkeyFile(subkeyFile(t, "pgp-software-valid"), 16)
	sig := sigs[0]
	var nilPrimary *openpgp.PrimaryKey
	var nilSub *openpgp.Subkey
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"a nil primary", openpgp.VerifyBackSignature(sig, nilPrimary, sub, ceremony), openpgp.ErrParams},
		{"a zero primary", openpgp.VerifyBackSignature(sig, &openpgp.PrimaryKey{}, sub, ceremony), openpgp.ErrParams},
		{"a nil subkey", openpgp.VerifyBackSignature(sig, a, nilSub, ceremony), openpgp.ErrParams},
		{"a zero subkey", openpgp.VerifyBackSignature(sig, a, &openpgp.Subkey{}, ceremony), openpgp.ErrParams},
		{"a nil primary, a nil subkey and a nil signature", openpgp.VerifyBackSignature(nil, nilPrimary, nilSub, time.Time{}), openpgp.ErrParams},
		{"a nil signature and a good primary", openpgp.VerifyBackSignature(nil, a, sub, ceremony), openpgp.ErrBackSignature},
		{"an empty signature", openpgp.VerifyBackSignature([]byte{}, a, sub, ceremony), openpgp.ErrBackSignature},
		{"a ceremony with half a second", openpgp.VerifyBackSignature(sig, a, sub, ceremony.Add(500*time.Millisecond)), openpgp.ErrParams},
		{"a ceremony with one nanosecond", openpgp.VerifyBackSignature(sig, a, sub, ceremony.Add(1)), openpgp.ErrParams},
		{"a ceremony that is the zero time", openpgp.VerifyBackSignature(sig, a, sub, time.Time{}), openpgp.ErrParams},
		{"a ceremony at the epoch", openpgp.VerifyBackSignature(sig, a, sub, time.Unix(0, 0)), openpgp.ErrParams},
		{"a ceremony before 1970", openpgp.VerifyBackSignature(sig, a, sub, time.Unix(-1, 0)), openpgp.ErrParams},
		{"a ceremony in 1900", openpgp.VerifyBackSignature(sig, a, sub, time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)), openpgp.ErrParams},
		{"a ceremony in 2106 after the last second", openpgp.VerifyBackSignature(sig, a, sub, time.Unix(1<<32, 0)), openpgp.ErrParams},
		{"a ceremony in the year 3000", openpgp.VerifyBackSignature(sig, a, sub, time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)), openpgp.ErrParams},
	}
	for _, c := range cases {
		if !errors.Is(c.err, c.want) {
			t.Errorf("%s: error = %v, want an %v", c.name, c.err, c.want)
		}
		if errors.Is(c.want, openpgp.ErrParams) && errors.Is(c.err, openpgp.ErrRequest) {
			t.Errorf("%s: a fault of the caller is taken for a fault of the request: %v", c.name, c.err)
		}
		if errors.Is(c.want, openpgp.ErrBackSignature) && !isRequestError(c.err, openpgp.ErrBackSignature) {
			t.Errorf("%s: error = %v, want an ErrBackSignature that is an ErrRequest", c.name, c.err)
		}
	}
	// The getters of a nil or zero value say nothing and do not panic.
	for _, p := range []*openpgp.PrimaryKey{nil, {}} {
		if p.Fingerprint() != "" || !p.Created().IsZero() || p.PublicKey() != nil {
			t.Errorf("a nil or zero primary says %q, %v, %v", p.Fingerprint(), p.Created(), p.PublicKey())
		}
	}
	for _, s := range []*openpgp.Subkey{nil, {}} {
		if s.Fingerprint() != "" || !s.Created().IsZero() || s.PublicKey() != nil {
			t.Errorf("a nil or zero subkey says %q, %v, %v", s.Fingerprint(), s.Created(), s.PublicKey())
		}
	}
}

func TestTheCeremonyTimeIsHeldToWholeSecondsOfTheYears1970To2106AtTheirEdges(t *testing.T) {
	// A key and a back-signature that are made at the very edges, so that the time of the ceremony
	// is the only thing that decides.
	k := genKey(t)
	last := time.Unix(1<<32-1, 0).UTC()
	first := time.Unix(1, 0).UTC()
	p, err := openpgp.NewPrimaryKey(&k.PublicKey, first)
	if err != nil {
		t.Fatalf("NewPrimaryKey at the first second: %v", err)
	}
	m := newSubkey(t, &k.PublicKey, first, first)
	sub, err := openpgp.ReadSubkey(m.Packet)
	if err != nil {
		t.Fatalf("ReadSubkey at the first second: %v", err)
	}
	if err := openpgp.VerifyBackSignature(m.BackSig, p, sub, first); err != nil {
		t.Errorf("a ceremony at the first second: %v", err)
	}
	if err := openpgp.VerifyBackSignature(m.BackSig, p, sub, last); err != nil {
		t.Errorf("a ceremony at the last second: %v", err)
	}
	if err := openpgp.VerifyBackSignature(m.BackSig, p, sub, last.Add(time.Second)); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("a ceremony one second after the last: %v, want an ErrParams", err)
	}
	if err := openpgp.VerifyBackSignature(m.BackSig, p, sub, first.Add(-time.Second)); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("a ceremony at the epoch: %v, want an ErrParams", err)
	}
	// The same instant in another zone is the same ceremony.
	zone := time.FixedZone("example", 5*3600+1800)
	if err := openpgp.VerifyBackSignature(m.BackSig, p, sub, last.In(zone)); err != nil {
		t.Errorf("the last second in another zone: %v", err)
	}
	// The ceremony decides the upper limit of the back-signature, to the second.
	for _, c := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"the creation of the subkey less one second", subAt.Add(-time.Second), false},
		{"the creation of the subkey", subAt, true},
		{"the ceremony less one second", ceremony.Add(-time.Second), true},
		{"the ceremony", ceremony, true},
		{"the ceremony and one second", ceremony.Add(time.Second), false},
	} {
		s := newSubkeyWith(t, &k.PublicKey, created, subAt, creationAt(c.at))
		sk, err := openpgp.ReadSubkey(s.Packet)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := openpgp.NewPrimaryKey(&k.PublicKey, created)
		if err != nil {
			t.Fatal(err)
		}
		err = openpgp.VerifyBackSignature(s.BackSig, pk, sk, ceremony)
		if c.ok && err != nil {
			t.Errorf("%s: %v, want it accepted", c.name, err)
		}
		if !c.ok && !isRequestError(err, openpgp.ErrBackSignature) {
			t.Errorf("%s: %v, want an ErrBackSignature", c.name, err)
		}
	}
	// A subkey created after the ceremony cannot have a back-signature inside the two limits.
	late := newSubkey(t, &k.PublicKey, created, ceremony.Add(time.Hour))
	lateSub, err := openpgp.ReadSubkey(late.Packet)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := openpgp.NewPrimaryKey(&k.PublicKey, created)
	if err := openpgp.VerifyBackSignature(late.BackSig, pk, lateSub, ceremony); !isRequestError(err, openpgp.ErrBackSignature) {
		t.Errorf("a subkey created after the ceremony: %v, want an ErrBackSignature", err)
	}
}

func TestNewPrimaryKeyRefusesWhatIsNotAnEcdsaP384KeyAndWholeSecondsOfTheYears1970To2106(t *testing.T) {
	k := genKey(t)
	good := &k.PublicKey
	cases := []struct {
		name   string
		pub    *ecdsa.PublicKey
		at     time.Time
		reason string
	}{
		{"a nil key", nil, created, "there is no key"},
		{"a key with no curve", &ecdsa.PublicKey{}, created, "the key is not on the curve"},
		{"a P-256 key", mustP256(t), created, "the key is not on the curve"},
		{"a P-521 key", mustCurve(t, elliptic.P521()), created, "the key is not on the curve"},
		{"a key on P-384 with no point", &ecdsa.PublicKey{Curve: elliptic.P384()}, created, "the point of the key"},
		{"a key with the abscissa only", abscissaOnly(t), created, "the point of the key"},
		{"a key with the ordinate only", ordinateOnly(t), created, "the point of the key"},
		{"a point that is not on the curve", offCurve(t), created, "the point of the key"},
		{"a time with half a second", good, created.Add(500 * time.Millisecond), "the creation time of the key has a fraction"},
		{"a time with a nanosecond", good, created.Add(1), "the creation time of the key has a fraction"},
		{"the zero time", good, time.Time{}, "the creation time of the key is outside the years"},
		{"the epoch", good, time.Unix(0, 0), "the creation time of the key is outside the years"},
		{"a time before 1970", good, time.Unix(-86400, 0), "the creation time of the key is outside the years"},
		{"a time after 2106", good, time.Unix(1<<32, 0), "the creation time of the key is outside the years"},
		{"a time in the year 9999", good, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), "the creation time of the key is outside the years"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := openpgp.NewPrimaryKey(c.pub, c.at)
			if p != nil {
				t.Error("a PrimaryKey came back with the error")
			}
			if !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrRequest) {
				t.Errorf("error = %v, want an ErrParams that is not an ErrRequest", err)
			}
			if err != nil && !strings.Contains(err.Error(), ": "+c.reason) {
				t.Errorf("error %q does not give the reason %q", err, c.reason)
			}
		})
	}
	// The edges are accepted, and a time in another zone is the same instant.
	for _, at := range []time.Time{time.Unix(1, 0), time.Unix(1<<32-1, 0), created.In(time.FixedZone("example", -7*3600))} {
		p, err := openpgp.NewPrimaryKey(good, at)
		if err != nil {
			t.Errorf("a time of %v: %v", at, err)
			continue
		}
		if !p.Created().Equal(at) || p.Created().Location() != time.UTC {
			t.Errorf("Created = %v, want the instant %v in UTC", p.Created(), at)
		}
	}
	// A typed nil key in a function that takes the pointer is a nil key.
	var none *ecdsa.PublicKey
	if _, err := openpgp.NewPrimaryKey(none, created); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("a typed nil key: %v", err)
	}
}

func mustP256(t testing.TB) *ecdsa.PublicKey { return mustCurve(t, elliptic.P256()) }

func mustCurve(t testing.TB, c elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

// A key that the caller passes is copied: changing it afterwards changes nothing in the primary, and
// the key that the primary gives back is a copy too.
func TestAPrimaryKeyAndASubkeyGiveCopiesOfTheirKeyAndHoldTheirOwn(t *testing.T) {
	k := genKey(t)
	at := created
	pub := &k.PublicKey
	p, err := openpgp.NewPrimaryKey(pub, at)
	if err != nil {
		t.Fatal(err)
	}
	m := newSubkey(t, pub, at, subAt)
	sub, err := openpgp.ReadSubkey(m.Packet)
	if err != nil {
		t.Fatal(err)
	}
	wantFP := p.Fingerprint()
	wantPub := p.PublicKey()
	// The caller changes its own key.
	pub.X.SetInt64(7) //nolint:staticcheck // the coordinates are the only way to change a key in place
	pub.Y.SetInt64(9) //nolint:staticcheck // see above
	if !p.PublicKey().Equal(wantPub) || p.Fingerprint() != wantFP {
		t.Error("the primary follows the key that the caller changed")
	}
	if err := openpgp.VerifyBackSignature(m.BackSig, p, sub, ceremony); err != nil {
		t.Errorf("VerifyBackSignature after the caller changed its key: %v", err)
	}
	// The caller changes the key that it was given.
	for _, got := range []*ecdsa.PublicKey{p.PublicKey(), sub.PublicKey()} {
		got.X.SetInt64(1) //nolint:staticcheck // the coordinates are the only way to change a key in place
		got.Y.SetInt64(2) //nolint:staticcheck // see above
		got.Curve = elliptic.P256()
	}
	if !p.PublicKey().Equal(wantPub) {
		t.Error("the primary's key changed with a copy that it gave out")
	}
	subPub := &m.Key.PublicKey
	if !sub.PublicKey().Equal(subPub) {
		t.Error("the subkey's key changed with a copy that it gave out")
	}
	p1, p2 := p.PublicKey(), p.PublicKey()
	s1, s2 := sub.PublicKey(), sub.PublicKey()
	if p1 == p2 || s1 == s2 || p1.X == p2.X || s1.X == s2.X { //nolint:staticcheck // the pointers are compared on purpose
		t.Error("two calls of PublicKey share a pointer: it is not a copy")
	}
	if err := openpgp.VerifyBackSignature(m.BackSig, p, sub, ceremony); err != nil {
		t.Errorf("VerifyBackSignature after the caller changed the copies: %v", err)
	}
}

// The subkey of a request that is the primary's own key is refused by BindSubkey (parseSubkey keeps
// that rule) and is not refused by VerifyBackSignature, which judges one back-signature. A caller of
// the check applies the rule itself. This test pins that division.
func TestTheRuleThatASubkeyIsNotThePrimaryItselfStaysWithBindSubkeyAndIsNotInVerifyBackSignature(t *testing.T) {
	s := newSigner(t)
	// The subkey is the primary's key and point, created after the primary and before the ceremony.
	subPacket := wrap(tagSubkey, keyBody(&s.key.PublicKey, subAt))
	back := backSig(t, s.key, subAt, &s.key.PublicKey, created, nil)
	b := openpgp.BindParams{Primary: s.params(), Subkey: subPacket, BackSig: back, Capability: "sign", ExpiresAt: ceremony.AddDate(1, 0, 0)}
	assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrRequest)
	if s.calls != 0 {
		t.Errorf("the signer was asked %d times for a subkey that is the primary", s.calls)
	}
	p, err := openpgp.NewPrimaryKey(&s.key.PublicKey, created)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := openpgp.ReadSubkey(subPacket)
	if err != nil {
		t.Fatalf("ReadSubkey: %v", err)
	}
	if got := point(sub.PublicKey()); !bytes.Equal(got, point(p.PublicKey())) {
		t.Fatal("the control: the subkey is not the primary's point")
	}
	if err := openpgp.VerifyBackSignature(back, p, sub, ceremony); err != nil {
		t.Errorf("VerifyBackSignature of a subkey that is the primary's point: %v; the rule is not part of it", err)
	}
}

// The creation time of the primary is part of what a back-signature covers: a PrimaryKey made with
// another creation time is another key packet, and the signature does not verify over it.
func TestAPrimaryKeyWithAnotherCreationTimeIsAnotherPrimaryAndTheBackSignatureDoesNotVerify(t *testing.T) {
	pub, _ := vectorPrimary(t, "a")
	sub := mustSubkey(t, "pgp-software-valid")
	_, sigs, _ := openpgp.SplitSubkeyFile(subkeyFile(t, "pgp-software-valid"), 16)
	right, err := openpgp.NewPrimaryKey(pub, created)
	if err != nil {
		t.Fatal(err)
	}
	if err := openpgp.VerifyBackSignature(sigs[0], right, sub, ceremony); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for _, d := range []time.Duration{time.Second, -time.Second, 24 * time.Hour} {
		wrong, err := openpgp.NewPrimaryKey(pub, created.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		if wrong.Fingerprint() == right.Fingerprint() {
			t.Errorf("a creation time %v later gives the same fingerprint", d)
		}
		if err := openpgp.VerifyBackSignature(sigs[0], wrong, sub, ceremony); !isRequestError(err, openpgp.ErrBackSignature) {
			t.Errorf("a primary created %v later: %v, want an ErrBackSignature", d, err)
		}
	}
}

// The reader opens no file, follows no link, starts no program and talks to no network: it takes
// bytes. The source of the package imports none of the packages that could.
func TestTheReaderOfThePackageImportsNothingThatReadsAPathStartsAProgramOrOpensANetwork(t *testing.T) {
	dir := testrepo.Path(t, "internal", "openpgp")
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"\"os\"", "\"os/exec\"", "\"net\"", "\"net/http\"", "\"io/ioutil\"", "\"io/fs\"", "\"path/filepath\"", "\"syscall\"", "\"unsafe\"", "\"plugin\""}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, line := range strings.Split(string(src), "\n") {
			l := strings.TrimSpace(line)
			for _, b := range banned {
				if l == b || strings.HasSuffix(l, " "+b) {
					t.Errorf("%s imports %s", filepath.Base(f), b)
				}
			}
		}
	}
	if checked < 8 {
		t.Errorf("%d source files looked at, want the whole package", checked)
	}
}

// The page: the first packet of the file is a Public-Subkey packet (tag 14). A packet of another
// tag is a fault of form, whatever key it holds: the tag is read before the key, so a primary key
// packet of Ed25519 is not reported as an algorithm that is not supported.
func TestReadSubkeyReadsTheTagBeforeTheKindOfTheKey(t *testing.T) {
	body := subkeyBody(t)
	bodies := map[string][]byte{
		"a P-384 key":      body,
		"an Ed25519 key":   bodyWith(body, setByte(5, 22)),
		"a P-521 key":      bodyWith(body, withOID(oidP521)),
		"a version 6 key":  bodyWith(body, setByte(0, 6)),
		"a body of 1 byte": {4},
	}
	for name, b := range bodies {
		for _, tag := range []byte{0, tagSignature, tagPublicKey, tagUserID, 7, 63} {
			t.Run(fmt.Sprintf("%s in a packet of tag %d", name, tag), func(t *testing.T) {
				sub, err := openpgp.ReadSubkey(wrap(tag, b))
				if sub != nil || !isRequestError(err, openpgp.ErrForm) || errors.Is(err, openpgp.ErrAlgorithm) {
					t.Errorf("error = %v, want an ErrForm and not an ErrAlgorithm", err)
				}
			})
		}
	}
}

// The frame of the packet comes before the kind of the key: a packet that is followed by a stray byte
// is a fault of form, also when its key is one that is not supported.
func TestReadSubkeyChecksThatThePacketIsWholeBeforeTheKindOfTheKey(t *testing.T) {
	body := subkeyBody(t)
	for name, b := range map[string][]byte{
		"an Ed25519 key":  bodyWith(body, setByte(5, 22)),
		"a P-521 key":     bodyWith(body, withOID(oidP521)),
		"a version 6 key": bodyWith(body, setByte(0, 6)),
		"a P-384 key":     body,
	} {
		for _, extra := range [][]byte{{0}, {0xC2}, wrap(tagSubkey, body)} {
			pkt := append(wrap(tagSubkey, b), extra...)
			if sub, err := openpgp.ReadSubkey(pkt); sub != nil || !isRequestError(err, openpgp.ErrForm) || errors.Is(err, openpgp.ErrAlgorithm) {
				t.Errorf("%s and %d bytes after the packet: error %v, want an ErrForm", name, len(extra), err)
			}
		}
	}
}

// Every cut of the body of a subkey packet, with the header made right for the cut body, is refused,
// and so is the body with bytes added. The cut ones are refused with a kind of a request.
func TestEveryCutAndEveryExtensionOfTheBodyOfASubkeyPacketIsRefused(t *testing.T) {
	body := subkeyBody(t)
	for n := 0; n < len(body); n++ {
		for _, form := range []struct {
			name string
			pkt  []byte
		}{{"new", wrap(tagSubkey, body[:n])}, {"old", oldHeader(tagSubkey, body[:n])}, {"long", wrapLong(tagSubkey, body[:n])}} {
			sub, err := openpgp.ReadSubkey(form.pkt)
			if sub != nil || (!isRequestError(err, openpgp.ErrForm) && !isRequestError(err, openpgp.ErrAlgorithm)) {
				t.Errorf("a body cut to %d bytes (%s header): error %v, want an ErrForm or an ErrAlgorithm", n, form.name, err)
			}
		}
	}
	for extra := 1; extra <= 8; extra++ {
		pkt := wrap(tagSubkey, append(bytes.Clone(body), make([]byte, extra)...))
		if sub, err := openpgp.ReadSubkey(pkt); sub != nil || !isRequestError(err, openpgp.ErrForm) {
			t.Errorf("a body with %d bytes added: error %v, want an ErrForm", extra, err)
		}
	}
}

// Every cut of the body of a back-signature, with the header made right for the cut body, is refused
// as a back-signature, and so is the body with bytes added and a body whose area lengths are changed.
func TestEveryCutAndEveryExtensionOfTheBodyOfABackSignatureIsRefusedAsABackSignature(t *testing.T) {
	primary := primaryOf(t, "a")
	subRaw, sigs, err := openpgp.SplitSubkeyFile(subkeyFile(t, "pgp-software-valid"), 16)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := openpgp.ReadSubkey(subRaw)
	if err != nil {
		t.Fatal(err)
	}
	body := splitPackets(t, sigs[0])[0].Body
	if err := openpgp.VerifyBackSignature(wrap(tagSignature, body), primary, sub, ceremony); err != nil {
		t.Fatalf("the control, with the header of the shortest form: %v", err)
	}
	refused := func(what string, pkt []byte) {
		t.Helper()
		if err := openpgp.VerifyBackSignature(pkt, primary, sub, ceremony); !isRequestError(err, openpgp.ErrBackSignature) {
			t.Errorf("%s: error %v, want an ErrBackSignature", what, err)
		}
	}
	for n := 0; n < len(body); n++ {
		refused(fmt.Sprintf("a body cut to %d bytes", n), wrap(tagSignature, body[:n]))
		refused(fmt.Sprintf("a body cut to %d bytes, old header", n), oldHeader(tagSignature, body[:n]))
	}
	for extra := 1; extra <= 8; extra++ {
		refused(fmt.Sprintf("%d bytes added", extra), wrap(tagSignature, append(bytes.Clone(body), make([]byte, extra)...)))
	}
	hl := int(body[4])<<8 | int(body[5])
	for v := 0; v < 400; v++ {
		if v == hl {
			continue
		}
		hashed := bytes.Clone(body)
		hashed[4], hashed[5] = byte(v>>8), byte(v)
		refused(fmt.Sprintf("a hashed area length of %d", v), wrap(tagSignature, hashed))
		unhashed := bytes.Clone(body)
		unhashed[6+hl], unhashed[7+hl] = byte(v>>8), byte(v)
		if want := int(body[6+hl])<<8 | int(body[7+hl]); v != want {
			refused(fmt.Sprintf("an unhashed area length of %d", v), wrap(tagSignature, unhashed))
		}
	}
	// The same back-signature with a hash tag and numbers cut in each place of the tail.
	tail := 8 + hl + (int(body[6+hl])<<8 | int(body[7+hl]))
	for n := tail; n < len(body); n++ {
		refused(fmt.Sprintf("the tail cut to %d bytes", n-tail), wrap(tagSignature, body[:n]))
	}
}

// The packets that a file may hold are all in the forms of RFC 9580, section 4.2, and nothing else:
// a partial length is not read as a two-octet length, a length of zero is a packet with no body, and
// the longest two-octet length is read whole.
func TestSplitSubkeyFileReadsEveryLengthFormAtItsEdgesAndRefusesThePartialLengths(t *testing.T) {
	m := newSubkey(t, &genKey(t).PublicKey, created, subAt)
	sub := m.Packet
	file := func(tail ...byte) []byte { return append(bytes.Clone(sub), tail...) }
	zeros := func(n int) []byte { return make([]byte, n) }
	accepted := []struct {
		name string
		pkt  []byte
	}{
		{"new format, one octet, 0", []byte{0xC2, 0x00}},
		{"new format, one octet, 191", append([]byte{0xC2, 191}, zeros(191)...)},
		{"new format, two octets, 192", append([]byte{0xC2, 0xC0, 0x00}, zeros(192)...)},
		{"new format, two octets, 8383", append([]byte{0xC2, 0xDF, 0xFF}, zeros(8383)...)},
		{"new format, five octets, 0", []byte{0xC2, 0xFF, 0, 0, 0, 0}},
		{"new format, five octets, 70000", append([]byte{0xC2, 0xFF, 0, 1, 0x11, 0x70}, zeros(70000)...)},
		{"old format, one octet, 0", []byte{0x88, 0x00}},
		{"old format, one octet, 255", append([]byte{0x88, 0xFF}, zeros(255)...)},
		{"old format, two octets, 0", []byte{0x89, 0, 0}},
		{"old format, two octets, 60000", append([]byte{0x89, 0xEA, 0x60}, zeros(60000)...)},
		{"old format, four octets, 0", []byte{0x8A, 0, 0, 0, 0}},
		{"old format, four octets, 70000", append([]byte{0x8A, 0, 1, 0x11, 0x70}, zeros(70000)...)},
	}
	for _, c := range accepted {
		t.Run("accepts "+c.name, func(t *testing.T) {
			_, sigs, err := openpgp.SplitSubkeyFile(file(c.pkt...), 1)
			if err != nil || len(sigs) != 1 || !bytes.Equal(sigs[0], c.pkt) {
				t.Errorf("error %v, %d packets", err, len(sigs))
			}
		})
	}
	// A partial length (224 to 254) is refused, also when enough bytes follow to make it look like a
	// two-octet length, and the indeterminate length of the old format is refused with a long tail.
	for l := 224; l <= 254; l++ {
		t.Run(fmt.Sprintf("refuses the partial length %d", l), func(t *testing.T) {
			// The bytes that follow are exactly the number that a two-octet length would give, so
			// that a reader that took this for a two-octet length would find a whole packet.
			n := (l-192)<<8 + 0x10 + 192
			if _, _, err := openpgp.SplitSubkeyFile(file(append([]byte{0xC2, byte(l), 0x10}, zeros(n)...)...), 16); !isRequestError(err, openpgp.ErrForm) {
				t.Errorf("error = %v, want an ErrForm", err)
			}
		})
	}
	t.Run("refuses the indeterminate length of the old format with a long tail", func(t *testing.T) {
		if _, _, err := openpgp.SplitSubkeyFile(file(append([]byte{0x8B}, zeros(70000)...)...), 16); !isRequestError(err, openpgp.ErrForm) {
			t.Errorf("error = %v, want an ErrForm", err)
		}
	})
	// A length that is one more than the bytes that follow is refused, in each form.
	for _, c := range accepted {
		if len(c.pkt) < 3 {
			continue
		}
		t.Run("refuses a cut "+c.name, func(t *testing.T) {
			if _, _, err := openpgp.SplitSubkeyFile(file(c.pkt[:len(c.pkt)-1]...), 16); !isRequestError(err, openpgp.ErrForm) {
				t.Errorf("error = %v, want an ErrForm", err)
			}
		})
	}
}
