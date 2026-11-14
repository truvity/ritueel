package bundle_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/testrepo"
)

// The test bundle: the policy of the development configuration of the hand-off vectors, one delegation and one
// wanted root, and a trust set made from the test root list of trust sequence 7. Everything is public test
// material; no key is made by these helpers except where a test says so.

// vectorNow is the clock of the hand-off vectors.
var vectorNow = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return vectorNow }

// settingsText is a ritueel.yaml with the stores given.
func settingsText(stores string) string {
	return "version: 1\nname: Example\nrelease_address: release@example.org\npolicy:\n  stores: [" + stores + "]\n  min_firmware: 5.7.0\n  pin_policy: [once, always]\n  require_name_constraints: true\n  validity_months: 13\n"
}

const (
	developmentStores = "piv, openpgp-card, aws-kms, software"
	productionStores  = "piv, openpgp-card, aws-kms"

	delegationName = "example-intermediate"
	rootName       = "example-root"

	x509DelegationText = "version: 1\ntype: x509-intermediate\nroot: example-root\npermitted_uri_hosts: [example.org, \".example.org\"]\npermitted_dns_names: [example.org]\n"
	x509RootText       = "version: 1\nkind: x509\ntest: true\n"
)

// tree maps a path in a bundle to the bytes of its file.
type tree map[string][]byte

// writeTree writes the files under dir.
func writeTree(t testing.TB, dir string, files tree) {
	t.Helper()
	for p, data := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// vector reads a file under testdata/.
func vector(t testing.TB, rel ...string) []byte {
	t.Helper()
	return testrepo.Read(t, append([]string{"testdata"}, rel...)...)
}

// header is the first line of a CA bundle of the trust sequence n.
func header(n int) string { return "# trust-sequence: " + strconv.Itoa(n) + "\n" }

// trustAB is the files of a trust set of sequence n whose list holds the test roots A and B. The list and the
// bundle of the vectors are of sequence 7; the sequence is changed in both, as text. The signature is not made:
// a bundle's reader does not check it.
func trustAB(t testing.TB, n int) tree {
	t.Helper()
	list := bytes.Replace(vector(t, "root-list", "v1", "lists", "seq7-a.json"), []byte(`"sequence":7`), []byte(`"sequence":`+strconv.Itoa(n)), 1)
	bundle := bytes.Replace(vector(t, "root-list", "v1", "bundles", "ca-bundle-7.pem"), []byte(header(7)), []byte(header(n)), 1)
	if bytes.Equal(list, vector(t, "root-list", "v1", "lists", "seq7-a.json")) && n != 7 {
		t.Fatal("the sequence of the list was not changed")
	}
	return tree{"root-list.json": list, "ca-bundle.pem": bundle}
}

// trustA is the files of a trust set of sequence n whose list holds the test root A alone.
func trustA(t testing.TB, n int) tree {
	t.Helper()
	list := bytes.Replace(vector(t, "root-list", "v1", "lists", "seq7-a-without-b.json"), []byte(`"sequence":7`), []byte(`"sequence":`+strconv.Itoa(n)), 1)
	blk, _ := pem.Decode(vector(t, "root-list", "v1", "bundles", "ca-bundle-7.pem"))
	if blk == nil {
		t.Fatal("no certificate in the bundle of the vectors")
	}
	return tree{"root-list.json": list, "ca-bundle.pem": append([]byte(header(n)), pem.EncodeToMemory(blk)...)}
}

// inSet puts the files of a trust set under trust/NAME/.
func inSet(name string, files tree) tree {
	out := tree{}
	for p, data := range files {
		out["trust/"+name+"/"+p] = data
	}
	return out
}

// merge joins trees; a later one wins.
func merge(trees ...tree) tree {
	out := tree{}
	for _, tr := range trees {
		for p, data := range tr {
			out[p] = data
		}
	}
	return out
}

// requestCase is the stem and the files of a request case of the hand-off vectors, placed under requests/STEM/. A
// case may share the files of another, so the stem is the one of the proof file that the manifest names.
func requestCase(t testing.TB, id string) (string, tree) {
	t.Helper()
	var m struct {
		Requests []struct {
			ID    string   `json:"id"`
			Files []string `json:"files"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(vector(t, "hand-off", "v1", "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Requests {
		if c.ID != id {
			continue
		}
		stem := ""
		for _, f := range c.Files {
			if s, ok := strings.CutSuffix(path.Base(f), ".proof.json"); ok {
				stem = s
			}
		}
		out := tree{}
		for _, f := range c.Files {
			out["requests/"+stem+"/"+path.Base(f)] = vector(t, "hand-off", "v1", f)
		}
		if stem == "" || len(out) < 2 {
			t.Fatalf("the case %s has the stem %q and %d files", id, stem, len(out))
		}
		return stem, out
	}
	t.Fatalf("the manifest holds no case %s", id)
	return "", nil
}

// requestFiles is the files of a request case.
func requestFiles(t testing.TB, id string) tree {
	t.Helper()
	_, files := requestCase(t, id)
	return files
}

// baseBundle is a bundle that can check a request: the development policy, one delegation, one root and a trust
// set of sequence 7 with the roots A and B.
func baseBundle(t testing.TB) tree {
	return merge(
		tree{
			"ritueel.yaml":                                 []byte(settingsText(developmentStores)),
			"want/roots/" + rootName + ".yaml":             []byte(x509RootText),
			"want/delegations/" + delegationName + ".yaml": []byte(x509DelegationText),
		},
		inSet("7-3fa9c1d2", trustAB(t, 7)),
	)
}

// makeBundle writes the tree into a new folder and returns its path.
func makeBundle(t testing.TB, files tree) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, files)
	return dir
}

// testRoots are the roots A and B of the vectors, from their certificates.
func testRoots(t testing.TB) []handoff.RootRef {
	t.Helper()
	var out []handoff.RootRef
	for _, f := range []string{"test-root-a.pem", "test-root-b.pem"} {
		blk, _ := pem.Decode(vector(t, "hand-off", "v1", "pki", f))
		if blk == nil {
			t.Fatalf("%s holds no certificate", f)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("%s: the key is not ECDSA", f)
		}
		out = append(out, handoff.RootRef{Subject: cert.RawSubject, Key: key})
	}
	return out
}

// listFiles lists every path under dir, folders with a trailing slash, sorted, with the mode of each.
func listFiles(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if d.IsDir() {
			name += "/"
		}
		out = append(out, name+" "+info.Mode().String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// countingVerifier counts its calls and gives no evidence.
type countingVerifier struct {
	calls int
	at    time.Time
}

func (c *countingVerifier) Verify(_ context.Context, _ *handoff.Request, _ *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
	c.calls++
	c.at = now
	return nil, errors.New("no evidence in this test")
}

// selfSignedSet is a trust set of sequence n with one self-signed CA certificate whose key is of the kind given:
// p256, p384, p521, ed25519 or rsa. The key is made in memory and thrown away.
func selfSignedSet(t testing.TB, kind string, n int) tree {
	t.Helper()
	var priv crypto.Signer
	var err error
	switch kind {
	case "p256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("unknown kind %s", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Test Root K (TEST ONLY)"},
		NotBefore: vectorNow.Add(-time.Hour), NotAfter: vectorNow.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	list := `{"expires_at":"2027-12-15T12:00:00Z","last_record_sha256":"` + strings.Repeat("ab", 32) + `","roots":[{"label":"K","x509_spki_sha256":"` +
		jws.Pin(cert) + `"}],"sequence":` + strconv.Itoa(n) + `,"signed_at":"2026-11-15T12:00:00Z","version":1}`
	return tree{"root-list.json": []byte(list), "ca-bundle.pem": append([]byte(header(n)), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)}
}

// sha256hex is the digest of b as `sha256sum` writes it.
func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
