package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/testrepo"
)

// Helpers of the tests of "new" and "check request". A bundle for a check is made on disk from the hand-off
// vectors: the policy and the delegation of the named configuration, a trust set made from the root list
// of the vectors, and the files of one request case. Nothing here holds a value that depends on the keys of
// a vector set: every key, subject and digest is read from the vectors when a test runs.

const crqVectorsDir = "testdata/hand-off/v1"

// The names of the objects of a test bundle.
const (
	crqDelegation = "example-intermediate"
	crqRoot       = "example-root"
	crqTrustSet   = "7-3fa9c1d2"
)

type crqConfig struct {
	Stores                 []string          `json:"stores"`
	MinFirmware            string            `json:"min_firmware"`
	PINPolicy              []string          `json:"pin_policy"`
	RequireNameConstraints bool              `json:"require_name_constraints"`
	PermittedURIHosts      []string          `json:"permitted_uri_hosts"`
	PermittedDNSNames      []string          `json:"permitted_dns_names"`
	ValidityMonths         int               `json:"validity_months"`
	KMSReadRoles           map[string]string `json:"kms_read_roles"`
}

type crqCase struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	Config       string   `json:"config"`
	Files        []string `json:"files"`
	Expect       string   `json:"expect"`
	Reason       string   `json:"reason"`
	Confirmation string   `json:"confirmation"`
}

type crqManifest struct {
	Clock  string `json:"clock"`
	Pinned struct {
		RootList struct {
			X509 []string `json:"x509"`
		} `json:"root_list"`
	} `json:"pinned"`
	Configs  map[string]crqConfig `json:"configs"`
	Requests []crqCase            `json:"requests"`
}

func crqRead(t testing.TB, rel ...string) []byte {
	t.Helper()
	return testrepo.Read(t, append([]string{"testdata"}, rel...)...)
}

func crqManifestOf(t testing.TB) crqManifest {
	t.Helper()
	var m crqManifest
	if err := json.Unmarshal(testrepo.Read(t, crqVectorsDir, "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Requests) == 0 || len(m.Configs) == 0 {
		t.Fatal("the manifest holds no request case or no configuration: a check that finds nothing to check fails")
	}
	return m
}

func (m crqManifest) clock(t testing.TB) time.Time {
	t.Helper()
	c, err := time.Parse(time.RFC3339, m.Clock)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (m crqManifest) byID(t testing.TB, id string) crqCase {
	t.Helper()
	for _, c := range m.Requests {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("the manifest holds no request case %s", id)
	return crqCase{}
}

// stem is the stem of a case: the name of its proof file without the ending. A case may share the files of another.
func (c crqCase) stem(t testing.TB) string {
	t.Helper()
	for _, f := range c.Files {
		if s, ok := strings.CutSuffix(path.Base(f), "."+handoff.FileProof); ok {
			return s
		}
	}
	t.Fatalf("the case %s names no proof file: %v", c.ID, c.Files)
	return ""
}

// crqTree maps a path in a bundle to the bytes of its file.
type crqTree map[string][]byte

func crqMerge(trees ...crqTree) crqTree {
	out := crqTree{}
	for _, tr := range trees {
		for p, d := range tr {
			out[p] = d
		}
	}
	return out
}

func crqWrite(t testing.TB, dir string, files crqTree) {
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

// crqList is a flow list of strings in YAML, each quoted.
func crqList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// crqSettings is the ritueel.yaml with the policy of a configuration.
func crqSettings(c crqConfig) string {
	return "version: 1\nname: Example\nrelease_address: release@example.org\npolicy:\n" +
		"  stores: " + crqList(c.Stores) + "\n" +
		"  min_firmware: " + c.MinFirmware + "\n" +
		"  pin_policy: " + crqList(c.PINPolicy) + "\n" +
		"  require_name_constraints: true\n" +
		"  validity_months: " + strconv.Itoa(c.ValidityMonths) + "\n"
}

// crqRootKind is the kind of the wanted root file that a type of request needs.
func crqRootKind(typ string) string {
	switch typ {
	case "openpgp-subkey":
		return "openpgp"
	case "ssh-ca-key":
		return "ssh"
	}
	return "x509"
}

// crqDelegationText is the delegation file for a case under its configuration.
func crqDelegationText(t testing.TB, c crqCase, cfg crqConfig) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "version: 1\ntype: %s\nroot: %s\n", c.Type, crqRoot)
	switch c.Type {
	case "x509-intermediate":
		if len(cfg.PermittedURIHosts) > 0 {
			b.WriteString("permitted_uri_hosts: " + crqList(cfg.PermittedURIHosts) + "\n")
		}
		if len(cfg.PermittedDNSNames) > 0 {
			b.WriteString("permitted_dns_names: " + crqList(cfg.PermittedDNSNames) + "\n")
		}
	case "openpgp-subkey":
		capability := "sign"
		if strings.Contains(c.ID, "authenticate") {
			capability = "authenticate"
		}
		b.WriteString("capability: " + capability + "\n")
	case "ssh-ca-key":
		use := "user"
		var proof struct {
			Use string `json:"use"`
		}
		for _, f := range c.Files {
			if strings.HasSuffix(f, "."+handoff.FileProof) {
				if err := json.Unmarshal(testrepo.Read(t, crqVectorsDir, f), &proof); err != nil {
					t.Fatal(err)
				}
			}
		}
		if proof.Use == "user" || proof.Use == "host" {
			use = proof.Use
		}
		b.WriteString("use: " + use + "\n")
	}
	if len(cfg.KMSReadRoles) > 0 {
		b.WriteString("kms_read_roles:\n")
		keys := make([]string, 0, len(cfg.KMSReadRoles))
		for k := range cfg.KMSReadRoles {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %q: %q\n", k, cfg.KMSReadRoles[k])
		}
	}
	return b.String()
}

// crqKeyringFile is the name of the keyring file inside a trust set. It is written here once, for the test
// bundles that put the file in place or take it out.
const crqKeyringFile = "keyring.gpg"

// crqKeyring is the keyring file of the primaries given by their letters (a, b, c or z): the certificate
// files of the root list vectors, joined in the order given.
func crqKeyring(t testing.TB, letters ...string) []byte {
	t.Helper()
	var out []byte
	for _, l := range letters {
		out = append(out, crqRead(t, "root-list", "v1", "pki", "test-primary-"+l+".pgp")...)
	}
	if len(out) == 0 {
		t.Fatal("a keyring file with no certificate")
	}
	return out
}

// crqTrust is the files of the trust set of the sequence 7 of the root list vectors: the list with the test
// roots A and B, the CA bundle of that list and the keyring file of its two primaries (a, then b, the order of
// the list). The signature is made by the vectors and copied; the command does not read it.
func crqTrust(t testing.TB) crqTree {
	t.Helper()
	at := "trust/" + crqTrustSet + "/"
	return crqTree{
		at + "root-list.json": crqRead(t, "root-list", "v1", "lists", "seq7-a.json"),
		at + "root-list.jws":  crqRead(t, "root-list", "v1", "lists", "seq7-a.jws"),
		at + "ca-bundle.pem":  crqRead(t, "root-list", "v1", "bundles", "ca-bundle-7.pem"),
		at + crqKeyringFile:   crqKeyring(t, "a", "b"),
	}
}

// crqRingPrimaries are the primaries of a keyring file as a second reader gives them: go-crypto reads the file, and
// the fingerprint, the key and the creation time of each primary are taken from its key packet. The command's own
// reader (package openpgp) is not used, so a fault of that reader cannot hide on both sides of a comparison.
func crqRingPrimaries(t testing.TB, file []byte) []handoff.PrimaryRef {
	t.Helper()
	ring, err := pgp.ReadKeyRing(bytes.NewReader(file))
	if err != nil || len(ring) == 0 {
		t.Fatalf("go-crypto cannot read the keyring file: %v", err)
	}
	var out []handoff.PrimaryRef
	for _, e := range ring {
		pub, ok := e.PrimaryKey.PublicKey.(*pgpecdsa.PublicKey)
		if !ok {
			t.Fatalf("go-crypto reads a key of type %T", e.PrimaryKey.PublicKey)
		}
		pt := make([]byte, 97)
		pt[0] = 4
		pub.X.FillBytes(pt[1:49])
		pub.Y.FillBytes(pt[49:])
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pt)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, handoff.PrimaryRef{Fingerprint: hex.EncodeToString(e.PrimaryKey.Fingerprint), Key: key, Created: e.PrimaryKey.CreationTime.UTC()})
	}
	return out
}

// crqFingerprintMember is the member of a root list that pins an OpenPGP primary, with the comma after it.
var crqFingerprintMember = regexp.MustCompile(`"openpgp_fingerprint":"[0-9a-f]{40}",`)

// crqTrustWithoutPrimaries is the trust set of crqTrust whose list pins no OpenPGP primary: the members
// openpgp_fingerprint are cut from the list as text (the reader of the list does not need the canonical form), and
// there is no keyring file. The signature file is the one of the whole list and does not fit; the command does
// not read it.
func crqTrustWithoutPrimaries(t testing.TB) crqTree {
	t.Helper()
	tr := crqTrust(t)
	at := "trust/" + crqTrustSet + "/"
	list := tr[at+"root-list.json"]
	cut := crqFingerprintMember.ReplaceAll(list, nil)
	if bytes.Equal(cut, list) || bytes.Contains(cut, []byte("openpgp_fingerprint")) {
		t.Fatal("the fingerprints were not cut from the list")
	}
	tr[at+"root-list.json"] = cut
	delete(tr, at+crqKeyringFile)
	return tr
}

// crqWithTrust is the tree with the files of its trust set replaced by the files of another.
func crqWithTrust(tree, trust crqTree) crqTree {
	out := crqTree{}
	for p, d := range tree {
		if !strings.HasPrefix(p, "trust/") {
			out[p] = d
		}
	}
	for p, d := range trust {
		out[p] = d
	}
	return out
}

// crqRequestFiles is the files of a case under requests/STEM/, by the name after the stem.
func crqRequestFiles(t testing.TB, c crqCase) crqTree {
	t.Helper()
	stem := c.stem(t)
	out := crqTree{}
	for _, f := range c.Files {
		if path.Dir(f) != "requests" || !strings.HasPrefix(path.Base(f), stem+".") {
			t.Fatalf("the case %s: the file %s is not of the stem %s in requests/", c.ID, f, stem)
		}
		out["requests/"+stem+"/"+path.Base(f)] = testrepo.Read(t, crqVectorsDir, f)
	}
	return out
}

// crqBundleTree is every file of a bundle that can check the case.
func crqBundleTree(t testing.TB, m crqManifest, c crqCase) crqTree {
	t.Helper()
	cfg, ok := m.Configs[c.Config]
	if !ok {
		t.Fatalf("the case %s names the configuration %q, which the manifest does not hold", c.ID, c.Config)
	}
	return crqMerge(
		crqTree{
			"ritueel.yaml":                                []byte(crqSettings(cfg)),
			"want/roots/" + crqRoot + ".yaml":             []byte("version: 1\nkind: " + crqRootKind(c.Type) + "\ntest: true\n"),
			"want/delegations/" + crqDelegation + ".yaml": []byte(crqDelegationText(t, c, cfg)),
		},
		crqTrust(t),
		crqRequestFiles(t, c),
	)
}

// crqBundle writes the bundle of a case into a new folder and returns it.
func crqBundle(t testing.TB, m crqManifest, c crqCase) string {
	t.Helper()
	dir := t.TempDir()
	crqWrite(t, dir, crqBundleTree(t, m, c))
	return dir
}

// crqBundleOf is the bundle of the case with the id.
func crqBundleOf(t testing.TB, id string) (dir, stem string) {
	t.Helper()
	m := crqManifestOf(t)
	c := m.byID(t, id)
	return crqBundle(t, m, c), c.stem(t)
}

// crqRun runs the command line in process with the clock of the vectors and fresh buffers.
func crqRun(t testing.TB, now time.Time, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, Env{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
		Build:  testBuild,
		Now:    func() time.Time { return now },
	})
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// crqClock is the clock of the vectors.
func crqClock(t testing.TB) time.Time { return crqManifestOf(t).clock(t) }

// crqRoots are the roots of the pinned root list of the manifest, read from their certificates.
func crqRoots(t testing.TB, m crqManifest) []handoff.RootRef {
	t.Helper()
	if len(m.Pinned.RootList.X509) < 2 {
		t.Fatalf("the pinned root list holds %d X.509 roots, want at least 2", len(m.Pinned.RootList.X509))
	}
	var roots []handoff.RootRef
	for _, f := range m.Pinned.RootList.X509 {
		blk, _ := pem.Decode(testrepo.Read(t, crqVectorsDir, f))
		if blk == nil {
			t.Fatalf("%s holds no PEM block", f)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("%s: the key is not ECDSA", f)
		}
		roots = append(roots, handoff.RootRef{Subject: cert.RawSubject, Key: key})
	}
	return roots
}

// crqLibrary is the library run of a case, made the way the command makes its own: the policy and the
// delegation of the configuration, the roots of the vectors, the clock of the vectors, no verifier and the
// primaries of the keyring file of the test trust set, read by another reader than the command's. It returns what
// Check returned.
func crqLibrary(t testing.TB, m crqManifest, c crqCase) (handoff.Verdict, error) {
	t.Helper()
	return crqLibraryWith(t, m, c, true)
}

// crqLibraryWith is crqLibrary with the delegation of the case, or with none, as the command is run with and
// without --delegation.
func crqLibraryWith(t testing.TB, m crqManifest, c crqCase, withDelegation bool) (handoff.Verdict, error) {
	t.Helper()
	cfg := m.Configs[c.Config]
	p := handoff.Policy{MinFirmware: cfg.MinFirmware, ValidityMonths: cfg.ValidityMonths}
	for _, s := range cfg.Stores {
		p.Stores = append(p.Stores, handoff.Store(s))
	}
	for _, s := range cfg.PINPolicy {
		p.PINPolicies = append(p.PINPolicies, handoff.PINPolicy(s))
	}
	d := &handoff.Delegation{
		Name:              crqDelegation,
		Type:              handoff.Type(c.Type),
		Root:              crqRoot,
		PermittedURIHosts: cfg.PermittedURIHosts,
		PermittedDNSNames: cfg.PermittedDNSNames,
		KMSReadRoles:      cfg.KMSReadRoles,
	}
	switch c.Type {
	case "openpgp-subkey":
		d.Capability = "sign"
		if strings.Contains(c.ID, "authenticate") {
			d.Capability = "authenticate"
		}
	case "ssh-ca-key":
		d.Use = "user"
		var proof struct {
			Use string `json:"use"`
		}
		for _, f := range c.Files {
			if strings.HasSuffix(f, "."+handoff.FileProof) {
				if err := json.Unmarshal(testrepo.Read(t, crqVectorsDir, f), &proof); err != nil {
					t.Fatal(err)
				}
			}
		}
		if proof.Use == "user" || proof.Use == "host" {
			d.Use = proof.Use
		}
	}
	if !withDelegation {
		d = nil
	}
	clock := m.clock(t)
	cfg2 := handoff.Config{Policy: p, Delegation: d, Roots: crqRoots(t, m), Now: func() time.Time { return clock }}
	// The checker holds the primaries of the trust set with no delegation and with a delegation of the type
	// openpgp-subkey, and none beside a delegation of another type (the library refuses them there).
	if !withDelegation || c.Type == "openpgp-subkey" {
		cfg2.Primaries = crqRingPrimaries(t, crqKeyring(t, "a", "b"))
	}
	checker, err := handoff.New(cfg2)
	if err != nil {
		t.Fatalf("the library cannot be made for %s: %v", c.ID, err)
	}
	root, err := fsx.OpenFS(testrepo.Path(t, crqVectorsDir))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	req, err := handoff.LoadRequest(root, "requests", c.stem(t))
	if err != nil {
		t.Fatalf("the case %s: %v", c.ID, err)
	}
	return checker.Check(context.Background(), req)
}

// crqSnapshot is every entry of a folder, links not followed, as "path type mode digest", sorted. A link
// holds its target; a regular file holds the digest of its bytes.
func crqSnapshot(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		line := rel + " " + info.Mode().String()
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			line += " -> " + target
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			line += " " + hex.EncodeToString(sum[:])
		}
		out = append(out, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// crqSame fails the test when two snapshots differ.
func crqSame(t testing.TB, what string, before, after []string) {
	t.Helper()
	if strings.Join(before, "\n") == strings.Join(after, "\n") {
		return
	}
	set := map[string]int{}
	for _, l := range before {
		set[l]--
	}
	for _, l := range after {
		set[l]++
	}
	var diff []string
	for l, n := range set {
		if n != 0 {
			diff = append(diff, fmt.Sprintf("%+d %s", n, l))
		}
	}
	sort.Strings(diff)
	t.Errorf("%s changed the folder:\n%s", what, strings.Join(diff, "\n"))
}

// crqChecks decodes the member "checks" of the object on standard output into the pairs (n, result).
func crqChecks(t testing.TB, obj map[string]any) [][2]string {
	t.Helper()
	list, ok := obj["checks"].([]any)
	if !ok {
		t.Fatalf("the object has no list \"checks\": %v", obj)
	}
	var out [][2]string
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok || len(m) != 2 {
			t.Fatalf("an entry of checks is not {n, result}: %v", e)
		}
		n, isNumber := m["n"].(json.Number)
		res, isString := m["result"].(string)
		if !isNumber || !isString {
			t.Fatalf("an entry of checks has a wrong type: %v", e)
		}
		out = append(out, [2]string{n.String(), res})
	}
	return out
}

// crqRingPrimariesOrNil are the fingerprints that go-crypto reads from a keyring file, in order, or nil when it
// cannot read the file as a keyring.
func crqRingPrimariesOrNil(file []byte) []string {
	ring, err := pgp.ReadKeyRing(bytes.NewReader(file))
	if err != nil || len(ring) == 0 {
		return nil
	}
	var out []string
	for _, e := range ring {
		out = append(out, hex.EncodeToString(e.PrimaryKey.Fingerprint))
	}
	return out
}
