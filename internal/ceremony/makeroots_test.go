//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/wanted"
)

// MakeRoots makes the keys and the artifacts of the first apply of an X.509 test root: two keys, a
// root certificate and a removal authorisation for each, a root.json for each and the first trust
// set. It runs the births, the signatures and the seven checks, writes the lines of the two journals
// and shows the fingerprints, and writes no file of the bundle (record 0005, rules 10 to 12).

func TestMakeRootsDoesEveryStepInTheOrderOfTheRecord(t *testing.T) {
	r, _ := mkGood(t)
	// record 0005, rule 10: a line after each key exists and after each signature is made, before the
	// next begins; rule 11: each fingerprint is shown before any root key signs for it.
	want := []string{
		"refuse",
		"birth A", "births-line A", "birth B", "births-line B",
		"console: root key A: x509 pin ", "console: root key B: x509 pin ",
		"sign A", "signatures-line 1 root-certificate",
		"sign A", "save-removal A", "signatures-line 2 root-removal",
		"sign B", "signatures-line 3 root-certificate",
		"sign B", "save-removal B", "signatures-line 4 root-removal",
		"sign A", "signatures-line 5 root-list",
		"read-removal A", "read-removal B",
	}
	got := r.log.all()
	if len(got) != len(want) {
		t.Fatalf("the run has %d events, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("event %d is %q, want %q", i+1, got[i], want[i])
		}
	}
	if n := r.log.count("console-out:"); n != 0 {
		t.Errorf("%d lines on standard output; the fingerprints go to standard error", n)
	}
}

func TestTheFingerprintsShownAreThePinsOfTheKeysInTheKeyFiles(t *testing.T) {
	r, m := mkGood(t)
	for _, l := range []string{"A", "B"} {
		d := mkScalarKey(t, r.keyDir, l)
		pin := mkPin(&d.PublicKey)
		line := "console: root key " + l + ": x509 pin " + pin
		if r.log.index(line) < 0 {
			t.Errorf("the console did not show %q:\n%s", line, strings.Join(r.log.all(), "\n"))
		}
		i := slices.IndexFunc(m.Roots, func(x ceremony.MadeRoot) bool { return x.Label == l })
		if i < 0 || m.Roots[i].Pin != pin {
			t.Errorf("the pin of %s in the result is not the pin of the key file", l)
		}
	}
	tr, err := r.console.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"A", "B"} {
		if !bytes.Contains(tr, []byte("root key "+l+": x509 pin ")) {
			t.Errorf("the transcript does not hold the fingerprint of %s", l)
		}
	}
}

// mkScalarKey reads the private key of a key file.
func mkScalarKey(t testing.TB, keyDir, label string) *ecdsa.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(keyDir, mkKeyFile(label)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PrivateKey)
}

func TestTheResultHoldsTheArtifactsOfThePageAndNoSecret(t *testing.T) {
	r, m := mkGood(t)
	if len(m.Roots) != 2 || m.Roots[0].Label != "A" || m.Roots[1].Label != "B" {
		t.Fatalf("the roots are %+v", m.Roots)
	}
	if !slices.Equal(m.Checked, []string{"root-certificate", "removal-authorisation", "root-list", "ca-bundle", "root-json", "plan", "journals"}) {
		t.Errorf("Checked = %v", m.Checked)
	}
	// The set: three files, the names of the set, in the folder trust/1-<8 characters>.
	sum := sha256.Sum256(m.Set.ListJSON())
	wantDir := "trust/1-" + hex.EncodeToString(sum[:])[:8]
	if m.TrustSetDir() != wantDir || m.Set.Name() != "1-"+hex.EncodeToString(sum[:])[:8] {
		t.Errorf("the set is %q in %q, want %q", m.Set.Name(), m.TrustSetDir(), wantDir)
	}
	var names []string
	for _, f := range m.Set.Files() {
		names = append(names, f.Name)
	}
	if !slices.Equal(names, []string{"root-list.json", "root-list.jws", "ca-bundle.pem"}) {
		t.Errorf("the files of the set are %v", names)
	}
	wantPaths := []string{
		"roots/A/root.json", "roots/B/root.json",
		wantDir + "/ca-bundle.pem", wantDir + "/root-list.json", wantDir + "/root-list.jws",
	}
	if got := m.Artifacts(); !slices.Equal(got, wantPaths) {
		t.Errorf("Artifacts = %v, want %v", got, wantPaths)
	}
	if !slices.IsSorted(m.Artifacts()) {
		t.Error("the artifacts are not in the byte order of the path")
	}
	// The record: the plan's root with the pin of the key that signed the list (A).
	wantRoot := files.PlanRoot{Label: "A", Store: "software", X509: m.Roots[0].Pin, Test: true, Copyable: true}
	if m.Record != wantRoot {
		t.Errorf("Record = %+v, want %+v", m.Record, wantRoot)
	}
	if *r.plan.Plan.Root != (files.PlanRoot{Label: "A", Store: "software", Test: true, Copyable: true}) {
		t.Errorf("the plan's root is %+v", *r.plan.Plan.Root)
	}
	// Each root: a certificate that an independent reader accepts for the key file, a removal digest
	// that is the digest of the stored text, and a root.json that says so.
	for i, root := range m.Roots {
		k := mkScalarKey(t, r.keyDir, root.Label)
		if root.Pin != mkPin(&k.PublicKey) || root.Place != "x509-root-"+strings.ToLower(root.Label) {
			t.Errorf("%s: pin %s place %s", root.Label, root.Pin, root.Place)
		}
		sig := r.plan.Signatures[2*i]
		want := ceremony.RootCertWant{Name: "Example", Label: root.Label, Pin: root.Pin, Serial: sig.Serial, NotBefore: pfClock, NotAfter: mkAddMonths(pfClock, 36)}
		if err := ceremony.CheckRootCertificate(root.Certificate, want); err != nil {
			t.Errorf("%s: %v", root.Label, err)
		}
		stored, err := os.ReadFile(filepath.Join(r.keyDir, root.Label+".removal.jws"))
		if err != nil {
			t.Fatal(err)
		}
		sh := sha256.Sum256(stored)
		if root.RemovalSHA256 != hex.EncodeToString(sh[:]) {
			t.Errorf("%s: removal digest %s is not the digest of the stored file", root.Label, root.RemovalSHA256)
		}
		if root.RootJSONPath != "roots/"+root.Label+"/root.json" {
			t.Errorf("%s: path %q", root.Label, root.RootJSONPath)
		}
		doc, err := files.ReadRootJSON(root.RootJSON)
		if err != nil {
			t.Fatalf("%s: %v", root.Label, err)
		}
		wantDoc := files.RootJSON{Version: 1, Label: root.Label, Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z", X509SPKISHA256: root.Pin, RemovalSHA256: root.RemovalSHA256}
		if !reflect.DeepEqual(*doc, wantDoc) {
			t.Errorf("%s: root.json is %+v, want %+v", root.Label, *doc, wantDoc)
		}
		// The removal authorisations of the two keys differ.
	}
	a, _ := os.ReadFile(filepath.Join(r.keyDir, "A.removal.jws"))
	b, _ := os.ReadFile(filepath.Join(r.keyDir, "B.removal.jws"))
	if bytes.Equal(a, b) || m.Roots[0].RemovalSHA256 == m.Roots[1].RemovalSHA256 {
		t.Error("the removal authorisations of two labels are one text")
	}
	// No secret in the result: not the scalar, its hex or its Base64.
	var blob []byte
	for _, root := range m.Roots {
		blob = append(blob, root.Certificate...)
		blob = append(blob, root.RootJSON...)
	}
	for _, f := range m.Set.Files() {
		blob = append(blob, f.Data...)
	}
	blob = append(blob, []byte(strings.Join(r.log.all(), "\n"))...)
	mkWantNoScalar(t, "the result and the lines of the run", blob, r.keyDir)
}

// mkWantNoScalar fails the test when the data holds the scalar of a key of the key directory, in
// bytes, in hexadecimal or in Base64 (standard or url, with and without padding).
func mkWantNoScalar(t testing.TB, what string, data []byte, keyDir string) {
	t.Helper()
	for _, l := range []string{"A", "B"} {
		raw := mkScalar(t, keyDir, l)
		forms := map[string][]byte{
			"bytes": raw, "hex": []byte(hex.EncodeToString(raw)), "HEX": []byte(strings.ToUpper(hex.EncodeToString(raw))),
			"std": []byte(base64.StdEncoding.EncodeToString(raw)), "url": []byte(base64.URLEncoding.EncodeToString(raw)),
			"rawstd": []byte(base64.RawStdEncoding.EncodeToString(raw)), "rawurl": []byte(base64.RawURLEncoding.EncodeToString(raw)),
		}
		for name, f := range forms {
			if bytes.Contains(data, f) {
				t.Errorf("%s hold the private key of %s (%s)", what, l, name)
			}
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Errorf("%s hold a PRIVATE KEY armour", what)
		}
	}
}

func TestEveryKeyIsClosedWhenMakeRootsReturns(t *testing.T) {
	r := newMkRun(t)
	r.mustMake()
	if len(r.store.keys) != 2 {
		t.Fatalf("%d keys were born", len(r.store.keys))
	}
	for _, k := range r.store.keys {
		if k.closed() < 1 {
			t.Errorf("the key %s is not closed", k.label)
		}
	}
	// A closed key does not sign any more.
	if _, err := r.store.keys[0].Key.Sign(rand.Reader, make([]byte, 48), crypto.SHA384); err == nil {
		t.Error("a key signs after MakeRoots returned")
	}
}

func TestMakeRootsAsksEachKeyOnceForEachSignatureOfThePlanAndNoMore(t *testing.T) {
	r, _ := mkGood(t)
	if n := r.log.count("sign A"); n != 3 {
		t.Errorf("A signed %d times, want 3 (its certificate, its removal authorisation, the list)", n)
	}
	if n := r.log.count("sign B"); n != 2 {
		t.Errorf("B signed %d times, want 2", n)
	}
}

func TestMakeRootsWritesNoFileInTheBundleAndOnlyTheKeysInTheKeyDirectory(t *testing.T) {
	r := newMkRun(t)
	before := tree(t, r.bundleDir)
	r.mustMake()
	sameTree(t, "the bundle", before, tree(t, r.bundleDir))
	if got, want := r.keyFiles(), []string{"A.removal.jws", "B.removal.jws", mkKeyFile("A"), mkKeyFile("B")}; !slices.Equal(got, want) {
		t.Errorf("the key directory holds %v, want %v", got, want)
	}
	if got, want := mkNames(t, r.keyDir), []string{"A.removal.jws", "B.removal.jws", "test-only-keys"}; !slices.Equal(got, want) {
		t.Errorf("the key directory holds the entries %q, want %q", got, want)
	}
	if st, err := os.Stat(filepath.Join(r.keyDir, "test-only-keys")); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Errorf("the folder test-only-keys: %v, %v; want a folder of the mode 0700", st, err)
	}
	for _, n := range r.keyFiles() {
		st, err := os.Stat(filepath.Join(r.keyDir, n))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", n, st, err)
		}
	}
}

func TestTheRemovalAuthorisationsOfTheRunFollowThePage(t *testing.T) {
	// docs/reference/root-list.md, "The removal authorisation": a compact JWS, Base64url without
	// padding, ASCII, no trailing newline; payload {"version":1,"x509_spki_sha256":"<pin>"}; a header
	// of alg ES384, kid the pin, typ root-removal+json and x5c the certificate.
	r, m := mkGood(t)
	for _, root := range m.Roots {
		b, err := os.ReadFile(filepath.Join(r.keyDir, root.Label+".removal.jws"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		if strings.HasSuffix(text, "\n") || strings.Count(text, ".") != 2 {
			t.Fatalf("%s: the text is not three parts and no line feed", root.Label)
		}
		parts := strings.Split(text, ".")
		hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"version":1,"x509_spki_sha256":"` + root.Pin + `"}`; string(payload) != want {
			t.Errorf("%s: the payload is %s", root.Label, payload)
		}
		wantHdr := `{"alg":"ES384","kid":"` + root.Pin + `","typ":"root-removal+json","x5c":["` + base64.StdEncoding.EncodeToString(root.Certificate) + `"]}`
		if string(hdr) != wantHdr {
			t.Errorf("%s: the header is %s", root.Label, hdr)
		}
		if sig, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(sig) != 96 {
			t.Errorf("%s: the signature is %d bytes (%v)", root.Label, len(sig), err)
		}
		if err := rootlist.CheckRemoval(rootlist.Removal{Label: root.Label, X509SPKISHA256: root.Pin, Authorisation: text}, nil, []string{root.Pin}); err != nil {
			t.Errorf("%s: %v", root.Label, err)
		}
	}
}

func TestTheFirstListOfTheRunIsAcceptedByAHostThatHoldsTheTwoPins(t *testing.T) {
	_, m := mkGood(t)
	trust, err := rootlist.PinTrust([]string{m.Roots[0].Pin, m.Roots[1].Pin})
	if err != nil {
		t.Fatal(err)
	}
	v := rootlist.Verify(rootlist.Signed{JSON: m.Set.ListJSON(), JWS: m.Set.ListJWS()}, trust, pfClock)
	if !v.Accepted || v.Again || v.Wayback {
		t.Fatalf("the list is refused: %+v", v)
	}
	if v.List.Sequence != 1 || v.List.LastRecordSHA256 != "" || len(v.List.Removals) != 0 {
		t.Errorf("the list is %+v", v.List)
	}
	// A host that holds the pin of one key only does not take it: the first list of two keys is
	// signed by one of them, and the host that holds the other alone has no way to know the first.
	if got := m.Set.Signers(); !slices.Equal(got, []string{"A"}) {
		t.Errorf("the list is signed by %v, want A alone", got)
	}
}

// ---- faults after the first key ----

func TestAFailedBirthOfTheSecondKeyLeavesOneKeyFileOneLineAndNoSignature(t *testing.T) {
	r := newMkRun(t)
	r.store.failBirth = map[string]error{"B": errors.New("test: the key of B cannot be made")}
	m, err := r.make()
	if m != nil || err == nil {
		t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
	}
	var me *ceremony.MakeError
	if !errors.As(err, &me) || me.Step != "births" {
		t.Errorf("the error is %v, want a MakeError of the step births", err)
	}
	if got := r.keyFiles(); !slices.Equal(got, []string{mkKeyFile("A")}) {
		t.Errorf("the key directory holds %v, want one key file", got)
	}
	if r.log.count("births-line") != 1 || r.log.count("console:") != 0 || r.log.count("sign") != 0 || r.log.count("signatures-line") != 0 {
		t.Errorf("after a failed birth the run did:\n%s", strings.Join(r.log.all(), "\n"))
	}
	if k := r.store.keys; len(k) != 1 || k[0].closed() < 1 {
		t.Error("the key of A is not closed")
	}
}

func TestAKeyThatIsBornAndWhoseJournalLineFailsLeavesTheKeyAndNoFingerprint(t *testing.T) {
	r := newMkRun(t)
	r.trace.births.failAt = 2
	m, err := r.make()
	if m != nil || err == nil {
		t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
	}
	// The key exists; the line does not: the page says that a missing line may mean that the key exists.
	if got := r.keyFiles(); !slices.Equal(got, []string{mkKeyFile("A"), mkKeyFile("B")}) {
		t.Errorf("the key directory holds %v", got)
	}
	if r.log.count("births-line") != 1 || r.log.count("console:") != 0 || r.log.count("sign") != 0 {
		t.Errorf("the run did:\n%s", strings.Join(r.log.all(), "\n"))
	}
	for _, k := range r.store.keys {
		if k.closed() < 1 {
			t.Errorf("the key %s is not closed", k.label)
		}
	}
}

func TestAFailedSaveOfARemovalAuthorisationLeavesNoFileAndNoLineForIt(t *testing.T) {
	r := newMkRun(t)
	r.store.failRemoval = map[string]error{"A": errors.New("test: disk full")}
	m, err := r.make()
	if m != nil || err == nil {
		t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
	}
	var me *ceremony.MakeError
	if !errors.As(err, &me) || me.Step != "signatures" {
		t.Errorf("the error is %v", err)
	}
	for _, n := range r.keyFiles() {
		if strings.HasSuffix(n, ".removal.jws") {
			t.Errorf("the file %s exists", n)
		}
	}
	// The certificate of A was signed and has its line; the removal of A has none; nothing of B signs.
	if r.log.count("signatures-line 1 ") != 1 || r.log.count("signatures-line 2 ") != 0 || r.log.count("sign B") != 0 {
		t.Errorf("the run did:\n%s", strings.Join(r.log.all(), "\n"))
	}
}

func TestAFaultOfTheKeyStoreWithAReasonCodeIsReturnedAsABackendRefusal(t *testing.T) {
	for _, step := range []string{"birth", "saveremoval", "refuse"} {
		t.Run(step, func(t *testing.T) {
			r := newMkRun(t)
			be := &ceremony.BackendError{Reasons: []string{"key-exists"}, Msg: "test: the key file stands there"}
			switch step {
			case "birth":
				r.store.failBirth = map[string]error{"B": be}
			case "saveremoval":
				r.store.failRemoval = map[string]error{"B": be}
			case "refuse":
				r.store.refuseErr = be
			}
			m, err := r.make()
			if m != nil || err == nil {
				t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
			}
			if !mkIsItself(err, be) {
				t.Fatalf("the error is %T %v, want the *BackendError itself and not wrapped (exit code 4)", err, err)
			}
			if step == "refuse" && (r.log.count("birth") != 0 || len(r.keyFiles()) != 0 || r.log.count("-line") != 0) {
				t.Errorf("a refusal that needs no key made keys or lines:\n%s", strings.Join(r.log.all(), "\n"))
			}
		})
	}
}

func TestAKeyFileThatStandsInTheKeyDirectoryIsRefusedBeforeAnyKeyIsMade(t *testing.T) {
	r := newMkRun(t)
	if err := os.WriteFile(filepath.Join(r.keyDir, "A.x509.key.pem"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := r.make()
	if m != nil || mkBackendReason(err) != "key-exists" {
		t.Fatalf("MakeRoots: a result %v, the error %v; want key-exists", m != nil, err)
	}
	if r.log.count("birth") != 0 || r.log.count("-line") != 0 || r.log.count("console:") != 0 {
		t.Errorf("the run did:\n%s", strings.Join(r.log.all(), "\n"))
	}
	if b, _ := os.ReadFile(filepath.Join(r.keyDir, "A.x509.key.pem")); string(b) != "old" {
		t.Errorf("the key file was changed: %q", b)
	}
}

func TestAJournalThatRefusesALineStopsTheRunAtThatLine(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5} {
		t.Run("signature line "+string(rune('0'+n)), func(t *testing.T) {
			r := newMkRun(t)
			r.trace.sigs.failAt = n
			m, err := r.make()
			if m != nil || err == nil {
				t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
			}
			if got := r.log.count("signatures-line"); got != n-1 {
				t.Errorf("%d signature lines were written, want %d", got, n-1)
			}
			// The n-th line fails after the n-th signature was made, and no later key is asked.
			if signs := r.log.count("sign "); signs != n {
				t.Errorf("%d signatures were asked for, want %d", signs, n)
			}
			for _, k := range r.store.keys {
				if k.closed() < 1 {
					t.Errorf("the key %s is not closed", k.label)
				}
			}
		})
	}
}

func TestAStoreOrAKeyOrAJournalThatPanicsIsAnErrorAndNotACrash(t *testing.T) {
	cases := map[string]func(r *mkRun){
		"store refuse":       func(r *mkRun) { r.store.panicOn = "refuse" },
		"store birth":        func(r *mkRun) { r.store.panicOn = "birth" },
		"store save":         func(r *mkRun) { r.store.panicOn = "saveremoval" },
		"store read":         func(r *mkRun) { r.store.panicOn = "readremoval" },
		"store kind":         func(r *mkRun) { r.store.panicOn = "kind" },
		"store place":        func(r *mkRun) { r.store.panicOn = "place" },
		"key sign":           func(r *mkRun) { r.store.wrapKey = mkWrap(func(k *mkKey) { k.panicOn = "sign" }) },
		"key public":         func(r *mkRun) { r.store.wrapKey = mkWrap(func(k *mkKey) { k.panicOn = "public" }) },
		"key close":          func(r *mkRun) { r.store.wrapKey = mkWrap(func(k *mkKey) { k.panicOn = "close" }) },
		"births journal":     func(r *mkRun) { r.trace.births.panics = true },
		"signatures journal": func(r *mkRun) { r.trace.sigs.panics = true },
		"the clock":          func(r *mkRun) { r.env.Now = func() time.Time { panic("clock") } },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newMkRun(t)
			setup(r)
			var m *ceremony.Made
			var err error
			func() {
				defer func() {
					if x := recover(); x != nil {
						t.Fatalf("MakeRoots panicked: %v", x)
					}
				}()
				m, err = r.make()
			}()
			if name == "key close" {
				// A key that panics when it is closed is closed and the run is the run it was.
				if err != nil || m == nil {
					t.Errorf("a panic of Close at the end changed the result: %v", err)
				}
				return
			}
			if m != nil || err == nil {
				t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the text %+q is not printable ASCII", err.Error())
			}
		})
	}
}

// mkWrap makes a wrapKey that changes each key with edit.
func mkWrap(edit func(k *mkKey)) func(string, keystore.Key) keystore.Key {
	return func(label string, k keystore.Key) keystore.Key {
		mk := &mkKey{Key: k, label: label}
		edit(mk)
		return mk
	}
}

func TestAStoreThatGivesAKeyThatIsNotWhatThePlanSaysIsRefusedAndNothingSigns(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	no := false
	cases := map[string]func(r *mkRun){
		"no key":                         func(r *mkRun) { r.store.nilKeyFor = "A" },
		"a typed nil key":                func(r *mkRun) { r.store.typedNilFor = "A" },
		"a P-256 key":                    func(r *mkRun) { r.store.wrapKey = mkWrap(func(k *mkKey) { k.pub = &p256.PublicKey }) },
		"a public key that is not a key": func(r *mkRun) { r.store.wrapKey = mkWrap(func(k *mkKey) { k.pub = "key" }) },
		"a key of another kind":          func(r *mkRun) { r.store.wrapKey = mkWrap(func(k *mkKey) { k.kind = "piv" }) },
		"a key that is not copyable":     func(r *mkRun) { r.store.wrapKey = mkWrap(func(k *mkKey) { k.copyOv = &no }) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newMkRun(t)
			setup(r)
			m, err := r.make()
			if m != nil || err == nil {
				t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
			}
			// The key is judged when it is born, before any key signs.
			if me, ok := mkAs[*ceremony.MakeError](err); !ok || me.Step != "births" {
				t.Errorf("the error is %v, want a fault of the step births", err)
			}
			if r.log.count("sign") != 0 || r.log.count("signatures-line") != 0 {
				t.Errorf("a key that is not what the plan says signed:\n%s", strings.Join(r.log.all(), "\n"))
			}
			for _, k := range r.store.keys {
				if k.closed() < 1 {
					t.Errorf("the key %s is not closed", k.label)
				}
			}
		})
	}
}

func TestAKeyThatSignsWithAnotherKeyIsCaughtBeforeTheCertificateIsUsed(t *testing.T) {
	other := mkKeyP384()
	r := newMkRun(t)
	r.store.wrapKey = mkWrap(func(k *mkKey) {
		k.signFn = func(rd io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error) {
			return other.Sign(rd, digest, o)
		}
	})
	m, err := r.make()
	if m != nil || err == nil {
		t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
	}
	if r.log.count("signatures-line") != 0 {
		t.Errorf("a signature by another key has a line:\n%s", strings.Join(r.log.all(), "\n"))
	}
	for _, bad := range [][]byte{nil, {1, 2, 3}, bytes.Repeat([]byte{0x30}, 200)} {
		r := newMkRun(t)
		r.store.wrapKey = mkWrap(func(k *mkKey) {
			k.signFn = func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return bad, nil }
		})
		if m, err := r.make(); m != nil || err == nil {
			t.Errorf("a signature of %d bytes: a result %v, %v", len(bad), m != nil, err)
		}
	}
	r = newMkRun(t)
	r.store.wrapKey = mkWrap(func(k *mkKey) {
		k.signFn = func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, errors.New("test: no touch") }
	})
	if m, err := r.make(); m != nil || err == nil {
		t.Errorf("a key that fails: a result %v, %v", m != nil, err)
	}
}

func TestAContextThatIsCancelledAfterTheFirstBirthStopsTheRun(t *testing.T) {
	r := newMkRun(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.store.afterBirth = func(label string) {
		if label == "A" {
			cancel()
		}
	}
	m, err := ceremony.MakeRoots(ctx, r.in())
	if m != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
	}
	if got := r.keyFiles(); !slices.Equal(got, []string{mkKeyFile("A")}) {
		t.Errorf("the key directory holds %v", got)
	}
	if r.log.count("birth B") != 0 || r.log.count("sign") != 0 {
		t.Errorf("the run went on:\n%s", strings.Join(r.log.all(), "\n"))
	}
}

func TestACheckThatFindsAMismatchStopsTheRunAndReturnsNothing(t *testing.T) {
	r := newMkRun(t)
	before := tree(t, r.bundleDir)
	defer func() { sameTree(t, "the bundle after a refused check", before, tree(t, r.bundleDir)) }()
	r.store.readRemoval = func(label string, real []byte) []byte {
		if label == "B" {
			return append(append([]byte(nil), real...), '\n')
		}
		return real
	}
	m, err := r.make()
	if m != nil {
		t.Fatalf("a result comes with the error %v", err)
	}
	mkWantArtifactError(t, err, "removal authorisation B", "stored file")
	r = newMkRun(t)
	r.store.readRemoval = func(label string, real []byte) []byte { return nil }
	m, err = r.make()
	if m != nil {
		t.Fatalf("a result comes with the error %v", err)
	}
	mkWantArtifactError(t, err, "removal authorisation A", "stored file")
}

// ---- input faults: before any key ----

func TestEveryFaultOfTheInputIsRefusedBeforeAnyKeyIsMade(t *testing.T) {
	personal, err := wanted.ParseSettings("ritueel.yaml", []byte(pfPersonal))
	if err != nil {
		t.Fatal(err)
	}
	otherName, err := wanted.ParseRoot("other", []byte(pfX509Test))
	if err != nil {
		t.Fatal(err)
	}
	real, err := wanted.ParseRoot("x509", []byte(pfX509Real))
	if err != nil {
		t.Fatal(err)
	}
	var nilStore *mkStore
	done, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name string
		edit func(r *mkRun, in *ceremony.MakeIn)
		ctx  context.Context
	}{
		{name: "the context is done", ctx: done},
		{name: "a zero input", edit: func(_ *mkRun, in *ceremony.MakeIn) { *in = ceremony.MakeIn{} }},
		{name: "no store", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Store = nil }},
		{name: "a typed nil store", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Store = nilStore }},
		{name: "no plan", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Plan = nil }},
		{name: "a plan with no bytes", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Plan = &ceremony.PlanOut{} }},
		{name: "a plan that is not JSON", edit: func(r *mkRun, in *ceremony.MakeIn) {
			p := *r.plan
			p.JSON = []byte("not json")
			in.Plan = &p
		}},
		{name: "a digest that is not the digest of the bytes", edit: func(r *mkRun, in *ceremony.MakeIn) {
			p := *r.plan
			p.SHA256 = strings.Repeat("0", 64)
			in.Plan = &p
		}},
		{name: "a plan of which one byte was changed", edit: func(r *mkRun, in *ceremony.MakeIn) {
			p := *r.plan
			p.JSON = bytes.Replace(p.JSON, []byte(`"ceremony_time":"2026-11-20T10:00:00Z"`), []byte(`"ceremony_time":"2026-11-20T10:00:01Z"`), 1)
			in.Plan = &p
		}},
		{name: "a plan that is whole and has no births", edit: func(r *mkRun, in *ceremony.MakeIn) {
			p := *r.plan
			p.Births = nil
			p.JSON = bytes.Replace(p.JSON, []byte(`"births":[`), []byte(`"births":[],"x":[`), 1)
			in.Plan = &p
		}},
		{name: "no settings", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Settings = nil }},
		{name: "settings that no reader made", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Settings = &wanted.Settings{Name: "Example"} }},
		{name: "the settings of a personal bundle", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Settings = personal }},
		{name: "no root file", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Root = nil }},
		{name: "a root file of another name", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Root = otherName }},
		{name: "a root that is not a test root", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Root = real }},
		{name: "no clock", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Env.Now = nil }},
		{name: "no console", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Env.Out = nil }},
		{name: "a console that no constructor made", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Env.Out = &ceremony.Console{} }},
		{name: "no trace", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Trace = nil }},
		{name: "a typed nil trace", edit: func(_ *mkRun, in *ceremony.MakeIn) { var tr *mkTrace; in.Trace = tr }},
		{name: "a trace with no birth journal", edit: func(r *mkRun, in *ceremony.MakeIn) { in.Trace = mkHalfTrace{sigs: r.trace.sigs} }},
		{name: "a trace with no signature journal", edit: func(r *mkRun, in *ceremony.MakeIn) { in.Trace = mkHalfTrace{births: r.trace.births} }},
		{name: "a trace that panics", edit: func(_ *mkRun, in *ceremony.MakeIn) { in.Trace = mkHalfTrace{panics: true} }},
		{name: "a store that gives another place", edit: func(r *mkRun, _ *ceremony.MakeIn) { r.store.placeFor = map[string]string{"A": "other.pem"} }},
		{name: "a store that is another kind", edit: func(r *mkRun, _ *ceremony.MakeIn) { r.store.kindOverride = "piv" }},
		{name: "a store that cannot be copied where the plan says it can", edit: func(r *mkRun, _ *ceremony.MakeIn) { no := false; r.store.copyOverride = &no }},
		{name: "a store whose place panics", edit: func(r *mkRun, _ *ceremony.MakeIn) { r.store.panicOn = "place" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newMkRun(t)
			in := r.in()
			if tc.edit != nil {
				tc.edit(r, &in)
				// The store may have been changed by the edit.
				if in.Store == ceremony.RootStore(r.store) {
					in.Store = r.store
				}
			}
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			m, err := ceremony.MakeRoots(ctx, in)
			if m != nil || err == nil {
				t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
			}
			if r.log.count("birth") != 0 || r.log.count("sign") != 0 || r.log.count("-line") != 0 || r.log.count("console:") != 0 {
				t.Errorf("the run did:\n%s", strings.Join(r.log.all(), "\n"))
			}
			if got := r.keyFiles(); len(got) != 0 {
				t.Errorf("the key directory holds %v", got)
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the text %+q is not printable ASCII", err.Error())
			}
		})
	}
}

// mkHalfTrace is a trace that lacks a journal, or panics.
type mkHalfTrace struct {
	births, sigs *mkJournal
	panics       bool
}

func (h mkHalfTrace) Births() ceremony.Journal {
	if h.panics {
		panic("the trace panics")
	}
	if h.births == nil {
		return nil
	}
	return h.births
}

func (h mkHalfTrace) Signatures() ceremony.Journal {
	if h.sigs == nil {
		return nil
	}
	return h.sigs
}

func TestAPlanThatWasReadFromItsBytesAndAPlanThatWasMadeGiveTheSameRun(t *testing.T) {
	r := newMkRun(t)
	read, err := ceremony.ReadPlanOut(r.plan.JSON)
	if err != nil {
		t.Fatal(err)
	}
	r.plan = read
	m := r.mustMake()
	if len(m.Roots) != 2 {
		t.Fatalf("%d roots", len(m.Roots))
	}
}

func TestTheResultsOfTwoRunsDifferInTheirKeysAndNothingIsSharedByTwoMades(t *testing.T) {
	_, a := mkGood(t)
	_, b := mkGood(t)
	if a.Roots[0].Pin == b.Roots[0].Pin || a.Roots[1].Pin == b.Roots[1].Pin {
		t.Error("two ceremonies made the same key")
	}
	// The plan is the same, so the serials in the certificates are the same, and the certificates differ.
	if bytes.Equal(a.Roots[0].Certificate, b.Roots[0].Certificate) {
		t.Error("two certificates of two keys are one")
	}
	// A change of a returned list does not change the next call.
	first := a.Artifacts()
	first[0] = "changed"
	if a.Artifacts()[0] == "changed" {
		t.Error("Artifacts shares its list")
	}
	f := a.Set.Files()
	f[0].Data[0] ^= 0xff
	if bytes.Equal(a.Set.Files()[0].Data, f[0].Data) {
		t.Error("Files shares its bytes")
	}
}

func TestAMadeThatIsNilOrZeroHasNoDirAndNoArtifacts(t *testing.T) {
	var m *ceremony.Made
	if m.TrustSetDir() != "" || m.Artifacts() != nil {
		t.Error("a nil Made has a folder or artifacts")
	}
	z := &ceremony.Made{}
	if z.TrustSetDir() != "" {
		t.Errorf("a zero Made has the folder %q", z.TrustSetDir())
	}
	if got := z.Artifacts(); len(got) != 0 {
		t.Errorf("a zero Made has the artifacts %v", got)
	}
}

func TestAContextThatIsCancelledWhileTheRemovalAuthorisationIsSignedStoresNothing(t *testing.T) {
	r := newMkRun(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.store.wrapKey = mkWrap(func(k *mkKey) {
		n := 0
		k.signFn = func(rd io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error) {
			n++
			sig, err := k.Key.Sign(rd, digest, o)
			if k.label == "A" && n == 2 {
				cancel()
			}
			return sig, err
		}
	})
	m, err := ceremony.MakeRoots(ctx, r.in())
	if m != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
	}
	for _, n := range r.keyFiles() {
		if strings.HasSuffix(n, ".removal.jws") {
			t.Errorf("the file %s was written after the context was cancelled", n)
		}
	}
	if r.log.count("save-removal") != 0 || r.log.count("signatures-line 2") != 0 {
		t.Errorf("the run went on:\n%s", strings.Join(r.log.all(), "\n"))
	}
}

func TestARemovalAuthorisationThatCannotBeReadBackIsAFaultOfTheStepThatReadsIt(t *testing.T) {
	r := newMkRun(t)
	r.store.readErr = errors.New("test: the file cannot be read")
	m, err := r.make()
	if m != nil || err == nil {
		t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
	}
	me, ok := mkAs[*ceremony.MakeError](err)
	if !ok || me.Step != "checks" || !strings.Contains(me.Reason, "cannot be read back") {
		t.Fatalf("the error is %v, want a fault of the step checks that says the file cannot be read back", err)
	}
	// And a refusal with a reason code is the refusal itself.
	be := &ceremony.BackendError{Reasons: []string{"key-file"}, Msg: "test: the key file is not of the shape of the page"}
	r = newMkRun(t)
	r.store.readErr = be
	if _, err := r.make(); !mkIsItself(err, be) {
		t.Fatalf("the error is %T %v, want the *BackendError itself", err, err)
	}
}

// mkIsItself reports whether err is the very error value want, not an error that wraps it: a refusal
// of the key store is returned as it is, so that the command maps its exit code.
func mkIsItself(err error, want *ceremony.BackendError) bool {
	return err == error(want) //nolint:errorlint // the test asks for the value itself, not for a wrapped one
}

func TestAKeyDirectoryThatIsGoneOrChangedAfterTheStoreWasOpenedIsRefusedBeforeAnyKeyIsMade(t *testing.T) {
	// The store was opened on a good folder; the early refusal of the command was long ago. MakeRoots
	// asks the store to refuse again, and the folder is judged as it is now.
	t.Run("the folder was removed", func(t *testing.T) {
		r := newMkRun(t)
		if err := os.Remove(r.keyDir); err != nil {
			t.Fatal(err)
		}
		m, err := r.make()
		if m != nil || mkBackendReason(err) != "key-dir" {
			t.Fatalf("MakeRoots: a result %v, the error %v; want key-dir", m != nil, err)
		}
		if r.log.count("birth") != 0 {
			t.Error("a key was asked for")
		}
	})
	t.Run("a key file came into the folder", func(t *testing.T) {
		r := newMkRun(t)
		if err := os.WriteFile(filepath.Join(r.keyDir, "B.x509.key.pem"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		m, err := r.make()
		if m != nil || mkBackendReason(err) != "key-exists" {
			t.Fatalf("MakeRoots: a result %v, the error %v; want key-exists", m != nil, err)
		}
		if r.log.count("birth") != 0 || r.log.count("-line") != 0 {
			t.Errorf("the run did:\n%s", strings.Join(r.log.all(), "\n"))
		}
	})
}

// mkBrokenWriter is a stream that cannot be written, as a terminal that was closed.
type mkBrokenWriter struct{}

func (mkBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("test: the stream is closed") }

func TestNoKeySignsWhenTheFingerprintsCouldNotBeShown(t *testing.T) {
	// record 0005, rule 11: each fingerprint is shown before any root key signs for it, so that a new
	// key is seen first. A fingerprint that was not printed was not seen.
	r := newMkRun(t)
	r.env.Out = ceremony.NewConsole(mkBrokenWriter{}, mkBrokenWriter{})
	m, err := r.make()
	if m != nil || err == nil {
		t.Fatalf("MakeRoots made a result (%v) and returned %v although the fingerprints were not shown", m != nil, err)
	}
	if n := r.log.count("sign "); n != 0 {
		t.Errorf("%d signatures were made after a fingerprint that was not shown", n)
	}
}

func TestSettingsAndRootThatAreNotTheFilesOfThePlanAreRefusedBeforeAnyKeyIsMade(t *testing.T) {
	// The plan lists the digests of the wanted files that the person confirmed. A name in a
	// certificate comes from ritueel.yaml, so a ritueel.yaml that is not the one of the plan makes
	// certificates that the person did not confirm, and the check of the certificate cannot see it
	// because it reads the name from the same place.
	changed, err := wanted.ParseSettings("ritueel.yaml", []byte(strings.Replace(pfSettings, "name: Example", "name: Other", 1)))
	if err != nil {
		t.Fatal(err)
	}
	commented, err := wanted.ParseSettings("ritueel.yaml", []byte(pfSettings+"# a comment\n"))
	if err != nil {
		t.Fatal(err)
	}
	rootCommented, err := wanted.ParseRoot("x509", []byte(pfX509Test+"# a comment\n"))
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(in *ceremony.MakeIn){
		"a ritueel.yaml with another name":       func(in *ceremony.MakeIn) { in.Settings = changed },
		"a ritueel.yaml with a comment more":     func(in *ceremony.MakeIn) { in.Settings = commented },
		"a wanted root file with a comment more": func(in *ceremony.MakeIn) { in.Root = rootCommented },
	} {
		t.Run(name, func(t *testing.T) {
			r := newMkRun(t)
			in := r.in()
			edit(&in)
			m, err := ceremony.MakeRoots(context.Background(), in)
			if m != nil || err == nil {
				t.Fatalf("MakeRoots made a result (%v) from a file that is not the file of the plan: %v", m != nil, err)
			}
			if r.log.count("birth") != 0 || len(r.keyFiles()) != 0 {
				t.Errorf("a key was made:\n%s", strings.Join(r.log.all(), "\n"))
			}
		})
	}
}

func TestAnEntryWithTheNameOfTheKeyFolderThatIsNotAnEmptyFitFolderIsRefusedBeforeAnyKeyIsMadeAndReplacesNothing(t *testing.T) {
	// The check of the key directory refuses with key-exists, before a key is made, the name test-only-keys when
	// it is a link, a file, a folder that holds anything, or a folder of another mode than 0700. Only an empty
	// folder of the mode 0700, owned by this user, is accepted, and it is used as it is. Nothing that stands
	// there is replaced or removed.
	for _, kind := range []string{"folder with a file", "folder of the mode 0755", "file", "link"} {
		t.Run(kind, func(t *testing.T) {
			r := newMkRun(t)
			path := filepath.Join(r.keyDir, "test-only-keys")
			switch kind {
			case "folder with a file":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "x509-root-a.p8"), []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "folder of the mode 0755":
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o755); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Symlink(filepath.Join(r.root, "elsewhere"), path); err != nil {
					t.Fatal(err)
				}
			}
			before := tree(t, r.keyDir)
			modeBefore, _ := os.Lstat(path)
			m, err := r.make()
			if m != nil || mkBackendReason(err) != "key-exists" {
				t.Fatalf("MakeRoots: a result %v, the error %v; want key-exists", m != nil, err)
			}
			sameTree(t, "the key directory", before, tree(t, r.keyDir))
			if modeAfter, err := os.Lstat(path); err != nil || modeAfter.Mode() != modeBefore.Mode() {
				t.Errorf("the entry with the name of the key folder changed its kind or mode: %v to %v (%v)", modeBefore.Mode(), modeAfter, err)
			}
			if _, err := os.Stat(filepath.Join(r.root, "elsewhere")); err == nil {
				t.Error("a file was written through the link")
			}
			if r.log.count("birth") != 0 || r.log.count("signatures-line") != 0 || r.log.count("console:") != 0 {
				t.Errorf("the run went on:\n%s", strings.Join(r.log.all(), "\n"))
			}
		})
	}
}
