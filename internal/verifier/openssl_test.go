package verifier_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/testrepo"
	"ritueel.id/ritueel/internal/verifier"
)

// The certificates are those of testdata/x509-builders, which OpenSSL's ASN.1 generator made: a root
// and an intermediate under it. The fixture is read at run time. 1794830400 is 2026-11-16 12:00:00 UTC,
// a day after both start.
var at = time.Unix(1794830400, 0).UTC()

func fixture(t testing.TB, name string) (pemBytes, der []byte) {
	t.Helper()
	pemBytes = testrepo.Read(t, "testdata", "x509-builders", name)
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s is not one PEM block", name)
	}
	return pemBytes, block.Bytes
}

func requireOpenSSL(t *testing.T) {
	t.Helper()
	verifier.Require(t, "openssl")
}

func TestOpenSSLVerifyAccepts(t *testing.T) {
	requireOpenSSL(t)
	rootPEM, rootDER := fixture(t, "root-test.cert.pem")
	interPEM, interDER := fixture(t, "inter-nc.cert.pem")
	cases := []struct {
		name       string
		root, cert []byte
	}{
		{"a root as its own root, in PEM", rootPEM, rootPEM},
		{"a root as its own root, in DER", rootDER, rootDER},
		{"an intermediate under its root, in PEM", rootPEM, interPEM},
		{"an intermediate under its root, in DER", rootDER, interDER},
		{"a root in PEM and a certificate in DER", rootPEM, interDER},
		{"a root in DER and a certificate in PEM", rootDER, interPEM},
		{"a PEM with text before the block", rootPEM, append([]byte("a note before the block\n"), interPEM...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := verifier.OpenSSLVerify(t, c.root, c.cert, at); err != nil {
				t.Errorf("OpenSSLVerify = %v, want nil", err)
			}
		})
	}
	t.Run("the time is an instant, whatever the zone", func(t *testing.T) {
		zoned := at.In(time.FixedZone("UTC+9", 9*3600))
		if err := verifier.OpenSSLVerify(t, rootDER, interDER, zoned); err != nil {
			t.Errorf("OpenSSLVerify = %v", err)
		}
	})
}

func TestOpenSSLVerifyRefuses(t *testing.T) {
	requireOpenSSL(t)
	rootPEM, rootDER := fixture(t, "root-test.cert.pem")
	_, interDER := fixture(t, "inter-nc.cert.pem")
	// An unrelated root, made with the standard library: another key and another name.
	otherKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Unrelated Root"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour * 24 * 365), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{Subject: pkix.Name{CommonName: "Example Unrelated Root"}}, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	// The intermediate with a byte of its signature changed.
	badSig := append([]byte(nil), interDER...)
	badSig[len(badSig)-3] ^= 0x01
	// The intermediate with a byte of its subject changed (a letter stays a letter).
	badName := append([]byte(nil), interDER...)
	badName[bytes.Index(badName, []byte("acme example"))] ^= 0x02
	cases := []struct {
		name       string
		root, cert []byte
		at         time.Time
		reason     string
	}{
		{"an unrelated root", otherDER, interDER, at, "unable to get local issuer certificate"},
		{"a root that is not the one that signed", otherDER, rootDER, at, "self-signed certificate"},
		{"a time after the end of the intermediate", rootPEM, interDER, time.Date(2027, 12, 16, 12, 0, 0, 0, time.UTC), "certificate has expired"},
		{"a time before the start", rootPEM, interDER, time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), "certificate is not yet valid"},
		{"a time after the end of the root", rootPEM, rootDER, time.Date(2029, 11, 16, 12, 0, 0, 0, time.UTC), "certificate has expired"},
		{"a changed signature", rootPEM, badSig, at, "certificate signature failure"},
		{"a changed subject", rootPEM, badName, at, "certificate signature failure"},
		{"the intermediate with no root over it", interDER, interDER, at, "unable to get local issuer certificate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifier.OpenSSLVerify(t, c.root, c.cert, c.at)
			if err == nil {
				t.Fatalf("OpenSSLVerify accepts it, want a refusal: %s", c.reason)
			}
			if !strings.Contains(err.Error(), c.reason) {
				t.Errorf("refused, but not for %q: %v", c.reason, err)
			}
			if !printable(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII: %q", err.Error())
			}
		})
	}
	t.Run("what is not a certificate", func(t *testing.T) {
		for name, junk := range map[string][]byte{
			"text":          []byte("not a certificate"),
			"nothing":       nil,
			"empty":         {},
			"a cut DER":     interDER[:40],
			"a PEM of junk": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		} {
			err := verifier.OpenSSLVerify(t, rootPEM, junk, at)
			if err == nil {
				t.Errorf("%s: OpenSSLVerify accepts it", name)
				continue
			}
			if !printable(err.Error()) {
				t.Errorf("%s: the text of the error is not printable ASCII: %q", name, err.Error())
			}
			err = verifier.OpenSSLVerify(t, junk, interDER, at)
			if err == nil {
				t.Errorf("%s as a root: OpenSSLVerify accepts it", name)
			}
		}
	})
}

// OpenSSL prints the path of the file it was given. A path can hold letters that look like others, and
// the text of an error must still be printable ASCII.
func TestOpenSSLVerifyEscapesTheOutput(t *testing.T) {
	requireOpenSSL(t)
	_, rootDER := fixture(t, "root-test.cert.pem")
	_, interDER := fixture(t, "inter-nc.cert.pem")
	for _, name := range []string{
		"caf" + string(rune(0xe9)),
		"Ex" + string(rune(0x0430)) + "mple",
		"a" + string(rune(0x202e)) + "b",
		"x" + string(rune(0x4e2d)) + string(rune(0x6587)),
	} {
		t.Run(name, func(t *testing.T) {
			err := verifier.OpenSSLVerify(t, rootDER, interDER, at.Add(time.Hour*24*400)) // after the end
			if err == nil {
				t.Fatal("OpenSSLVerify accepts it")
			}
			if !printable(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII: %q", err.Error())
			}
		})
	}
}

// The command line of the tool: only the root given is trusted (no system folder, no system store),
// at the time given, and the certificate is the last argument. A fake openssl records its arguments.
func TestOpenSSLVerifyCommandLine(t *testing.T) {
	_, rootDER := fixture(t, "root-test.cert.pem")
	_, interDER := fixture(t, "inter-nc.cert.pem")
	record := filepath.Join(t.TempDir(), "args")
	dir := writeTool(t, "openssl", fmt.Sprintf(`printf '%%s\n' "$@" > %s; echo "$(eval echo \$$#): OK"`, record))
	t.Setenv("PATH", dir)
	if err := verifier.OpenSSLVerify(t, rootDER, interDER, at); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"verify", "-attime", "1794830400", "-check_ss_sig", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile"}
	if len(args) != len(want)+2 {
		t.Fatalf("the arguments are %q", args)
	}
	for i, w := range want {
		if args[i] != w {
			t.Errorf("argument %d = %q, want %q (all: %q)", i, args[i], w, args)
		}
	}
	rootFile, certFile := args[len(want)], args[len(want)+1]
	if filepath.Base(rootFile) != "root.pem" || filepath.Base(certFile) != "cert.pem" || filepath.Dir(rootFile) != filepath.Dir(certFile) {
		t.Errorf("the files are %q and %q", rootFile, certFile)
	}
}

// What counts as an acceptance: the tool exits with 0 and prints a line that ends ": OK". Anything
// else is not one, whatever the exit code says.
func TestOpenSSLVerifyAcceptanceRule(t *testing.T) {
	_, rootDER := fixture(t, "root-test.cert.pem")
	cases := []struct {
		name   string
		script string
		accept bool
	}{
		{"exit 0 and OK", `echo "cert.pem: OK"`, true},
		{"exit 0 and OK with a newline after", `printf 'cert.pem: OK\n\n'`, true},
		{"exit 0 and OK after other lines", `echo "warning"; echo "cert.pem: OK"`, true},
		{"exit 0 and nothing", `exit 0`, false},
		{"exit 0 and something else", `echo "fine"`, false},
		{"exit 0 and OK in the middle", `echo "cert.pem: OK"; echo "but not really"`, false},
		{"exit 0 and a different word at the end", `echo "cert.pem: NOT OK"`, false},
		{"exit 1 and OK", `echo "cert.pem: OK"; exit 1`, false},
		{"exit 2 and an error", `echo "error 20 at 0 depth lookup"; exit 2`, false},
		{"a signal", `echo "cert.pem: OK"; kill -9 $$`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("PATH", writeTool(t, "openssl", c.script))
			err := verifier.OpenSSLVerify(t, rootDER, rootDER, at)
			if c.accept != (err == nil) {
				t.Errorf("OpenSSLVerify = %v, accept = %v", err, c.accept)
			}
			if err != nil && !printable(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII: %q", err.Error())
			}
		})
	}
	t.Run("the output of the tool is escaped", func(t *testing.T) {
		t.Setenv("PATH", writeTool(t, "openssl", `printf 'bad \033[31m\303\251 \377 line\r\n'; exit 3`))
		err := verifier.OpenSSLVerify(t, rootDER, rootDER, at)
		if err == nil || !printable(err.Error()) {
			t.Fatalf("OpenSSLVerify = %v, want a printable ASCII error", err)
		}
		if !strings.Contains(err.Error(), "bad ") || !strings.Contains(err.Error(), "line") {
			t.Errorf("the text of the tool is not in the error: %q", err.Error())
		}
	})
}

func TestOpenSSLVerifyNeedsTheTool(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	unsetenv(t, verifier.RequireToolsEnv)
	_, rootDER := fixture(t, "root-test.cert.pem")
	if fake := runFake(t, func(tb testing.TB) { _ = verifier.OpenSSLVerify(tb, rootDER, rootDER, at) }); !fake.skipped || fake.failed {
		t.Errorf("OpenSSLVerify without the tool: skipped = %v, failed = %v, want a skip", fake.skipped, fake.failed)
	}
	if fake := runFake(t, func(tb testing.TB) { _ = verifier.OpenSSLText(tb, rootDER) }); !fake.skipped || fake.failed {
		t.Errorf("OpenSSLText without the tool: skipped = %v, failed = %v, want a skip", fake.skipped, fake.failed)
	}
	t.Setenv(verifier.RequireToolsEnv, "1")
	if fake := runFake(t, func(tb testing.TB) { _ = verifier.OpenSSLVerify(tb, rootDER, rootDER, at) }); !fake.failed || fake.skipped {
		t.Errorf("OpenSSLVerify without the tool and the variable 1: skipped = %v, failed = %v, want a failure", fake.skipped, fake.failed)
	}
	if fake := runFake(t, func(tb testing.TB) { _ = verifier.OpenSSLText(tb, rootDER) }); !fake.failed || fake.skipped {
		t.Errorf("OpenSSLText without the tool and the variable 1: skipped = %v, failed = %v, want a failure", fake.skipped, fake.failed)
	}
}

func TestOpenSSLText(t *testing.T) {
	requireOpenSSL(t)
	rootPEM, rootDER := fixture(t, "root-test.cert.pem")
	interPEM, interDER := fixture(t, "inter-nc.cert.pem")
	for name, in := range map[string][]byte{"PEM": rootPEM, "DER": rootDER} {
		t.Run("a root in "+name, func(t *testing.T) {
			text := verifier.OpenSSLText(t, in)
			for _, row := range []string{
				"Version: 3 (0x2)",
				"Signature Algorithm: ecdsa-with-SHA384",
				"Issuer: CN=Example Test Root K (TEST ONLY)",
				"Not Before: Nov 15 12:00:00 2026 GMT",
				"X509v3 Basic Constraints: critical",
				"Certificate Sign, CRL Sign",
			} {
				if !strings.Contains(text, row) {
					t.Errorf("the text has no %q:\n%s", row, text)
				}
			}
		})
	}
	for name, in := range map[string][]byte{"PEM": interPEM, "DER": interDER} {
		t.Run("an intermediate in "+name, func(t *testing.T) {
			text := verifier.OpenSSLText(t, in)
			for _, row := range []string{"CA:TRUE, pathlen:0", "Subject: O=acme, CN=acme example intermediate CA", "Permitted:", "URI:example.org", "X509v3 Authority Key Identifier"} {
				if !strings.Contains(text, row) {
					t.Errorf("the text has no %q:\n%s", row, text)
				}
			}
		})
	}
	t.Run("what is not a certificate fails the test, in printable ASCII", func(t *testing.T) {
		for name, junk := range map[string][]byte{"text": []byte("junk"), "nothing": nil, "a cut DER": interDER[:30]} {
			fake := runFake(t, func(tb testing.TB) { _ = verifier.OpenSSLText(tb, junk) })
			if !fake.failed || fake.skipped {
				t.Errorf("%s: failed = %v, skipped = %v, want a failure", name, fake.failed, fake.skipped)
			}
			if !printable(fake.message) {
				t.Errorf("%s: the message is not printable ASCII: %q", name, fake.message)
			}
		}
	})
	t.Run("the output of the tool in a failure is escaped", func(t *testing.T) {
		t.Setenv("PATH", writeTool(t, "openssl", `printf 'bad \033[31m\303\251 \377 line\n'; exit 3`))
		fake := runFake(t, func(tb testing.TB) { _ = verifier.OpenSSLText(tb, rootDER) })
		if !fake.failed || !printable(fake.message) || !strings.Contains(fake.message, "line") {
			t.Errorf("failed = %v, message = %q", fake.failed, fake.message)
		}
	})
	t.Run("the command line", func(t *testing.T) {
		record := filepath.Join(t.TempDir(), "args")
		t.Setenv("PATH", writeTool(t, "openssl", fmt.Sprintf(`printf '%%s\n' "$@" > %s; echo text`, record)))
		if got := verifier.OpenSSLText(t, rootDER); strings.TrimSpace(got) != "text" {
			t.Errorf("OpenSSLText = %q", got)
		}
		data, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(args) != 5 || args[0] != "x509" || args[1] != "-in" || filepath.Base(args[2]) != "cert.pem" || args[3] != "-noout" || args[4] != "-text" {
			t.Errorf("the arguments are %q", args)
		}
	})
}

// plainVerify is "openssl verify" as OpenSSLVerify ran it before it was strict: the same trust, the
// same time, and neither -check_ss_sig nor -x509_strict.
func plainVerify(t *testing.T, root, cert []byte) error {
	t.Helper()
	bin := verifier.Require(t, "openssl")
	dir := t.TempDir()
	write := func(name string, der []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	out, err := exec.Command(bin, "verify", "-attime", fmt.Sprint(at.Unix()), "-no-CApath", "-no-CAstore",
		"-CAfile", write("root.pem", root), write("cert.pem", cert)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// A certificate that is sound but breaks a rule of RFC 5280 that only the strict mode of OpenSSL
// applies: a leaf with no authority key identifier. Plain OpenSSL accepts it; OpenSSLVerify must not,
// so a dropped -x509_strict is noticed.
func TestOpenSSLVerifyIsStrict(t *testing.T) {
	requireOpenSSL(t)
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Strict Root"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: bytes.Repeat([]byte{7}, 20),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(parent *x509.Certificate) []byte {
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.example.org"}, DNSNames: []string{"leaf.example.org"},
			NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		}, parent, &leafKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	withAKI := leaf(rootTmpl)
	// Go takes the authority key identifier from the key identifier of the parent: with none, no AKI.
	noKeyID := *rootTmpl
	noKeyID.SubjectKeyId = nil
	withoutAKI := leaf(&noKeyID)
	if c, _ := x509.ParseCertificate(withoutAKI); len(c.AuthorityKeyId) != 0 {
		t.Fatal("the test certificate has an authority key identifier")
	}
	if err := verifier.OpenSSLVerify(t, rootDER, withAKI, at); err != nil {
		t.Errorf("the sound leaf is refused: %v", err)
	}
	if err := plainVerify(t, rootDER, withoutAKI); err != nil {
		t.Fatalf("plain OpenSSL refuses the leaf with no authority key identifier, so it shows nothing: %v", err)
	}
	err = verifier.OpenSSLVerify(t, rootDER, withoutAKI, at)
	if err == nil {
		t.Fatal("OpenSSLVerify accepts a leaf with no authority key identifier, which only the strict mode refuses")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "authority key identifier") {
		t.Errorf("refused, but not for the authority key identifier: %v", err)
	}
}
