package verifier

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
)

// toolTimeout is how long one run of a tool may take.
const toolTimeout = 30 * time.Second

// OpenSSLVerify runs `openssl verify -attime AT -check_ss_sig -x509_strict -CAfile ROOT CERT` and
// returns nil when OpenSSL accepts the certificate at that time, and an error with its output when
// it does not. root and cert are certificates, each in PEM or in DER. OpenSSL is given no other
// source of trust: the system store and the system folder of certificates are switched off. The
// test is skipped, or fails, when openssl is missing (see [Require]).
//
// What an acceptance proves, by a tool that did not build the certificate: the chain from cert to
// root is built by name and key identifier, every signature on it verifies, the dates hold at the
// given time, and the certificates meet the profile checks of RFC 5280 that OpenSSL applies in
// strict mode (a CA has basic constraints and a subject key identifier, an issued certificate has
// an authority key identifier, the extensions are in a form that the RFC allows, a key has named
// curve parameters). -check_ss_sig makes OpenSSL verify the signature of a self-signed trusted
// certificate, which it skips otherwise: without it, OpenSSLVerify(root, root, at) would accept a
// root with a damaged signature. It does not prove that the extensions are the ones of a ritueel
// profile; a test reads those from the certificate or from [OpenSSLText].
func OpenSSLVerify(t testing.TB, root, cert []byte, at time.Time) error {
	t.Helper()
	bin := Require(t, "openssl")
	dir := t.TempDir()
	rootFile := writePEM(t, dir, "root.pem", root)
	certFile := writePEM(t, dir, "cert.pem", cert)
	out, err := run(bin, "verify", "-attime", strconv.FormatInt(at.Unix(), 10),
		"-check_ss_sig", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile", rootFile, certFile)
	if err != nil {
		return fmt.Errorf("verifier: openssl verify: %w: %s", err, jsonset.Escape(out))
	}
	// A successful run prints "<file>: OK". Anything else is not an acceptance, whatever the exit
	// code says.
	if !strings.HasSuffix(strings.TrimSpace(out), ": OK") {
		return fmt.Errorf("verifier: openssl verify did not print OK: %s", jsonset.Escape(out))
	}
	return nil
}

// OpenSSLText returns the output of `openssl x509 -noout -text` for the certificate (PEM or DER).
// It fails the test when OpenSSL cannot read the certificate.
func OpenSSLText(t testing.TB, cert []byte) string {
	t.Helper()
	bin := Require(t, "openssl")
	file := writePEM(t, t.TempDir(), "cert.pem", cert)
	out, err := run(bin, "x509", "-in", file, "-noout", "-text")
	if err != nil {
		t.Fatalf("verifier: openssl x509: %v: %s", err, jsonset.Escape(out))
	}
	return out
}

// writePEM writes a certificate, as PEM, to a file of dir and returns its path. A PEM input is
// written as it is; anything else is taken for DER.
func writePEM(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	if block, _ := pem.Decode(data); block == nil {
		data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return path
}

// run runs a tool with a time limit and returns its output, standard output and standard error
// together. An exit with a code other than 0 is an error.
func run(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), errors.Join(err, ctx.Err())
	}
	return string(out), err
}
