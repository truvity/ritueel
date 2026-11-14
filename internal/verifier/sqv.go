package verifier

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
)

// SQVVerify runs `sqv --time AT --keyring KEYRING --signature-file SIG DATA` and returns nil when
// sqv accepts the signature at that time as a signature by a key of the certificate that is meant,
// and an error with its output when it does not. keyring is a file of OpenPGP packets
// (certificates one after the other, binary), sig is a detached signature, data is the signed data,
// and fingerprint is the version 4 fingerprint of the primary key of the certificate that is meant:
// 40 lower-case hexadecimal digits. The test is skipped, or fails, when sqv is missing (see
// [Require]).
//
// sqv prints, with --verbose, the fingerprint of the certificate that made each valid signature on
// a line of its own. An acceptance needs one such line and that it is the fingerprint that is meant,
// so a signature by a key of another certificate of the same keyring is refused.
//
// What an acceptance proves, by a tool that did not build the packets: Sequoia reads the
// certificate as a relying party does, the signing key is bound to a certificate of the keyring
// by a valid binding (and, for a signing subkey, a valid back-signature), neither the key nor the
// certificate is revoked or expired at AT, and the signature verifies. A soft revocation (superseded
// or retired) leaves a signature made before the revocation valid, and a hard one (compromised)
// does not: this is the verdict a test asserts on for a revoked key, since the exit status of
// gpgv is not one (record 0009, rule 20). sqv runs with no agent, no socket and no home folder of
// the user, and with the built-in cryptographic policy: it is given an empty policy file, so that
// the policy of the machine does not decide a test.
func SQVVerify(t testing.TB, keyring, sig, data []byte, fingerprint string, at time.Time) error {
	t.Helper()
	if err := checkFingerprint(fingerprint); err != nil {
		return err
	}
	bin := Require(t, "sqv")
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("verifier: %v", err)
	}
	files := map[string][]byte{"keyring.pgp": keyring, "message.sig": sig, "message": data, "policy.toml": nil}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatalf("verifier: %v", err)
		}
	}
	env := []string{"HOME=" + home, "LC_ALL=C", "TZ=UTC", "SEQUOIA_CRYPTO_POLICY=" + filepath.Join(dir, "policy.toml")}
	stdout, stderr, err := runSplit(env, bin, "--time", at.UTC().Format("2006-01-02T15:04:05Z"),
		"--verbose", "--keyring", filepath.Join(dir, "keyring.pgp"), "--signature-file", filepath.Join(dir, "message.sig"),
		filepath.Join(dir, "message"))
	out := stdout + stderr
	if err != nil {
		return fmt.Errorf("verifier: sqv: %w: %s", err, jsonset.Escape(out))
	}
	// A successful verbose run prints "1 of 1 signatures are valid". Anything else is not an
	// acceptance, whatever the exit code says.
	if !strings.Contains(out, "1 of 1 signatures are valid") {
		return fmt.Errorf("verifier: sqv did not print that its one signature is valid: %s", jsonset.Escape(out))
	}
	// The certificate that made the signature stands on a line of its own: 40 upper-case digits.
	var certs []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); isUpperFingerprint(line) {
			certs = append(certs, line)
		}
	}
	if len(certs) != 1 || certs[0] != strings.ToUpper(fingerprint) {
		return fmt.Errorf("verifier: sqv did not name %s as the one certificate that made the signature: %s", fingerprint, jsonset.Escape(out))
	}
	return nil
}

// isUpperFingerprint tells whether s is 40 upper-case hexadecimal digits.
func isUpperFingerprint(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
