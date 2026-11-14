package verifier_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/verifier"
)

// OpenSSL does not check the signature of a self-signed certificate that it is told to trust, unless
// it is run with -check_ss_sig. Without that flag, a root whose signature was changed after it was made
// is "OK" as its own root, and the helper would say nothing about the signature of a root. OpenSSLVerify
// passes -check_ss_sig, so OpenSSLVerify(root, root, at) fails with a signature failure for such a root.
func TestOpenSSLVerifyChecksTheSelfSignatureOfARoot(t *testing.T) {
	requireOpenSSL(t)
	_, rootDER := fixture(t, "root-test.cert.pem")
	if err := verifier.OpenSSLVerify(t, rootDER, rootDER, at); err != nil {
		t.Fatalf("the honest root is refused: %v", err)
	}
	forged := append([]byte(nil), rootDER...)
	forged[len(forged)-3] ^= 0x01 // a byte of the signature
	err := verifier.OpenSSLVerify(t, forged, forged, at)
	if err == nil {
		t.Fatal("OpenSSLVerify accepts a root whose signature does not verify")
	}
	if !strings.Contains(err.Error(), "certificate signature failure") {
		t.Errorf("refused, but not for its signature: %v", err)
	}
}
