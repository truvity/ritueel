package answer_test

import (
	"testing"

	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/testrepo"
	"ritueel.id/ritueel/internal/verifier"
)

// The requester's verdict and OpenSSL agree on the certificates of the vectors that the checks of an issued
// certificate can be compared on: the ones that are installed verify to their root, and the one that has ended
// and the one that is signed by a root that is not on the list do not. Skipped when OpenSSL is not there
// (RITUEEL_REQUIRE_TOOLS=1 makes the skip a failure); OpenSSL is run on public vector files only.
func TestTheVerdictAgreesWithOpenSSLOnTheVectorCertificates(t *testing.T) {
	verifier.Require(t, "openssl")
	m := readVectorManifest(t)
	chk := mustChecker(t, vectorConfig(t, m))
	root := func(name string) []byte { return testrepo.Read(t, vectorsDir, "pki", name) }
	for _, c := range []struct {
		id     string
		root   string
		accept bool
	}{
		{"x509-piv-valid", "test-root-a.pem", true},
		{"x509-kms-valid", "test-root-a.pem", true},
		{"x509-software-valid", "test-root-a.pem", true},
		{"x509-eku-server-and-client", "test-root-a.pem", true},
		{"x509-eku-client-only", "test-root-a.pem", true},
		{"x509-response-other-root", "test-root-b.pem", true},
		{"x509-response-expired", "test-root-a.pem", false},
		{"x509-response-untrusted-issuer", "test-root-a.pem", false},
	} {
		t.Run(c.id, func(t *testing.T) {
			rc := vectorCase(t, c.id)
			ans := vectorAnswer(t, rc)
			v, err := chk.Check(vectorAsked(t, rc), ans)
			if err != nil {
				t.Fatal(err)
			}
			ossl := verifier.OpenSSLVerify(t, root(c.root), ans.Files[answer.FileCert], vectorNow)
			if (ossl == nil) != c.accept {
				t.Fatalf("OpenSSL: %v, want accepted %v", ossl, c.accept)
			}
			if c.accept && !v.Accepted() {
				t.Errorf("OpenSSL accepts and the requester refuses: %q %s", v.Code, v.Detail)
			}
			if !c.accept && v.Accepted() {
				t.Error("OpenSSL refuses and the requester accepts")
			}
		})
	}
	t.Run("the root of the other pin does not verify the certificate of root A", func(t *testing.T) {
		rc := vectorCase(t, "x509-piv-valid")
		if err := verifier.OpenSSLVerify(t, root("test-root-b.pem"), vectorAnswer(t, rc).Files[answer.FileCert], vectorNow); err == nil {
			t.Error("OpenSSL accepts the certificate of root A under root B")
		}
	})
}
