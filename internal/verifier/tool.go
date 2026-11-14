// Package verifier holds the helpers of tests that check an artifact with a tool that did not
// build it: OpenSSL for a certificate (openssl.go), and gpgv (gpg.go) and sqv (sqv.go) for an
// OpenPGP signature and the certificate that makes it valid. A test that builds
// a certificate and checks it with the code that built it proves little; a tool that is
// written by someone else, and reads the bytes as a relying party does, proves the profile.
//
// The package is for _test.go files only. It never writes into the repository: a file it makes is
// in a folder of the test that the testing package removes. It runs a tool with a time limit, and
// a failure shows the output of the tool with every character outside printable ASCII escaped.
package verifier

import (
	"os"
	"os/exec"
	"testing"

	"ritueel.id/ritueel/internal/jsonset"
)

// RequireToolsEnv is the name of the environment variable that makes a missing tool an error.
// The recipe go-test sets it to 1, so that CI and the local gate fail where a test would skip.
const RequireToolsEnv = "RITUEEL_REQUIRE_TOOLS"

// Require returns the path of the tool, found on PATH. When the tool is missing, the test is
// skipped; when RITUEEL_REQUIRE_TOOLS is 1, the test fails instead, because a skip would be a
// check that did not run. A skip outside the devbox is not a pass.
func Require(t testing.TB, tool string) string {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		if os.Getenv(RequireToolsEnv) == "1" {
			t.Fatalf("verifier: the tool \"%s\" is not on PATH and %s=1", jsonset.Escape(tool), RequireToolsEnv)
		}
		t.Skipf("verifier: the tool \"%s\" is not on PATH (set %s=1 to fail instead)", jsonset.Escape(tool), RequireToolsEnv)
	}
	return path
}
