package openpgp

import "testing"

// gpgv reads no subpacket area longer than 10000 bytes ("unhashed data too long"), and then it reads
// no signature of the key. The guard of BindSubkey is that number: a different one would refuse
// bindings that gpgv reads, or let through ones that it does not. The tests of the package measure
// the edge in gpgv itself.
func TestTheGuardOnTheUnhashedAreaIsTheLengthThatGpgvReads(t *testing.T) {
	if maxUnhashedArea != 10000 {
		t.Errorf("maxUnhashedArea = %d, want 10000", maxUnhashedArea)
	}
}
