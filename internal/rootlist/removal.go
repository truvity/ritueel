package rootlist

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"ritueel.id/ritueel/internal/jws"
)

// The two types of signed documents of this page. A signature over one is never read as the other
// (RFC 8725, section 3.11), nor as the SSH CA key list, which uses the same keys.
const (
	listTyp    = "root-list+json"
	removalTyp = "root-removal+json"
)

// ErrRemovalInvalid is wrapped by every error that CheckRemoval returns.
var ErrRemovalInvalid = errors.New("invalid removal authorisation")

// CheckRemoval is the body of check 9 for one entry of removals: the entry must be a valid removal
// authorisation of the root key it names, on the list the host holds (heldPins, the pins of its
// root keys, or its initial pins) and not on the candidate list cand. Valid means the format of the
// page: a compact JWS whose protected header has typ root-removal+json, whose kid, whose key in
// x5c and whose payload's pin all equal the entry's pin, whose payload is exactly the bytes
// {"version":1,"x509_spki_sha256":"<pin>"}, and whose signature verifies with that key. The entry's
// label is not compared with anything: a pin names the key, and the label of the held list is
// not carried by initial pins. Every error wraps ErrRemovalInvalid.
func CheckRemoval(r Removal, cand *List, heldPins []string) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrRemovalInvalid, fmt.Sprintf(format, args...))
	}
	pin := r.X509SPKISHA256
	if !isLowerHex(pin, 64) {
		return fail("the entry's pin is not 64 lower-case hexadecimal digits")
	}
	if !slices.Contains(heldPins, pin) {
		return fail("the root key %s is not a root key of the list the host holds", pin)
	}
	if cand != nil && slices.Contains(cand.Pins(), pin) {
		return fail("the root key %s is still on this list", pin)
	}
	c, err := jws.ParseCompact(r.Authorisation, removalTyp)
	if err != nil {
		return fail("the authorisation of %s: %v", pin, err)
	}
	if c.Header.Kid != pin || jws.Pin(c.Cert) != pin {
		return fail("the kid and the key of the authorisation of %s are not the entry's pin", pin)
	}
	if want := `{"version":1,"x509_spki_sha256":"` + pin + `"}`; !bytes.Equal(c.Payload, []byte(want)) {
		return fail("the payload of the authorisation of %s is not exactly the removal statement for its pin", pin)
	}
	if err := c.Verify(); err != nil {
		return fail("the authorisation of %s: %v", pin, err)
	}
	return nil
}
