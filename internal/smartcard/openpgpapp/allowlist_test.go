package openpgpapp

import (
	"errors"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

func names(match func(commandSpec) bool) []string {
	var out []string
	for _, r := range allowlist {
		if match(r) {
			out = append(out, r.name)
		}
	}
	return out
}

func TestTableShape(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range allowlist {
		if r.name == "" || seen[r.name] {
			t.Errorf("name %q empty or repeated", r.name)
		}
		seen[r.name] = true
		if len(r.params) == 0 {
			t.Errorf("%s: no parameters listed", r.name)
		}
		if r.cla&chainingBit != 0 {
			t.Errorf("%s: the chaining bit is set in the class", r.name)
		}
		if r.secret && !r.changes {
			t.Errorf("%s: a PIN is sent to a command that changes nothing", r.name)
		}
		if r.readOnly && (r.changes || r.secret || r.mayWait) {
			t.Errorf("%s: read-only but changes, holds a secret or waits", r.name)
		}
	}
	got := names(func(r commandSpec) bool { return r.readOnly })
	want := []string{"select-application", "get-data", "get-public-key", "get-firmware-version", "select-data", "get-response"}
	if !slices.Equal(got, want) {
		t.Errorf("read-only rows: %v", got)
	}
	if got := names(func(r commandSpec) bool { return r.internal }); !slices.Equal(got, []string{"get-response"}) {
		t.Errorf("internal rows: %v", got)
	}
	if got := names(func(r commandSpec) bool { return r.secret }); !slices.Equal(got, []string{"verify", "change-reference-data"}) {
		t.Errorf("secret rows: %v", got)
	}
	if got := names(func(r commandSpec) bool { return r.mayWait }); !slices.Equal(got,
		[]string{"generate-key", "compute-signature", "authenticate", "generate-attestation"}) {
		t.Errorf("rows that may wait: %v", got)
	}
	if got := names(func(r commandSpec) bool { return !r.changes }); !slices.Equal(got,
		[]string{"select-application", "get-data", "get-public-key", "get-firmware-version", "select-data", "get-response", "authenticate"}) {
		t.Errorf("rows that change nothing: %v", got)
	}
}

// TestNeverSent holds the commands that must never be sent. Each one is refused by a session of
// either mode, with a data field that would be right for the nearest row, and reaches no transport.
func TestNeverSent(t *testing.T) {
	digest := make([]byte, 48)
	pin := []byte("123456")
	crt := func(b ...byte) []byte { return b }
	for _, tc := range []struct {
		name string
		cmd  apdu.Command
	}{
		{"terminate", apdu.Command{INS: 0xE6}},
		{"activate", apdu.Command{INS: 0x44}},
		{"reset retry counter with the Admin PIN", apdu.Command{INS: 0x2C, P1: 0x02, P2: 0x81, Data: make([]byte, 16)}},
		{"reset retry counter with the code", apdu.Command{INS: 0x2C, P1: 0x00, P2: 0x81, Data: make([]byte, 16)}},
		{"key import", apdu.Command{INS: 0xDB, P1: 0x3F, P2: 0xFF, Data: make([]byte, 40)}},
		{"key import data object", apdu.Command{INS: 0x4D, Data: make([]byte, 40)}},
		{"decipher", apdu.Command{INS: 0x2A, P1: 0x80, P2: 0x86, Data: make([]byte, 100)}},
		{"get challenge", apdu.Command{INS: 0x84, Le: 8}},
		{"verify with no PIN", apdu.Command{INS: 0x20, P2: 0x81}},
		{"verify with a short PIN", verifyCmd(pin[:5])},
		{"verify with a long PIN", verifyCmd(make([]byte, 128))},
		{"verify with another P1", apdu.Command{INS: 0x20, P1: 0x01, P2: 0x81, Data: pin}},
		{"verify with another P2", apdu.Command{INS: 0x20, P2: 0x84, Data: pin}},
		{"deauthenticate with a PIN", apdu.Command{INS: 0x20, P1: 0xFF, P2: 0x81, Data: pin}},
		{"change reference data of the reset code", apdu.Command{INS: 0x24, P2: 0x82, Data: make([]byte, 16)}},
		{"generate the attestation key", apdu.Command{INS: 0x47, P1: 0x80, Data: crt(0xB6, 0x03, 0x84, 0x01, 0x81)}},
		{"generate with the extended template", apdu.Command{INS: 0x47, P1: 0x80, Data: crt(0xB6, 0x03, 0x84, 0x01, 0x01)}},
		{"generate with no template", apdu.Command{INS: 0x47, P1: 0x80}},
		{"generate with another P2", apdu.Command{INS: 0x47, P1: 0x80, P2: 0x01, Data: crt(0xB6, 0x00)}},
		{"read the attestation key", apdu.Command{INS: 0x47, P1: 0x81, Data: crt(0xB6, 0x03, 0x84, 0x01, 0x81)}},
		{"sign 32 bytes", apdu.Command{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: digest[:32]}},
		{"sign 64 bytes", apdu.Command{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: make([]byte, 64)}},
		{"authenticate 32 bytes", apdu.Command{INS: 0x88, Data: digest[:32]}},
		{"attest the decryption key", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x02}},
		{"attest with data", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x01, Data: []byte{1}}},
		{"attest with class 00", apdu.Command{INS: 0xFB, P1: 0x01}},
		{"a read with the chaining bit", apdu.Command{CLA: 0x10, INS: 0xCA, P2: 0x4F}},
		{"a read with the vendor class", apdu.Command{CLA: 0x80, INS: 0xCA, P2: 0x4F}},
		{"a read with the secure messaging class", apdu.Command{CLA: 0x0C, INS: 0xCA, P2: 0x4F}},
		{"a read with data", apdu.Command{INS: 0xCA, P2: 0x4F, Data: []byte{1}}},
		{"get response by a caller", apdu.Command{INS: 0xC0}},
		{"select by another identifier", apdu.Command{INS: 0xA4, P1: 0x04, Data: []byte{0xA0, 0x00, 0x00, 0x03, 0x08}}},
		{"select by the identifier with another P1", apdu.Command{INS: 0xA4, P1: 0x00, Data: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}}},
		{"select a file", apdu.Command{INS: 0xA4, P1: 0x00, P2: 0x00, Data: []byte{0x3F, 0x00}}},
		{"select data of the fourth slot", apdu.Command{INS: 0xA5, P1: 0x03, P2: 0x04, Data: []byte{0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21}}},
		{"select data of another object", apdu.Command{INS: 0xA5, P1: 0x00, P2: 0x04, Data: []byte{0x60, 0x04, 0x5C, 0x02, 0x7F, 0x22}}},
		{"touch fixed", apdu.Command{INS: 0xDA, P2: 0xD6, Data: []byte{0x02, 0x20}}},
		{"touch cached and fixed", apdu.Command{INS: 0xDA, P2: 0xD7, Data: []byte{0x04, 0x20}}},
		{"touch value with another second byte", apdu.Command{INS: 0xDA, P2: 0xD8, Data: []byte{0x01, 0x21}}},
		{"touch with one byte", apdu.Command{INS: 0xDA, P2: 0xD8, Data: []byte{0x01}}},
		{"touch of the attestation key", apdu.Command{INS: 0xDA, P2: 0xD9, Data: []byte{0x01, 0x20}}},
		{"PW status of four bytes", apdu.Command{INS: 0xDA, P2: 0xC4, Data: []byte{0x01, 0x7F, 0x7F, 0x7F}}},
		{"PW status with a value of two", apdu.Command{INS: 0xDA, P2: 0xC4, Data: []byte{0x02}}},
		{"PUT DATA with the odd instruction", apdu.Command{INS: 0xDB, P2: 0xC4, Data: []byte{0x01}}},
		{"fingerprint of 19 bytes", apdu.Command{INS: 0xDA, P2: 0xC7, Data: make([]byte, 19)}},
		{"fingerprint of 21 bytes", apdu.Command{INS: 0xDA, P2: 0xC7, Data: make([]byte, 21)}},
		{"time of 3 bytes", apdu.Command{INS: 0xDA, P2: 0xCE, Data: make([]byte, 3)}},
		{"time of 5 bytes", apdu.Command{INS: 0xDA, P2: 0xCE, Data: make([]byte, 5)}},
		{"attributes with no bytes", apdu.Command{INS: 0xDA, P2: 0xC1}},
		{"attributes of 17 bytes", apdu.Command{INS: 0xDA, P2: 0xC1, Data: make([]byte, 17)}},
		{"firmware version with data", apdu.Command{INS: 0xF1, Data: []byte{1}}},
		{"firmware version with a parameter", apdu.Command{INS: 0xF1, P1: 0x01}},
	} {
		for _, readOnly := range []bool{false, true} {
			f := &fakeTransport{}
			s := newSession(t, f, Options{ReadOnly: readOnly})
			_, err := s.send(tc.cmd)
			if !errors.Is(err, ErrNotAllowed) || errors.Is(err, ErrReadOnly) || f.calls() != 0 || s.Dead() {
				t.Errorf("%s (read-only %v): %v, %d calls", tc.name, readOnly, err, f.calls())
			}
		}
	}
}

// The tags that a read of a data object may name, and the tags that a write may name. They are spelled
// out here again, from the card specification and not from the table, and every one of the 65536
// pairs of P1 and P2 is tried against them.
func TestEveryTagOfTheDataObjectCommands(t *testing.T) {
	reads := []uint16{0x004F, 0x5F52, 0x006E, 0x00C4, 0x00DE, 0x00F9, 0x00FA, 0x00D6, 0x00D7, 0x00D8, 0x00D9, 0x007A, 0x7F21, 0x7F66, 0x7F74, 0x00FC}
	writes := []uint16{0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C7, 0x00C8, 0x00C9, 0x00CE, 0x00CF, 0x00D0, 0x00D6, 0x00D7, 0x00D8}
	// A data field that the row of each written tag takes.
	dataFor := func(tag uint16) []byte {
		switch tag {
		case 0x00C4:
			return []byte{0x01}
		case 0x00D6, 0x00D7, 0x00D8:
			return []byte{0x01, 0x20}
		case 0x00C7, 0x00C8, 0x00C9:
			return make([]byte, 20)
		case 0x00CE, 0x00CF, 0x00D0:
			return make([]byte, 4)
		}
		return make([]byte, 6)
	}
	for p := range 0x10000 {
		tag := uint16(p)
		_, getOK := lookup(allowlist, apdu.Command{INS: 0xCA, P1: byte(tag >> 8), P2: byte(tag), Le: 256}, false)
		if getOK != slices.Contains(reads, tag) {
			t.Fatalf("GET DATA %04X: allowed %v", tag, getOK)
		}
		// Any data length that some row takes, for any tag.
		putOK := false
		for _, n := range []int{0, 1, 2, 4, 6, 20, 48} {
			data := make([]byte, n)
			if slices.Contains(writes, tag) && n == len(dataFor(tag)) {
				data = dataFor(tag)
			}
			if _, ok := lookup(allowlist, apdu.Command{INS: 0xDA, P1: byte(tag >> 8), P2: byte(tag), Data: data}, false); ok {
				putOK = true
			}
		}
		if putOK != slices.Contains(writes, tag) {
			t.Fatalf("PUT DATA %04X: allowed %v", tag, putOK)
		}
	}
}

func TestAllowedCommandsAreMatched(t *testing.T) {
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	for _, tc := range []struct {
		name string
		cmd  apdu.Command
		op   string
	}{
		{"select", apdu.Command{INS: 0xA4, P1: 0x04, Data: aid, Le: 256}, "select-application"},
		{"get data", getData(0x006E, 256), "get-data"},
		{"public key SIG", apdu.Command{INS: 0x47, P1: 0x81, Data: []byte{0xB6, 0x00}, Le: 256}, "get-public-key"},
		{"public key AUT", apdu.Command{INS: 0x47, P1: 0x81, Data: []byte{0xA4, 0x00}, Le: 256}, "get-public-key"},
		{"public key DEC", apdu.Command{INS: 0x47, P1: 0x81, Data: []byte{0xB8, 0x00}, Le: 256}, "get-public-key"},
		{"firmware", apdu.Command{INS: 0xF1, Le: 256}, "get-firmware-version"},
		{"select data", apdu.Command{INS: 0xA5, P1: 0x02, P2: 0x04, Data: []byte{0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21}, Le: 256}, "select-data"},
		{"verify PW1", verifyCmd([]byte("123456")), "verify"},
		{"verify PW3", apdu.Command{INS: 0x20, P2: 0x83, Data: []byte("12345678")}, "verify"},
		{"deauthenticate", apdu.Command{INS: 0x20, P1: 0xFF, P2: 0x82}, "deauthenticate"},
		{"change PIN", apdu.Command{INS: 0x24, P2: 0x81, Data: make([]byte, 12)}, "change-reference-data"},
		{"attributes", apdu.Command{INS: 0xDA, P2: 0xC1, Data: []byte{0x13, 0x2B, 0x81, 0x04, 0x00, 0x22}}, "put-key-attributes"},
		{"pw status", apdu.Command{INS: 0xDA, P2: 0xC4, Data: []byte{0x00}}, "put-pw-status"},
		{"fingerprint", apdu.Command{INS: 0xDA, P2: 0xC9, Data: make([]byte, 20)}, "put-fingerprint"},
		{"time", apdu.Command{INS: 0xDA, P2: 0xD0, Data: make([]byte, 4)}, "put-creation-time"},
		{"touch off", apdu.Command{INS: 0xDA, P2: 0xD6, Data: []byte{0x00, 0x20}}, "put-touch-policy"},
		{"touch on", apdu.Command{INS: 0xDA, P2: 0xD7, Data: []byte{0x01, 0x20}}, "put-touch-policy"},
		{"touch cached", apdu.Command{INS: 0xDA, P2: 0xD8, Data: []byte{0x03, 0x20}}, "put-touch-policy"},
		{"generate", apdu.Command{INS: 0x47, P1: 0x80, Data: []byte{0xB6, 0x00}, Le: 256}, "generate-key"},
		{"sign", apdu.Command{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: make([]byte, 48), Le: 256}, "compute-signature"},
		{"authenticate", apdu.Command{INS: 0x88, Data: make([]byte, 48), Le: 256}, "authenticate"},
		{"attest SIG", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x01, Le: 256}, "generate-attestation"},
		{"attest AUT", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x03, Le: 256}, "generate-attestation"},
	} {
		r, ok := lookup(allowlist, tc.cmd, false)
		if !ok || r.name != tc.op {
			t.Errorf("%s: %v %v", tc.name, ok, r)
		}
	}
}
