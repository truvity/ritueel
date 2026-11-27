package openpgpapp

import (
	"bytes"
	"slices"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// commandSpec is one row of the allowlist: one kind of command that this layer may send, with everything
// that the layer needs to decide about it.
type commandSpec struct {
	// name is the name of the operation. It is what an error shows; a command byte never is.
	name string
	// cla and ins are the class and instruction bytes, exactly. The chaining bit of the class is
	// not part of a row: send sets it on the blocks of a chain, and a command that arrives with it
	// set matches no row.
	cla, ins byte
	// params are the P1 and P2 pairs that the row allows, as P1<<8|P2. For a command on a data
	// object they are the exact tags that may be touched: a tag that is not listed is refused.
	params []uint16
	// data says which command data the row allows.
	data dataRule
	// changes: the command changes the card, in what it stores, in a PIN counter, in the state of
	// a verification or in a counter of use. When the exchange of such a command is lost, its
	// outcome is unknown.
	changes bool
	// secret: the command data holds a PIN. The encoded command is overwritten after the call.
	secret bool
	// mayWait: the command may wait for a person to touch the key, or may take the card long (key
	// generation). It gets the longer budget.
	mayWait bool
	// readOnly: the command is allowed in a read-only session. Only a row that changes nothing and
	// uses no key and no PIN is.
	readOnly bool
	// internal: only send itself may send the command (the continuation of a response); a caller
	// that asks for it is refused.
	internal bool
}

// dataRule allows command data of exact values, or of lengths in a range. The zero value allows no data.
type dataRule struct {
	exact    [][]byte
	min, max int
}

func noData() dataRule                  { return dataRule{} }
func lengths(min, max int) dataRule     { return dataRule{min: min, max: max} }
func exactly(values ...[]byte) dataRule { return dataRule{exact: values} }
func (r dataRule) allows(d []byte) bool {
	if r.exact != nil {
		return slices.ContainsFunc(r.exact, func(v []byte) bool { return bytes.Equal(v, d) })
	}
	return len(d) >= r.min && len(d) <= r.max
}

// The allowlist.
//
// This table is the one place that says which commands the OpenPGP application layer may ever send. A
// command that is not matched by a row is refused before it reaches the transport, so a command that
// must never be sent has no row: terminate (INS E6), activate (44), reset retry counter (2C), key
// import (DB and 4D), decipher (PSO 2A 80 86), get challenge (84), a verification with no PIN, the
// generation of the attestation key, a write to the fingerprints of the CA (CA, CB, CC), to the list
// of times (CD) or to the attestation touch setting (D9), and the touch values "fixed" and "cached
// and fixed" (02 and 04), which cannot be undone. A data object that the card gives only inside the
// application related data (C0 to C3, C5, CD, 73) has no row for a read of its own.
//
// A later piece adds a row only for a command that its operation needs, with the reason in the
// change, and a test of this package states that every command that must never be sent is refused.
// A row is as narrow as the bytes allow: the tags of a data object are listed one by one, and the
// data of a command is exact where the card specification gives its bytes.
//
// The bytes are those of the OpenPGP smart card application, version 3.4.1 (section 7.2 for each
// command, section 4.4 for the data objects and section 5 for the access conditions), and of the
// vendor's page "OpenPGP Attestation" for INS FB. The rows, with what each says:
//
//	name                    changes  secret  may wait  read-only
//	select-application      no       no      no        yes
//	get-data                no       no      no        yes
//	get-public-key          no       no      no        yes
//	get-firmware-version    no       no      no        yes
//	select-data             no       no      no        yes
//	get-response            no       no      no        yes (internal)
//	verify                  yes      yes     no        no
//	deauthenticate          yes      no      no        no
//	change-reference-data   yes      yes     no        no
//	put-key-attributes      yes      no      no        no
//	put-pw-status           yes      no      no        no
//	put-fingerprint         yes      no      no        no
//	put-creation-time       yes      no      no        no
//	put-touch-policy        yes      no      no        no
//	generate-key            yes      no      yes       no
//	compute-signature       yes      no      yes       no
//	authenticate            no       no      yes       no
//	generate-attestation    yes      no      yes       no
//
// Notes on single rows: verification changes the card because a wrong PIN spends a try and a right
// one sets the state of a verification. Computing a signature changes the card because the counter of
// signatures goes up (section 7.2.10). The vendor's attestation command is a write: it stores the
// attestation in the cardholder certificate of the key and overwrites what was there. Reading the
// card's own certificate is a read of a data object (FC), not a command of its own. The key
// certificate of a key is read with select-data and then get-data of 7F21.
var allowlist = []commandSpec{
	{
		// SELECT by application identifier: the six bytes D2 76 00 01 24 01 (section 7.2.1).
		name: "select-application", cla: 0x00, ins: 0xA4, params: []uint16{0x0400},
		data: exactly([]byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}), readOnly: true,
	},
	{
		// GET DATA (section 7.2.6): P1 and P2 are the tag. Only data objects that the card gives
		// alone: C5 and CD are not among them (section 4.4.1, they are read inside 6E).
		name: "get-data", cla: 0x00, ins: 0xCA, data: noData(), readOnly: true,
		params: []uint16{
			0x004F,                         // application identifier
			0x5F52,                         // historical bytes
			0x006E,                         // application related data
			0x00C4,                         // PW status bytes
			0x00DE,                         // key information
			0x00F9,                         // key derivation function
			0x00FA,                         // algorithm information
			0x00D6, 0x00D7, 0x00D8, 0x00D9, // touch settings (vendor)
			0x007A, // security support template, with the signature counter
			0x7F21, // cardholder certificate (the one selected by select-data)
			0x7F66, // extended length information
			0x7F74, // general feature management
			0x00FC, // the card's own attestation certificate (vendor)
		},
	},
	{
		// GENERATE ASYMMETRIC KEY PAIR with P1 81: read the public key that is there (section
		// 7.2.14). The data is the short control reference template of one of the three keys.
		name: "get-public-key", cla: 0x00, ins: 0x47, params: []uint16{0x8100},
		data: exactly(crtSignature, crtAuthentication, crtDecryption), readOnly: true,
	},
	{
		// The vendor's firmware version (INS F1).
		name: "get-firmware-version", cla: 0x00, ins: 0xF1, params: []uint16{0x0000},
		data: noData(), readOnly: true,
	},
	{
		// SELECT DATA (section 7.2.5): the occurrence of the cardholder certificate, 7F21. It
		// moves only the pointer of the current data object.
		name: "select-data", cla: 0x00, ins: 0xA5, params: []uint16{0x0004, 0x0104, 0x0204},
		data: exactly([]byte{0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21}), readOnly: true,
	},
	{
		// GET RESPONSE (section 7.2.9): only the continuation of an answer sends it.
		name: "get-response", cla: 0x00, ins: 0xC0, params: []uint16{0x0000},
		data: noData(), readOnly: true, internal: true,
	},
	{
		// VERIFY with P2 81 (PW1 for signing), 82 (PW1 for the other uses) or 83 (PW3, the Admin
		// PIN) (section 7.2.2). The PIN is 6 to 127 bytes: 127 is what seven bits of the length in
		// the PW status bytes can state. The PW3 minimum of 8 is checked where the PIN is made.
		name: "verify", cla: 0x00, ins: 0x20, params: []uint16{0x0081, 0x0082, 0x0083},
		data: lengths(6, 127), changes: true, secret: true,
	},
	{
		// VERIFY with P1 FF: end the verification of one reference (section 7.2.2).
		name: "deauthenticate", cla: 0x00, ins: 0x20, params: []uint16{0xFF81, 0xFF82, 0xFF83},
		data: noData(), changes: true,
	},
	{
		// CHANGE REFERENCE DATA (section 7.2.3): the old PIN and the new one, joined, with P2 81
		// or 83. 12 to 254 bytes.
		name: "change-reference-data", cla: 0x00, ins: 0x24, params: []uint16{0x0081, 0x0083},
		data: lengths(12, 254), changes: true, secret: true,
	},
	{
		// PUT DATA (section 7.2.8) of the algorithm attributes of the three keys, C1 to C3.
		name: "put-key-attributes", cla: 0x00, ins: 0xDA, params: []uint16{0x00C1, 0x00C2, 0x00C3},
		data: lengths(2, 16), changes: true,
	},
	{
		// PUT DATA of the PW status byte, C4: one byte, 00 or 01 (section 4.4.3). The three
		// bytes after it are not written.
		name: "put-pw-status", cla: 0x00, ins: 0xDA, params: []uint16{0x00C4},
		data: exactly([]byte{0x00}, []byte{0x01}), changes: true,
	},
	{
		// PUT DATA of a fingerprint: C7 for the signature key, C8 for decryption, C9 for
		// authentication. 20 bytes.
		name: "put-fingerprint", cla: 0x00, ins: 0xDA, params: []uint16{0x00C7, 0x00C8, 0x00C9},
		data: lengths(20, 20), changes: true,
	},
	{
		// PUT DATA of a generation time: CE for signature, CF for decryption, D0 for
		// authentication. 4 bytes.
		name: "put-creation-time", cla: 0x00, ins: 0xDA, params: []uint16{0x00CE, 0x00CF, 0x00D0},
		data: lengths(4, 4), changes: true,
	},
	{
		// PUT DATA of the touch setting of one of the three keys, D6, D7 or D8: the value byte and
		// the byte 20 of the vendor's button (section 4.4.3.6). Only off (00), on (01) and cached
		// (03). Fixed (02) and cached and fixed (04) cannot be taken back and are not written.
		name: "put-touch-policy", cla: 0x00, ins: 0xDA, params: []uint16{0x00D6, 0x00D7, 0x00D8},
		data: exactly([]byte{0x00, 0x20}, []byte{0x01, 0x20}, []byte{0x03, 0x20}), changes: true,
	},
	{
		// GENERATE ASYMMETRIC KEY PAIR with P1 80 (section 7.2.14): make a key on the card. The
		// data is the short control reference template of one of the three keys. A generation takes
		// the card seconds.
		name: "generate-key", cla: 0x00, ins: 0x47, params: []uint16{0x8000},
		data: exactly(crtSignature, crtAuthentication, crtDecryption), changes: true, mayWait: true,
	},
	{
		// PSO: COMPUTE DIGITAL SIGNATURE (section 7.2.10): the 48 bytes of a SHA-384 digest, with no
		// header, for ECDSA (clause 7.2.10.1). The key may need a touch.
		name: "compute-signature", cla: 0x00, ins: 0x2A, params: []uint16{0x9E9A},
		data: lengths(48, 48), changes: true, mayWait: true,
	},
	{
		// INTERNAL AUTHENTICATE (section 7.2.13): the same 48 bytes. It changes nothing in the
		// card. The key may need a touch.
		name: "authenticate", cla: 0x00, ins: 0x88, params: []uint16{0x0000},
		data: lengths(48, 48), mayWait: true,
	},
	{
		// The vendor's attestation, class 80, INS FB, for the signature key (P1 01) and the
		// authentication key (P1 03). The decryption key is loaded, not generated, and is not
		// attested. No data. A write: see the notes above.
		name: "generate-attestation", cla: 0x80, ins: 0xFB, params: []uint16{0x0100, 0x0300},
		data: noData(), changes: true, mayWait: true,
	},
}

// The short control reference templates of the three keys (section 7.2.14).
var (
	crtSignature      = []byte{0xB6, 0x00}
	crtAuthentication = []byte{0xA4, 0x00}
	crtDecryption     = []byte{0xB8, 0x00}
)

// lookup finds the row that a command matches in table. It reports false for a command that no row
// matches, and for a row that only send itself may use when internal is false.
func lookup(table []commandSpec, cmd apdu.Command, internal bool) (*commandSpec, bool) {
	for i := range table {
		r := &table[i]
		if r.cla != cmd.CLA || r.ins != cmd.INS {
			continue
		}
		if !slices.Contains(r.params, uint16(cmd.P1)<<8|uint16(cmd.P2)) || !r.data.allows(cmd.Data) {
			continue
		}
		if r.internal && !internal {
			return nil, false
		}
		return r, true
	}
	return nil, false
}
