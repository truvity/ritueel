package openpgp

import (
	"bytes"
	"io"
)

// Reason is a reason for revocation (RFC 9580, section 5.2.3.31): the code, and the word that the
// ceremony record uses for it.
type Reason struct {
	Code byte
	Text string
}

// The reasons of docs/reference/revocation-material.md, "What is made". The two that are made at
// birth are Compromised and Superseded (record 0007, rule 21); the holder may add Retired and
// NoReason.
var (
	// Compromised: verifiers distrust everything the key signed.
	Compromised = Reason{Code: 2, Text: "compromised"}
	// Superseded: verifiers believe what was signed before the revocation.
	Superseded = Reason{Code: 1, Text: "superseded"}
	// Retired: the same as superseded.
	Retired = Reason{Code: 3, Text: "retired"}
	// NoReason: left to the verifier.
	NoReason = Reason{Code: 0, Text: "no-reason"}
)

// RevocationSignature returns a key revocation signature (type 0x20) over the primary's public key
// packet alone. It is version 4 with SHA-384; its hashed area holds the signature creation time
// (the ceremony time), the reason for revocation (the code and the word) and the issuer
// fingerprint, and its unhashed area holds the issuer key ID. The result is the signature packet;
// the caller stores it apart from the key (docs/reference/revocation-material.md).
//
// The reason subpacket is not critical, as in the test vectors. When the signature is written into
// a keyring file, it must stand right after the primary key packet: gpg and gpgv apply a
// revocation only there, and read it anywhere else as a signature on the last subkey, so the helper
// that writes a keyring file belongs to later work. The revocation of a subkey is not built here.
//
// Only the key, the creation time and the ceremony time of p are used. The reason must be one of
// the four of the table, with its word: a reason that is not one of them is refused. The signature
// is verified before it is returned.
func RevocationSignature(rnd io.Reader, p PrimaryParams, r Reason) ([]byte, error) {
	if r != Compromised && r != Superseded && r != Retired && r != NoReason {
		return nil, fail(ErrParams, "the reason for revocation is not one of the four of the profile")
	}
	g, err := newPrimarySigner(rnd, p)
	if err != nil {
		return nil, err
	}
	body, err := g.sign(sigSpec{
		sigType: sigKeyRevocation,
		hashed: []subpacket{
			{typ: spCreationTime, data: u32(unixU32(p.CeremonyTime))},
			{typ: spRevocationReason, data: append([]byte{r.Code}, r.Text...)},
			g.issuerFingerprint(),
		},
		unhashed: []subpacket{g.issuerKeyID()},
		data:     [][]byte{hashPrefix(g.body)},
	})
	if err != nil {
		return nil, err
	}
	pkt := wrap(tagSignature, body)
	sig, err := readBack(pkt, g.key)
	if err != nil {
		return nil, err
	}
	if err := g.pk.VerifyRevocationSignature(sig); err != nil {
		return nil, fail(ErrSignature, "the revocation signature does not verify: %v", err)
	}
	if sig.SigType != sigKeyRevocation || !sig.CreationTime.Equal(p.CeremonyTime) ||
		sig.RevocationReason == nil || byte(*sig.RevocationReason) != r.Code || sig.RevocationReasonText != r.Text {
		return nil, fail(ErrSignature, "the revocation signature does not read back as it was built")
	}
	return bytes.Clone(pkt), nil
}
