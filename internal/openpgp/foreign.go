package openpgp

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// The limits of the reader of a foreign key (record 0008, rule 5). Passing one is an
// [ErrForeignLimit] whose text names the constant. A key that a person has kept for twenty years
// passes all of them: ten user IDs, twenty subkeys, hundreds of certifications from other people and
// one photograph are far below each. The values are proposed: no page names them.
const (
	// MaxForeignKeyBytes is the most bytes of the file: 8 MiB. It is checked before anything is read,
	// armoured or not. A key with a few thousand certifications from other people is about 1 MiB; one
	// that the keyservers once flooded with certifications can be several times larger and is refused.
	MaxForeignKeyBytes = 8 << 20
	// MaxForeignPackets is the most packets in the file, counting the trust and marker packets that
	// are skipped: 10,000.
	MaxForeignPackets = 10000
	// MaxForeignUserIDs is the most user IDs in the file, and the most user attribute packets
	// (photographs) in the file: 32 of each.
	MaxForeignUserIDs = 32
	// MaxForeignSubkeys is the most subkeys in the file: 64, three subkeys a year for twenty years.
	MaxForeignSubkeys = 64
	// MaxForeignSignatures is the most signatures on one component (the key, one user ID, one
	// attribute, one subkey): 1024.
	MaxForeignSignatures = 1024
	// MaxForeignPacketBytes is the most bytes of the body of one packet: 1 MiB, enough for a large
	// photograph.
	MaxForeignPacketBytes = 1 << 20
	// MaxForeignPassphraseBytes is the most bytes of the passphrase that [ForeignKey.OpenSecret]
	// takes: 4096. A longer one is an [ErrParams].
	MaxForeignPassphraseBytes = 4096
)

// SecretState tells whether the secret of the primary key in the file is protected by a passphrase.
// The zero value is not a state.
type SecretState uint8

// The two states of a secret that the reader takes. A secret that is protected in another way, or
// that is not in the file, is refused when the file is read.
const (
	// SecretUnprotected is S2K usage 0: the secret is in the file as it is, with a checksum.
	SecretUnprotected SecretState = iota + 1
	// SecretProtected is S2K usage 254: AES in CFB mode with the SHA-1 check of the standard, under a
	// key from an iterated and salted S2K.
	SecretProtected
)

// String is "unprotected" or "protected".
func (s SecretState) String() string {
	switch s {
	case SecretUnprotected:
		return "unprotected"
	case SecretProtected:
		return "protected"
	}
	return "unknown"
}

// SubkeyForm tells which of the three forms a subkey has in the file. The zero value is not a form.
type SubkeyForm uint8

// The forms of a subkey in an export. The reader never decrypts or keeps the secret of a subkey,
// and it keeps no card serial number that a stub may carry.
const (
	// SubkeyPublic is a Public-Subkey packet: there is no secret, as in a public export.
	SubkeyPublic SubkeyForm = iota + 1
	// SubkeyStub is a Secret-Subkey packet with the GNU extension that says the secret is not in the
	// file: it is kept elsewhere or on a card.
	SubkeyStub
	// SubkeyWithSecret is a Secret-Subkey packet that holds a secret, protected or not.
	SubkeyWithSecret
)

// String is "public", "stub" or "with secret".
func (f SubkeyForm) String() string {
	switch f {
	case SubkeyPublic:
		return "public"
	case SubkeyStub:
		return "stub"
	case SubkeyWithSecret:
		return "with secret"
	}
	return "unknown"
}

// SignatureStatus is what the reader made of one signature that its own primary key claims to have
// made. Only SignatureValid counts.
type SignatureStatus uint8

// The statuses of a signature, in the order that the reader decides them: the first that applies.
const (
	// SignatureValid is a version 4 signature that verifies with the primary key, with SHA-256,
	// SHA-384 or SHA-512, and no critical subpacket that the reader does not understand.
	SignatureValid SignatureStatus = iota + 1
	// SignatureWeakHash is a signature made with MD5, SHA-1, RIPEMD-160 or another hash that is
	// broken or obsolete. It is present and does not count; it is not verified.
	SignatureWeakHash
	// SignatureHashNotAccepted is a signature made with a hash that is not weak and that the reader
	// does not take: SHA-224, SHA-3 or a hash that it does not know. It does not count.
	SignatureHashNotAccepted
	// SignatureUnknownCritical is a signature with a critical subpacket that the reader does not
	// understand (RFC 9580, section 5.2.3.7). It does not count.
	SignatureUnknownCritical
	// SignatureNotVerified is a signature that is well formed and does not verify with the primary
	// key, or that another reader refuses. It does not count.
	SignatureNotVerified
	// SignatureUnreadable is a signature that the reader cannot read: it is not version 4, or its
	// fields, its subpackets or its creation time are not in the form that it takes. It does not
	// count.
	SignatureUnreadable
	// SignatureMisplaced is a signature of the primary key of a type that does not belong where it
	// stands (a binding signature on a user ID, for example). It does not count.
	SignatureMisplaced
)

// String is a few words for the status.
func (s SignatureStatus) String() string {
	switch s {
	case SignatureValid:
		return "valid"
	case SignatureWeakHash:
		return "weak hash"
	case SignatureHashNotAccepted:
		return "hash not accepted"
	case SignatureUnknownCritical:
		return "unknown critical subpacket"
	case SignatureNotVerified:
		return "does not verify"
	case SignatureUnreadable:
		return "unreadable"
	case SignatureMisplaced:
		return "misplaced"
	}
	return "unknown"
}

// ForeignSignature is one signature that the primary key claims to have made (its issuer is the
// primary's, or it names none), with what the reader found. The times are in UTC, and zero when the
// signature has none. A signature that is not [SignatureValid] gives the fields that its hashed
// subpackets hold, for a person to see; none of them counts.
type ForeignSignature struct {
	// Type is the signature type of RFC 9580, section 5.2.1: 0x10 to 0x13 a certification of a user
	// ID, 0x30 its revocation, 0x18 a subkey binding, 0x28 a subkey revocation, 0x1F a direct-key
	// signature, 0x20 a key revocation.
	Type uint8
	// Status is what the reader decided.
	Status SignatureStatus
	// Hash is the name of the hash ("SHA-256"), or "hash 99" for a number that is not named.
	Hash string
	// Created is the signature creation time.
	Created time.Time
	// Expires is the end of the signature, from its signature expiration time, and zero if it has
	// none. The reader reads no clock, so it does not compare it with a date.
	Expires time.Time
	// KeyExpires is the end of the key, from the key expiration time of the signature counted from
	// the creation of the key that it concerns, and zero if the signature has none.
	KeyExpires time.Time
	// KeyFlags is the first octet of the key flags (0x01 certify, 0x02 sign, 0x04 and 0x08 encrypt,
	// 0x20 authenticate), and 0 if the signature has none.
	KeyFlags uint8
	// Primary is the primary user ID flag of the signature.
	Primary bool
	// Reason is the reason code of a revocation (RFC 9580, section 5.2.3.31), when HasReason is true.
	Reason    uint8
	HasReason bool
}

// ForeignPrimary is the primary key of a foreign key.
type ForeignPrimary struct {
	// Fingerprint is the version 4 fingerprint: 40 lower-case hexadecimal digits.
	Fingerprint string
	// KeyID is its last 16 digits.
	KeyID string
	// Algorithm is RSA 4096, EdDSA on Ed25519 or ECDSA on P-384: the others are refused.
	Algorithm ForeignAlgorithm
	// Created is the creation time of the key.
	Created time.Time
	// Secret is whether the secret in the file is protected.
	Secret SecretState
	// Cipher names the cipher of a protected secret: "AES-128", "AES-192" or "AES-256". It is empty
	// for an unprotected secret.
	Cipher string
	// Revoked is true when a valid key revocation signature by the primary is in the file. The reader
	// does not refuse such a key: the caller decides.
	Revoked bool
}

// ForeignUserID is one user ID of a foreign key and what the file says about it.
type ForeignUserID struct {
	// Text is the bytes of the user ID packet as they are, and they are not checked: they may be
	// anything, invalid UTF-8 and control characters included. A caller that shows them escapes them.
	// The reader puts them in no error.
	Text string
	// Signatures are the certifications (0x10 to 0x13) and certification revocations (0x30) that the
	// primary claims to have made on this user ID, in the order of the file.
	Signatures []ForeignSignature
	// Valid is true when at least one of Signatures is a valid certification: a self-signature that
	// counts.
	Valid bool
	// Created is the creation time of the newest valid self-signature (the later one in the file
	// among equal times), and the fields below are read from that signature.
	Created time.Time
	// KeyExpires is the key expiry that the newest valid self-signature gives, and zero if none.
	KeyExpires time.Time
	// KeyFlags is its first key flags octet.
	KeyFlags uint8
	// Primary is its primary user ID flag.
	Primary bool
	// Revoked is true when a valid certification revocation by the primary is not older than the
	// newest valid self-signature (or when it is valid and there is no valid self-signature). A
	// revocation in the same second as a self-signature counts: when in doubt it revokes.
	Revoked bool
	// RevokedAt is the creation time of that revocation.
	RevokedAt time.Time
	// Certifications counts the certifications (types 0x10 to 0x13) that other keys made on this user
	// ID. They are kept in the certificate and not verified: the reader does not have those keys. A
	// signature whose issuer cannot be read is counted here too.
	Certifications int
	// OtherSignatures counts the other signatures of other keys on this user ID, a revocation by
	// another key for example. They are kept in the certificate and not verified.
	OtherSignatures int
}

// ForeignSubkey is one subkey of a foreign key. The reader never decrypts or keeps the secret of a
// subkey: it reports what the packet is.
type ForeignSubkey struct {
	// Fingerprint is the version 4 fingerprint: 40 lower-case hexadecimal digits.
	Fingerprint string
	// KeyID is its last 16 digits.
	KeyID string
	// Algorithm is the algorithm with its size or its curve.
	Algorithm ForeignAlgorithm
	// Created is the creation time of the subkey.
	Created time.Time
	// Form is which of the three forms the file held. A stub can carry a card serial number: it is
	// not kept or shown.
	Form SubkeyForm
	// Signatures are the subkey bindings (0x18) and subkey revocations (0x28) that the primary
	// claims to have made on this subkey, in the order of the file.
	Signatures []ForeignSignature
	// Bound is true when at least one binding verifies. A binding of a subkey that can sign needs its
	// embedded back-signature, which go-crypto checks with it.
	Bound bool
	// BoundAt is the creation time of the newest valid binding (the later one in the file among
	// equal times), and Flags and Expires are read from that binding: the first key flags octet, and
	// the end of the key counted from the creation of the subkey (zero if none).
	BoundAt time.Time
	Flags   uint8
	Expires time.Time
	// Revoked is true when a valid subkey revocation by the primary is not older than the newest valid
	// binding, or when it is valid and no binding is.
	Revoked bool
	// OtherSignatures counts the signatures of other keys on this subkey, kept and not verified.
	OtherSignatures int
}

// ForeignKey is what the file of an exported secret key holds, read by [ReadForeignKey]. The exported
// fields are for reading: a caller that changes them changes nothing that the reader keeps. The
// secret of the primary is kept inside, in the form it had in the file, and [ForeignKey.Wipe]
// clears it. A ForeignKey is not safe for use by several goroutines at once, and it is used by its
// pointer: a copy of the struct shares the secret and is not wiped by the wipe of the original.
type ForeignKey struct {
	// Primary is the primary key.
	Primary ForeignPrimary
	// UserIDs are the user IDs in the order of the file.
	UserIDs []ForeignUserID
	// Subkeys are the subkeys in the order of the file.
	Subkeys []ForeignSubkey
	// KeySignatures are the direct-key signatures (0x1F) and key revocations (0x20) that the primary
	// claims to have made, in the order of the file.
	KeySignatures []ForeignSignature
	// OtherKeySignatures counts the signatures of other keys on the primary key itself (a revocation by
	// a designated revoker, for example): kept and not verified.
	OtherKeySignatures int
	// UserAttributes is the number of user attribute packets (photographs) and UserAttributeBytes
	// the total size of their bodies. They are kept in the certificate and not read.
	UserAttributes     int
	UserAttributeBytes int

	cert  []byte
	pub   fkPublic
	prot  fkProtection // holds the secret of the primary as it stood in the file, until the wipe
	wiped bool
}

// Certificate returns the public certificate, binary: every packet of the file that is not secret
// material, byte for byte and in order, with the secret key packet of the primary and of each subkey
// turned into its public key packet (a new-format header with the shortest length, and the public
// part of the body). It starts with the primary and holds no secret. Trust packets and marker packets
// are not in it: a trust packet is local to the tool that wrote it. It is a copy.
func (k *ForeignKey) Certificate() []byte {
	if k == nil {
		return nil
	}
	return bytes.Clone(k.cert)
}

// Wipe clears the secret that the key holds, and the key then opens nothing: [ForeignKey.OpenSecret]
// is an [ErrParams]. It does not clear the file that the caller gave to [ReadForeignKey], which holds
// the secret as it came: the caller clears its own buffer. It is safe to call more than once.
func (k *ForeignKey) Wipe() {
	if k == nil {
		return
	}
	clear(k.prot.data)
	clear(k.prot.iv)
	k.prot.data, k.prot.iv, k.wiped = nil, nil, true
}

// ReadForeignKey reads the file of one exported transferable secret key (RFC 9580, section 10.1), the
// kind that gpg writes with --export-secret-keys: binary packets, or one armour block of type PGP
// PRIVATE KEY BLOCK. It needs no passphrase: it tells what the file holds, so that a person sees it
// before the passphrase is asked for. [ForeignKey.OpenSecret] takes the secret of the primary.
//
// The file is held to [MaxForeignKeyBytes] before anything is read. The reader refuses what it does
// not read, each with a text of its own and no byte of the file in it, and never guesses:
//
//   - the framing: old and new packet headers are read; a partial body length and an indeterminate
//     length are refused by name (a key is never written with them); a packet over
//     [MaxForeignPacketBytes], more than [MaxForeignPackets] packets, [MaxForeignUserIDs] user IDs,
//     [MaxForeignSubkeys] subkeys or [MaxForeignSignatures] signatures on one component are an
//     [ErrForeignLimit]; trust packets and marker packets are skipped and are not kept; any other
//     packet that does not belong in a transferable key is an [ErrForeignPacket] with its tag; the
//     order is the standard's (the primary, its signatures, the user IDs and attributes with their
//     signatures, then the subkeys with theirs), and another order is an [ErrForeignForm];
//   - the armour: one block of type PGP PRIVATE KEY BLOCK, its CRC-24 line checked when there is one;
//     any other type, a second block or text around it is an [ErrForeignArmour];
//   - the primary: exactly one, version 4 (3, 5 and 6 each have a reason) and RSA with a 4096-bit
//     modulus, EdDSA legacy on Ed25519 (algorithm 22) or ECDSA on P-384, and nothing else
//     ([ErrForeignVersion], [ErrForeignAlgorithm]); a second primary is an [ErrForeignPrimaries];
//   - the secret of the primary: S2K usage 0 (not protected) or S2K usage 254 (AES-128, AES-192 or
//     AES-256 in CFB mode with the SHA-1 check, key from an iterated and salted S2K with SHA-1,
//     SHA-224, SHA-256, SHA-384 or SHA-512); a primary with no secret (a public key packet, or the
//     GNU extension for a dummy or a card) is an [ErrForeignNoSecret]; any other protection (usage
//     255, 253 or a cipher number, another cipher, a simple or salted S2K, Argon2, another hash) is an
//     [ErrForeignProtection];
//   - the subkeys: public, as a GNU stub with no secret, or with a secret: all are read. The reader
//     skips the secret bytes of a subkey and never decrypts or keeps them; the algorithm of a secret
//     subkey must be one whose public part it can delimit (RSA, ElGamal, DSA, ECDSA, EdDSA, ECDH,
//     X25519, X448, Ed25519, Ed448), or the file is an [ErrForeignAlgorithm]; a subkey that is not
//     version 4 is an [ErrForeignVersion];
//   - the signatures: a signature that the primary claims (its issuer fingerprint, or its issuer key
//     ID when there is no fingerprint) is read and verified with go-crypto, and counts only when it
//     is version 4, made with SHA-256, SHA-384 or SHA-512 and has no critical subpacket that the
//     reader does not understand (the subpackets 2, 3, 9, 11, 16, 21 to 30, 32, 33 and 39 are
//     understood; a critical bit on any other one, notation data included, makes the signature not
//     count). A signature of another key is counted, never parsed beyond its issuer, and never makes
//     a refusal. If no user ID has a valid self-signature, the file is an [ErrForeignSelfSignature].
//
// A primary that carries a valid key revocation is not refused: it is reported
// ([ForeignPrimary.Revoked]). The reader reads no clock, so a key or a signature that has expired is
// reported with its dates and not refused.
//
// It returns no key with an error. The file is not changed and not kept: everything that the key
// holds is a copy, and the buffers that the reader made for an armoured file or for the secret are
// cleared before it returns. The caller clears its own copy of the file when it has no more use for
// it. Every fault is an [ErrForeignKey].
func ReadForeignKey(file []byte) (key *ForeignKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			key, err = nil, fail(ErrForeignForm, "the file could not be read")
		}
	}()
	return readForeignKey(file)
}

func readForeignKey(file []byte) (*ForeignKey, error) {
	if len(file) == 0 {
		return nil, fail(ErrForeignForm, "the file is empty")
	}
	if len(file) > MaxForeignKeyBytes {
		return nil, fail(ErrForeignLimit, "the file is longer than MaxForeignKeyBytes (%d bytes)", MaxForeignKeyBytes)
	}
	data := file
	if bytes.HasPrefix(file, []byte(armourLine)) {
		dec, err := readForeignArmour(file)
		if err != nil {
			return nil, err
		}
		defer clear(dec[:cap(dec)])
		data = dec
	}
	w, err := walkForeign(data)
	if err != nil {
		return nil, err
	}
	v, err := newForeignVerifier(w)
	if err != nil {
		return nil, err
	}
	k := &ForeignKey{cert: w.cert, pub: w.pub, prot: w.prot}
	k.Primary = ForeignPrimary{
		Fingerprint: v.fpHex,
		KeyID:       v.idHex,
		Algorithm:   w.pub.alg,
		Created:     w.pub.created,
		Secret:      w.prot.state(),
		Cipher:      w.prot.cipherName(),
	}
	k.KeySignatures, k.OtherKeySignatures = v.keyLevel(w)
	for _, s := range k.KeySignatures {
		if s.Type == sigKeyRevocation && s.Status == SignatureValid {
			k.Primary.Revoked = true
		}
	}
	valid := 0
	k.UserIDs, valid = v.userIDs(w)
	k.Subkeys = v.subkeys(w)
	k.UserAttributes, k.UserAttributeBytes = w.attrs, w.attrBytes
	if valid == 0 {
		return nil, v.noSelfSignature(k.UserIDs)
	}
	if err := checkPublicOnly(k.cert, v.fp); err != nil {
		return nil, err
	}
	return k, nil
}

// checkPublicOnly is the read back of the certificate: it is whole packets from the first to the
// last, it starts with the primary key packet that has the given fingerprint, and it holds no secret
// key packet.
func checkPublicOnly(cert, fp []byte) error {
	rest := cert
	for n := 1; len(rest) > 0; n++ {
		tag, _, body, after, err := splitForeignPacket(rest, n)
		if err != nil || tag == tagSecretKey || tag == tagSecretSubkey || (n == 1 && tag != tagPublicKey) {
			return fail(ErrForeignForm, "the certificate does not read back as public packets")
		}
		if n == 1 {
			if got, err := foreignFingerprint(body); err != nil || !bytes.Equal(got, fp) {
				return fail(ErrForeignForm, "the certificate does not read back as the primary that was read")
			}
		}
		rest = after
	}
	return nil
}

// noSelfSignature is the refusal of a key none of whose user IDs has a valid self-signature. Its
// text counts the self-signatures by what the reader made of them, and holds no user ID.
func (v *fkVerifier) noSelfSignature(ids []ForeignUserID) error {
	var counts [SignatureMisplaced + 1]int
	for _, u := range ids {
		for _, s := range u.Signatures {
			if s.Type >= 0x10 && s.Type <= 0x13 {
				counts[s.Status]++
			}
		}
	}
	return fail(ErrForeignSelfSignature, "%d user IDs; self-signatures: %d with a weak hash, %d with a hash that is not accepted, %d with an unknown critical subpacket, %d that do not verify, %d unreadable",
		len(ids), counts[SignatureWeakHash], counts[SignatureHashNotAccepted], counts[SignatureUnknownCritical],
		counts[SignatureNotVerified], counts[SignatureUnreadable]+counts[SignatureMisplaced])
}

// goCryptoPublic reads a public key packet with go-crypto, the second reader of the key.
func goCryptoPublic(pkt []byte) (*packet.PublicKey, error) {
	p, err := packet.Read(bytes.NewReader(pkt))
	if err != nil {
		return nil, err
	}
	pk, ok := p.(*packet.PublicKey)
	if !ok || pk.Version != 4 {
		return nil, fmt.Errorf("not a version 4 public key")
	}
	return pk, nil
}
