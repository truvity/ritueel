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
	// MaxForeignUserIDBytes is the most bytes of the body of one user ID packet: 2048. A photograph is a
	// user attribute packet, and keeps the limit of [MaxForeignPacketBytes].
	MaxForeignUserIDBytes = 2048
	// MaxForeignHashedBytes is the most bytes that the checks of signatures may hash in one file:
	// 512 MiB, counted before each check (the data that a signature covers, for the hash tag and for
	// go-crypto's verification, and once more for a binding that is also judged with its back-signature).
	// A key with a photograph of a few hundred kilobytes and thirty self-signatures on it hashes tens
	// of megabytes, so it passes many times over; the worst case that the limit allows is about a
	// second of hashing on an ordinary machine. A file that would pass it is refused.
	MaxForeignHashedBytes = 512 << 20
	// MaxForeignVerifications is the most public-key verifications of signatures in one file: 4096,
	// counted before each one. A self-signature costs one. A binding costs three: the check of its
	// signature and the strict pass (which counts two: the binding, and the cross-signature inside it
	// for a subkey that can sign), and a back-signature costs one more for each distinct one of a subkey.
	// A twenty-year key with fifteen user IDs and thirty subkeys, re-signed every year, has 15 x 20 = 300
	// self-signatures and 30 x 20 = 600 bindings, which cost 300 + 600 x 3 = 2100 verifications; if
	// every binding had a back-signature of its own that is 600 more, 2700, below the limit. A rich key
	// that QA measured costs 75. The most that a file can ask is bounded by
	// this and not by the number of signatures.
	MaxForeignVerifications = 4096
	// MaxForeignClaimedSignatures is the most signatures in the whole file that the primary has to answer
	// for, which are the ones that are verified: those that name the primary, and the revocations and subkey bindings that
	// are not provably another key's: 2048, which a key re-signed every year for twenty years, with fifteen
	// user IDs and thirty subkeys, comes near. The certifications of other keys are only counted, and keep
	// the limit of [MaxForeignSignatures] for each component.
	MaxForeignClaimedSignatures = 2048
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
// made. SignatureValid and SignatureValidWeakHash count (see [SignatureStatus.Counts]); the others do not.
type SignatureStatus uint8

// The statuses of a signature, in the order that the reader decides them: the first that applies.
const (
	// SignatureValid is a version 4 signature that verifies with the primary key, with SHA-256,
	// SHA-384 or SHA-512, and no critical subpacket that the reader does not understand.
	SignatureValid SignatureStatus = iota + 1
	// SignatureValidWeakHash is such a signature made with SHA-1 that verifies. It counts: a SHA-1
	// signature still proves that the key made it, and keys of 2008 to 2016 (RSA-4096 among them) carry
	// no other. The user ID or the subkey that only has such signatures is flagged (the field WeakHash),
	// and the adoption of the key re-signs with a strong hash. go-crypto verifies a SHA-1 signature
	// without a setting for it, so no change of its use was needed.
	SignatureValidWeakHash
	// SignatureWeakHash is a signature made with MD5, RIPEMD-160 or another hash that is broken or
	// obsolete (not SHA-1: see SignatureValidWeakHash). It is present and does not count; it is not
	// verified.
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

// Counts tells whether a signature with this status counts: it verified.
func (s SignatureStatus) Counts() bool { return s == SignatureValid || s == SignatureValidWeakHash }

// String is a few words for the status.
func (s SignatureStatus) String() string {
	switch s {
	case SignatureValid:
		return "valid"
	case SignatureValidWeakHash:
		return "valid, weak hash"
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
// signature has none. A signature that does not count gives the fields that its hashed
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
	// does not refuse such a key: the caller decides. A key revocation is hard whatever its date.
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
	// Valid is true when at least one of Signatures is a certification that counts: a self-signature
	// that verifies (made with SHA-1 or a strong hash). Only a user ID with Valid true is in the
	// certificate. The primary may have made a self-signature that does not count: it has a critical
	// subpacket that the reader does not understand, a field that is repeated, more than 32 subpackets
	// in an area, or a hash that is not accepted (MD5, RIPEMD-160, SHA-224, SHA-3 and every hash that is
	// not SHA-1, SHA-256, SHA-384 or SHA-512). A user ID can thus be absent from the certificate although
	// the primary signed it: the view shows it, with the status of each of its signatures.
	Valid bool
	// WeakHash is true when Valid is true and no self-signature that counts is strong: the fields above
	// come from a SHA-1 self-signature (status [SignatureValidWeakHash]). The key is accepted, and the adoption re-signs with a strong hash.
	WeakHash bool
	// Created is the creation time of the self-signature that gives the fields: the newest strong one
	// when there is one, else the newest weak one (the later one in the file among equal times). The
	// fields below are read from that signature.
	Created time.Time
	// KeyExpires is the key expiry that the newest valid self-signature gives, and zero if none.
	KeyExpires time.Time
	// KeyFlags is its first key flags octet.
	KeyFlags uint8
	// Primary is its primary user ID flag.
	Primary bool
	// Revoked is true when a hard certification revocation by the primary counts, whatever its date (no
	// reason, no reason specified, key material compromised, or a reason that is not known), or when a
	// soft one counts (superseded, retired, user ID no longer valid) that is not older than the newest
	// self-signature that counts, or that counts when there is none. A revocation in the same second as
	// a self-signature revokes: when in doubt it does.
	Revoked bool
	// RevokedAt is the creation time of the revocation that revokes.
	RevokedAt time.Time
	// UnreadableRevocations counts the certification revocations (type 0x30) in Signatures that the
	// primary claims and that the reader could not use: unreadable, with a critical subpacket that it
	// does not understand, or made with a hash that it does not take. A signature of this type that is
	// not provably another key's is in Signatures with its status, so that a revocation does not hide
	// behind a signature that cannot be read. A caller that adopts a key must look at this count.
	UnreadableRevocations int
	// Certifications counts the certifications (types 0x10 to 0x13) that other keys made on this user
	// ID. They are left out of the certificate and not verified: the reader does not have those keys.
	// A certification whose issuer cannot be read is counted here too.
	Certifications int
	// OtherRevocations counts the certification revocations (type 0x30) of other keys on this user ID: a
	// subset of OtherSignatures. A revocation by ANOTHER key was in the file and is not in the
	// certificate; the user ID may be revoked although the certificate does not show it. A caller that
	// adopts or publishes the key must ask the person when this count is not zero.
	OtherRevocations int
	// OtherSignatures counts the other signatures on this user ID that the primary does not claim: those
	// of other keys (a revocation by another key, for example), and those whose type cannot be read or is
	// not a certification or a revocation and whose issuer is not the primary's. They are left out of the
	// certificate and not verified.
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
	// Bound is true when at least one binding verifies (with SHA-1 or a strong hash). A binding of a
	// subkey that can sign needs its embedded back-signature, which go-crypto checks with it. A signing
	// subkey whose binding has no back-signature that verifies is in the certificate, with its
	// binding and without a back-signature, and is reported here as not bound.
	Bound bool
	// WeakHash is true when Bound is true and no binding that counts is strong: the fields come from a
	// SHA-1 binding.
	WeakHash bool
	// BoundAt is the creation time of the binding that gives the fields (the newest strong one when
	// there is one, else the newest weak one; the later one in the file among equal times), and Flags
	// and Expires are read from that binding: the first key flags octet, and
	// the end of the key counted from the creation of the subkey (zero if none).
	BoundAt time.Time
	Flags   uint8
	Expires time.Time
	// Revoked is true when a hard subkey revocation by the primary counts, whatever its date, or a soft
	// one that is not older than the newest binding that counts, or that counts when there is none (see
	// [ForeignUserID.Revoked] for the reasons).
	Revoked bool
	// UnreadableRevocations counts the subkey revocations (type 0x28) that the primary claims and that
	// the reader could not use (see [ForeignUserID.UnreadableRevocations]).
	UnreadableRevocations int
	// OtherRevocations counts the subkey revocations (type 0x28) of other keys on this subkey: a subset
	// of OtherSignatures. A revocation by ANOTHER key was in the file and is not in the certificate; the
	// subkey may be revoked although the certificate does not show it. A caller that adopts or
	// publishes the key must ask the person when this count is not zero.
	OtherRevocations int
	// OtherSignatures counts the signatures on this subkey that the primary does not claim, left out of
	// the certificate and not verified.
	OtherSignatures int
	// IncompleteBinding is true when a binding of the primary verifies over the public bytes of the subkey
	// and no binding is complete, so the subkey is left out of the certificate (InCertificate is false). A
	// binding is complete when it verifies and, if its key flags allow signing or certifying (0x02 or
	// 0x01), it carries a back-signature that verifies with the subkey's key. A binding with no key flags
	// subpacket asks for no back-signature, as go-crypto's strict pass does, which treats the signing
	// flag as false when the subpacket is absent. The library's key-ring reader refuses a whole certificate
	// that holds a signing subkey without a verifying back-signature, and other tools treat such a subkey
	// as unusable, so it is not written. The view keeps the Fingerprint and KeyID of such a subkey: its
	// public bytes were confirmed by a binding of the primary that verifies, and the caller needs to
	// name it to the person ("this subkey has a binding without a back-signature").
	IncompleteBinding bool
	// InCertificate is true when the subkey is in the certificate. A caller must look at a subkey for
	// which it is false: the subkey is not in the certificate, it has no Fingerprint or KeyID, and for
	// a public packet that the reader cannot read it has no Algorithm either. It is true when at least one binding of the primary
	// verifies over its public part (SHA-1 or stronger). A subkey that is not (no binding, a binding that
	// does not verify or is made with MD5, a public part that does not read) is left out whatever
	// packet it came in, and reported: its Fingerprint and KeyID are empty, because an unconfirmed
	// public part is not to be trusted, and the Algorithm and Created that are shown are those that
	// its packet claims.
	InCertificate bool
}

// ForeignKey is what the file of an exported secret key holds, read by [ReadForeignKey]. The exported
// fields are for reading: a caller that changes them changes nothing that the reader keeps. The
// secret of the primary is kept inside, in the form it had in the file, and [ForeignKey.Wipe]
// clears it. A ForeignKey is not safe for use by several goroutines at once (a Wipe against a call of
// OpenSecret or SecretPacket included: the caller serialises them), and it is used by its
// pointer: a copy of the struct shares the memory of the secret with the original, so the wipe of the
// original clears it for the copy too, and the copy then answers [ForeignKey.OpenSecret] with an
// error ([ErrForeignSecret] or [ErrWrongPassphrase]) and never with a key. A wipe of the copy does
// not mark the original as wiped.
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
	// OtherKeySignatures counts the signatures on the primary key itself that the primary does not
	// claim: left out of the certificate and not verified. OtherKeyRevocations counts the key
	// revocations (type 0x20) among them: a key revocation by ANOTHER key was in the file and is not in
	// the certificate. It may be the revocation of a designated revoker, so the key may be revoked
	// although the certificate does not show it. A caller that adopts or publishes the key must refuse,
	// or ask the person, when this count is not zero. A key revocation whose issuer cannot be read and
	// that does not verify with the primary's key is counted here too (a designated revoker's revocation
	// whose issuer was stripped looks like this), and likewise in OtherRevocations of a user ID and a
	// subkey.
	OtherKeySignatures  int
	OtherKeyRevocations int
	// UnreadableRevocations counts the key revocations (type 0x20) in KeySignatures that the primary
	// claims and that the reader could not use (see [ForeignUserID.UnreadableRevocations]). A caller that
	// adopts a key must look at it.
	UnreadableRevocations int
	// UserAttributes is the number of user attribute packets (photographs) and UserAttributeBytes
	// the total size of their bodies. They are not read. A user attribute is in the certificate only
	// with a certification by the primary that verifies over it and a body that is a well-formed sequence
	// of attribute subpackets (each with a valid length, running exactly to the end of the body), since
	// other readers refuse a certificate that holds one that is not. UserAttributesLeftOut counts the
	// distinct attributes that are not in it, for either reason, which a caller tells the person.
	// DuplicatesDropped counts what the certificate left out because the same thing was in the file
	// twice: a user ID, an attribute or a subkey with the same bytes (merged into the first, with their
	// verified signatures), and a signature written out twice for one part.
	DuplicatesDropped     int
	UserAttributes        int
	UserAttributeBytes    int
	UserAttributesLeftOut int

	cert  []byte
	pub   fkPublic
	prot  fkProtection // holds the secret of the primary as it stood in the file, until the wipe
	wiped bool
}

// Certificate returns the public certificate, binary: the part of the file that the primary's own
// signatures confirm, written by the reader. It is not the packets of the file. The reader writes
// every packet itself, with the shortest header of the new format, and puts into it only what a
// signature of the primary verifies, in the order of the standard:
//
//   - the public key packet of the primary, cut from the secret key packet and confirmed by its
//     self-signatures;
//   - each direct-key signature and key revocation of the primary that verifies;
//   - each user ID with at least one certification by the primary that verifies, then every
//     certification and certification revocation by the primary that verifies; each user attribute
//     the same way;
//   - each subkey, whatever packet it came in (secret, stub or public), with at least one binding by
//     the primary that verifies over its public bytes, written as a public subkey packet built from
//     the part that was confirmed, then every binding and subkey revocation by the primary that
//     verifies.
//
// The same holds for a direct-key signature, a user ID and a binding: one that the primary made but
// that does not count (an unknown critical subpacket, a repeated field, more than 32 subpackets in an
// area, or a hash that is not accepted, SHA-224 and SHA-3 included) is not in the certificate, and
// the view shows it with its status. A user ID, a user attribute or a subkey that appears twice with
// the same bytes is written once, with the verified signatures of both ([ForeignKey.DuplicatesDropped]).
//
// A signature is written again from the bytes that were verified: its version, type, algorithms and
// hashed area as they were hashed, its signature values (refused if they are not in the canonical form),
// and an unhashed area that the reader builds (the issuer of the primary, and a back-signature of a
// subkey that verified). Nothing else of the unhashed area of the file is carried over. SHA-1 signatures
// that verify count and are flagged in the view; MD5 and RIPEMD-160 signatures, signatures with a
// critical subpacket that the reader does not understand, and signatures that do not verify do not.
//
// What stays out, and is counted in the view so that a caller can tell the person: every certification
// and revocation by another key (the reader cannot verify them; other people's certifications remain
// where the person already has them, in their own keyring and on the key servers that keep them, and
// a caller that publishes the certificate publishes none of them), every signature that claims the primary and does not verify, a user ID or
// user attribute with no valid self-signature, a subkey with no valid binding, and the trust and marker
// packets, which are local to the tool that wrote them. The certificate thus has fewer packets than
// the file, and no byte that the primary did not sign, except within the value of a signature: an
// edited file cannot make the reader write into the certificate a byte that is not covered by a
// signature that verified, because the only bytes of the file that are copied are the content that such
// a signature covers and the signature values themselves, and the secret bytes of the file are in
// neither. It is a copy.
func (k *ForeignKey) Certificate() []byte {
	if k == nil {
		return nil
	}
	return bytes.Clone(k.cert)
}

// Wipe clears the secret that the key holds, and the key then opens nothing: [ForeignKey.OpenSecret]
// is an [ErrParams]. It does not clear the file that the caller gave to [ReadForeignKey], which holds
// the secret as it came: the caller clears its own buffer. The copies that an earlier [ForeignKey.OpenSecret]
// or [ForeignKey.SecretPacket] left in the standard library and in scratch space are not reachable from
// here ([ForeignSecret.Wipe] lists them). It is safe to call more than once, and [ForeignKey.Wiped] tells.
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
//     [ErrForeignLimit]; trust packets and marker packets are skipped; any other
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
//     skips the secret bytes of a subkey and never decrypts or keeps them; a malformed secret subkey
//     packet (an algorithm whose public part it cannot delimit, a public part out of the bounds, a
//     second parser that disagrees, a secret area that does not account for the packet, a version
//     other than 4) refuses the file ([ErrForeignAlgorithm], [ErrForeignForm], [ErrForeignVersion],
//     [ErrForeignProtection]); a subkey that no binding of the primary confirms is left out of the
//     certificate and reported ([ForeignSubkey.InCertificate]), never a reason to refuse the file;
//   - the signatures: a signature that the primary claims (its issuer fingerprint, or its issuer key
//     ID when there is no fingerprint) is read and verified with go-crypto, and counts only when it
//     is version 4, made with SHA-256, SHA-384, SHA-512 or SHA-1, and has no critical subpacket that
//     the reader does not understand (the subpackets 2, 3, 9, 11, 16, 21 to 30, 32, 33 and 39 are
//     understood; a critical bit on any other one, notation data included, makes the signature not
//     count). A SHA-1 signature that verifies counts with the status [SignatureValidWeakHash] and the
//     user ID or subkey that has only such signatures is flagged: such keys are common among RSA-4096
//     keys made from 2008 to 2016, a SHA-1 signature still proves that the key made it, and the
//     adoption re-signs with a strong hash. MD5 and RIPEMD-160 never count. A signature of another key
//     is counted, never parsed beyond its issuer, and never makes a refusal; a revocation (0x20, 0x28,
//     0x30) that is not provably another key's is read as the primary's and listed, so that it does not
//     hide behind a signature that cannot be read. At most [MaxForeignClaimedSignatures] signatures are
//     verified. If no user ID has a valid self-signature, the file is an [ErrForeignSelfSignature].
//
// A primary that carries a valid key revocation is not refused: it is reported
// ([ForeignPrimary.Revoked]). The reader reads no clock, so a key or a signature that has expired is
// reported with its dates and not refused.
//
// It returns no key with an error. The file is not changed and not kept: everything that the key
// holds is a copy. The buffer that the reader made for an armoured file is cleared before it returns,
// and so is the copy that it made of the secret of the primary on every return that does not hand the
// key back. When it hands the key back, that copy is kept inside the key by design, so that
// [ForeignKey.OpenSecret] can open it, until [ForeignKey.Wipe]. The caller clears its own copy of the
// file when it has no more use for it. Every fault is an [ErrForeignKey].
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
	done := false
	defer func() {
		if !done {
			w.clearSecret()
		}
	}()
	v, err := newForeignVerifier(w)
	if err != nil {
		return nil, err
	}
	if n := v.countClaimed(w); n > MaxForeignClaimedSignatures {
		return nil, fail(ErrForeignLimit, "the file has more than MaxForeignClaimedSignatures (%d) signatures that the primary has to answer for", MaxForeignClaimedSignatures)
	}
	k := &ForeignKey{pub: w.pub, prot: w.prot}
	out := &fkOutput{}
	k.Primary = ForeignPrimary{
		Fingerprint: v.fpHex,
		KeyID:       v.idHex,
		Algorithm:   w.pub.alg,
		Created:     w.pub.created,
		Secret:      w.prot.state(),
		Cipher:      w.prot.cipherName(),
	}
	k.KeySignatures, k.OtherKeySignatures, k.OtherKeyRevocations, k.UnreadableRevocations = v.keyLevel(w, out)
	for _, s := range k.KeySignatures {
		if s.Type == sigKeyRevocation && s.Status.Counts() {
			k.Primary.Revoked = true
		}
	}
	valid := 0
	k.UserIDs, valid, k.UserAttributesLeftOut = v.components(w, out)
	k.Subkeys = v.subkeys(w, out)
	k.UserAttributes, k.UserAttributeBytes = w.attrs, w.attrBytes
	if v.err != nil {
		return nil, v.err
	}
	if valid == 0 {
		return nil, v.noSelfSignature(k.UserIDs)
	}
	k.DuplicatesDropped = out.dups
	k.cert = out.assemble(w.primaryPacket)
	if err := checkPublicOnly(k.cert, v.fp); err != nil {
		return nil, err
	}
	done = true
	return k, nil
}

// checkPublicOnly is the read back of the certificate: it is whole packets from the first to the last,
// each with the shortest header of the new format, it starts with the primary key packet that has the given
// fingerprint, and the only other tags in it are public subkeys, user IDs, user attributes and signatures:
// no secret key packet, no trust packet, no packet of any other kind.
func checkPublicOnly(cert, fp []byte) error {
	rest := cert
	for n := 1; len(rest) > 0; n++ {
		tag, raw, body, after, err := splitForeignPacket(rest, n)
		ok := err == nil && bytes.Equal(raw, wrap(tag, body))
		if ok && n == 1 {
			got, ferr := foreignFingerprint(body)
			ok = tag == tagPublicKey && ferr == nil && bytes.Equal(got, fp)
		} else if ok {
			ok = tag == tagSubkey || tag == tagUserID || tag == tagUserAttribute || tag == tagSignature
		}
		if !ok {
			return fail(ErrForeignForm, "the certificate does not read back as the public packets that were written")
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
