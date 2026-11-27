package openpgp

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/big"
	"strconv"
	"sync"
	"time"
)

// This file reads and opens the secret of the primary key of a foreign key (RFC 9580, section
// 5.5.3 for the secret key packet, section 3.7.1.3 for the iterated and salted S2K). It parses the
// protection itself, so that every form that it does not take has a refusal of its own, and it
// derives the key and decrypts into buffers that it owns and clears. go-crypto is not used here:
// its S2K code copies the passphrase and its secret key reader keeps big numbers that this package
// could not clear.

const (
	usageNone     = 0
	usageSHA1     = 254
	usageChecksum = 255
	usageAEAD     = 253
	// s2kIterated is the S2K type of the iterated and salted form (RFC 9580, section 3.7.1.3), and
	// s2kGNU the private type that gpg uses for its extensions.
	s2kIterated = 3
	s2kGNU      = 101
	// aesBlock is the block size of AES, which is the size of the IV.
	aesBlock = 16
	// rsaPrimeMinBits and rsaPrimeMaxBits bound the two primes of an RSA-4096 key.
	rsaPrimeMinBits = 2040
	rsaPrimeMaxBits = 2056
	// maxRSASecretNumber is the most bytes of one of the numbers of an RSA secret: the modulus has 512.
	maxRSASecretNumber = 512
)

// fkProtection is the secret of the primary as it stood in the file, and how it is protected. It
// holds copies, so that the file can be cleared.
type fkProtection struct {
	usage  byte // usageNone or usageSHA1
	cipher byte // 7, 8 or 9 for usageSHA1
	hash   byte // the S2K hash, for usageSHA1
	salt   [8]byte
	count  byte
	iv     []byte
	data   []byte // usageNone: the numbers and their two-octet checksum; usageSHA1: the ciphertext
}

func (p fkProtection) state() SecretState {
	if p.usage == usageNone {
		return SecretUnprotected
	}
	return SecretProtected
}

func (p fkProtection) cipherName() string {
	if p.usage == usageNone {
		return ""
	}
	return map[byte]string{7: "AES-128", 8: "AES-192", 9: "AES-256"}[p.cipher]
}

// cipherKeySize is the key size of the AES variants of the standard (cipher numbers 7, 8 and 9).
func cipherKeySize(c byte) int {
	switch c {
	case 7:
		return 16
	case 8:
		return 24
	case 9:
		return 32
	}
	return 0
}

// s2kHashes are the hashes that the S2K may use: SHA-1, SHA-256, SHA-384, SHA-512 and SHA-224, by
// their numbers (RFC 9580, section 9.5). MD5, RIPEMD-160 and SHA-3 are not here: the standard
// library has no RIPEMD-160, and the others are not used by any tool that makes a key.
var s2kHashes = map[byte]func() hash.Hash{
	2:  sha1.New,
	8:  sha256.New,
	9:  sha512.New384,
	10: sha512.New,
	11: sha256.New224,
}

// cipherFault names a cipher that is not AES, for the refusal.
func cipherFault(c byte) string {
	names := map[byte]string{
		0:  "no cipher",
		1:  "IDEA",
		2:  "TripleDES",
		3:  "CAST5",
		4:  "Blowfish",
		10: "Twofish",
		11: "Camellia-128",
		12: "Camellia-192",
		13: "Camellia-256",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return "a cipher of number " + strconv.Itoa(int(c))
}

// hashFault names an S2K hash that the reader has not, for the refusal.
func hashFault(h byte) string {
	names := map[byte]string{1: "MD5", 3: "RIPEMD-160", 12: "SHA3-256", 14: "SHA3-512"}
	if n, ok := names[h]; ok {
		return n
	}
	return "a hash of number " + strconv.Itoa(int(h))
}

// classifyPrimarySecret reads what stands after the public part of the secret key packet of the
// primary and tells how the secret is protected, or refuses (RFC 9580, section 5.5.3). It copies
// what it keeps. The checks run in this order: no secret in the packet, usage 0, any usage that is
// not 254, then for usage 254 the cipher, the S2K type, the S2K hash and the lengths.
func classifyPrimarySecret(alg byte, region []byte) (p fkProtection, err error) {
	if len(region) == 0 {
		return p, fail(ErrForeignForm, "the secret key packet of the primary has no secret part")
	}
	usage := region[0]
	if usage == usageNone {
		if len(region) < 1+3+2 || !secretNumbersExact(alg, region[1:]) {
			return p, fail(ErrForeignForm, "the unprotected secret of the primary does not account for its packet")
		}
		p.data = bytes.Clone(region[1:])
		return p, nil
	}
	if usage == usageSHA1 || usage == usageChecksum {
		if len(region) < 3 {
			return p, fail(ErrForeignForm, "the protection of the secret of the primary is cut short")
		}
		if region[2] == s2kGNU {
			return p, gnuFault(region)
		}
	}
	switch usage {
	case usageChecksum:
		return p, fail(ErrForeignProtection, "S2K usage 255, which checks a two-octet sum and not the SHA-1 hash of the standard")
	case usageAEAD:
		return p, fail(ErrForeignProtection, "S2K usage 253 (an AEAD form)")
	case usageSHA1:
		return classifyProtected(region)
	}
	return p, fail(ErrForeignProtection, "an S2K usage that is a cipher number (%d), the old form with an MD5 hash", usage)
}

// gnuFault is the refusal of a primary whose secret is not in the file: the GNU extension of gpg
// (S2K type 101, the three letters, a mode). Mode 1 is a dummy, mode 2 is a card; for a card the
// serial number follows, which is not read and not shown.
func gnuFault(region []byte) error {
	if len(region) < 8 || string(region[4:7]) != "GNU" {
		return fail(ErrForeignProtection, "a private S2K type (101) that is not the GNU extension")
	}
	switch region[7] {
	case 1:
		return fail(ErrForeignNoSecret, "a GNU dummy: the secret is kept elsewhere")
	case 2:
		return fail(ErrForeignNoSecret, "a GNU card stub: the secret is on a smartcard")
	}
	return fail(ErrForeignNoSecret, "a GNU extension of mode %d: the secret is not in this file", region[7])
}

// checkSecretArea holds what follows the public part of the secret key packet of a subkey of algorithm
// alg to be a secret area of a known form that accounts for the packet (RFC 9580, section 5.5.3), and
// tells whether it is the GNU stub, which says the secret is not in the file. It keeps nothing and
// reads no value: it walks lengths. Only the usage octets 0, 253, 254 and 255 are a start: any other
// is the old form that names a cipher directly (with an MD5 key) and is an [ErrForeignProtection]. Then:
//
//   - usage 0: the secret numbers of the algorithm, each with its length field, and the two-octet
//     checksum must end exactly at the end of the packet ([secretNumbersExact]);
//   - usage 254 and 255: the cipher is one that the standard names, the S2K specifier is complete for
//     its type, and unless it is the GNU stub the IV has the block size of the cipher and at least the
//     check value follows (20 octets for 254, 2 for 255);
//   - usage 253: the cipher is named and the S2K specifier is complete.
//
// The cut that the public part made is thereby confirmed from the far end of the packet too. Any
// other fault is an [ErrForeignForm].
func checkSecretArea(alg byte, region []byte) (stub bool, err error) {
	bad := func() error {
		return fail(ErrForeignForm, "what follows the public part of a secret subkey is not a secret area that accounts for its packet")
	}
	if len(region) == 0 {
		return false, fail(ErrForeignForm, "the secret key packet of a subkey has no secret part")
	}
	switch u := region[0]; u {
	case usageNone:
		if !secretNumbersExact(alg, region[1:]) {
			return false, bad()
		}
		return false, nil
	case usageSHA1, usageChecksum, usageAEAD:
		return checkProtectedArea(u, region, bad)
	}
	return false, fail(ErrForeignProtection, "a secret subkey is protected with the legacy S2K usage %d, which names a cipher directly and is not read", region[0])
}

// checkProtectedArea is checkSecretArea for the usages 253, 254 and 255.
func checkProtectedArea(u byte, region []byte, bad func() error) (stub bool, err error) {
	off := 2
	if u == usageAEAD {
		off = 3
	}
	if len(region) <= off {
		return false, bad()
	}
	n, gnu, ok := s2kSpecLen(region[off:])
	if !ok {
		return false, bad()
	}
	if gnu {
		return u != usageAEAD, nil
	}
	block := cipherBlockSize(region[1])
	if block == 0 {
		return false, bad()
	}
	if u == usageAEAD {
		return false, nil
	}
	rest := len(region) - off - n
	check := sha1.Size
	if u == usageChecksum {
		check = 2
	}
	if rest < block+check {
		return false, bad()
	}
	return false, nil
}

// cipherBlockSize is the block size of the ciphers that the standard names (RFC 9580, section 9.3):
// 8 for IDEA, TripleDES, CAST5 and Blowfish, 16 for AES, Twofish and Camellia, and 0 for anything else.
func cipherBlockSize(c byte) int {
	switch {
	case c >= 1 && c <= 4:
		return 8
	case c >= 7 && c <= 13:
		return 16
	}
	return 0
}

// s2kSpecLen tells whether b starts with an S2K specifier that is complete for its type (types 0, 1, 3, 4
// and the GNU type 101 with its three letters), its length, and whether it is the GNU extension. The
// GNU specifier is counted as its six fixed octets: a serial number that may follow is not looked at.
func s2kSpecLen(b []byte) (n int, gnu, ok bool) {
	n = map[byte]int{0: 2, 1: 10, s2kIterated: 11, 4: 20, s2kGNU: 6}[b[0]]
	if n == 0 || len(b) < n {
		return 0, false, false
	}
	if b[0] == s2kGNU {
		return n, true, string(b[2:5]) == "GNU"
	}
	return n, false, true
}

// secretNumbersExact walks the length fields of the unprotected secret of a key of algorithm alg, which
// is what follows its usage octet: the numbers of the algorithm (four for RSA, one for ElGamal, DSA,
// ECDSA, ECDH and EdDSA legacy, the fixed size of a native key), then the two-octet checksum, and it
// tells whether that ends exactly at the end of the packet. It keeps and reads no value.
func secretNumbersExact(alg byte, b []byte) bool {
	numbers := 1
	switch alg {
	case algoRSA, algoRSAEncrypt, algoRSASign:
		numbers = 4
	case algoX25519, algoEd25519:
		return len(b) == 32+2
	case algoX448:
		return len(b) == 56+2
	case algoEd448:
		return len(b) == 57+2
	}
	for i := 0; i < numbers; i++ {
		if len(b) < 2 {
			return false
		}
		bits := int(binary.BigEndian.Uint16(b))
		n := (bits + 7) / 8
		if bits == 0 || len(b) < 2+n {
			return false
		}
		b = b[2+n:]
	}
	return len(b) == 2
}

// classifyProtected reads usage 254: the cipher, the iterated and salted S2K, the IV and the
// ciphertext.
func classifyProtected(region []byte) (p fkProtection, err error) {
	p.usage = usageSHA1
	if cipherKeySize(region[1]) == 0 {
		return p, fail(ErrForeignProtection, "encrypted with %s: only AES-128, AES-192 and AES-256 are read", cipherFault(region[1]))
	}
	p.cipher = region[1]
	switch t := region[2]; t {
	case s2kIterated:
	case 0:
		return p, fail(ErrForeignProtection, "a simple S2K, which has no salt and no iteration")
	case 1:
		return p, fail(ErrForeignProtection, "a salted S2K with no iteration")
	case 4:
		return p, fail(ErrForeignProtection, "the Argon2 S2K")
	default:
		return p, fail(ErrForeignProtection, "an S2K of type %d, which is not known", t)
	}
	const head = 1 + 1 + 1 + 1 + 8 + 1 // usage, cipher, S2K type, hash, salt, count
	if len(region) < head+aesBlock {
		return p, fail(ErrForeignForm, "the protection of the secret of the primary is cut short")
	}
	if _, ok := s2kHashes[region[3]]; !ok {
		return p, fail(ErrForeignProtection, "an S2K with %s: only SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 are read", hashFault(region[3]))
	}
	p.hash = region[3]
	copy(p.salt[:], region[4:12])
	p.count = region[12]
	p.iv = bytes.Clone(region[head : head+aesBlock])
	p.data = bytes.Clone(region[head+aesBlock:])
	if len(p.data) < sha1.Size+3 {
		clear(p.iv)
		clear(p.data)
		return fkProtection{}, fail(ErrForeignForm, "the encrypted secret of the primary is shorter than its SHA-1 check and one number")
	}
	return p, nil
}

// s2kCount is the number of octets that an iterated S2K hashes, from its one-octet code (RFC 9580,
// section 3.7.1.3).
func s2kCount(c byte) int { return (16 + int(c&15)) << (uint32(c>>4) + 6) }

// iteratedKey writes into out the key of the iterated and salted S2K (RFC 9580, section 3.7.1.3): the
// salt and the passphrase repeated until count octets are hashed, and the whole of one unit at least.
// A key longer than a digest takes one more hash for each digest, preloaded with one more zero octet.
// The passphrase is written to the hash from the caller's slice and is not copied. The digests are
// cleared; what the hash keeps inside until it is dropped is out of reach.
func iteratedKey(newHash func() hash.Hash, salt, pass []byte, count int, out []byte) {
	unit := len(salt) + len(pass)
	if count < unit {
		count = unit
	}
	var zeros [8]byte
	for done, i := 0, 0; done < len(out); i++ {
		h := newHash()
		h.Write(zeros[:i])
		left := count
		for ; left >= unit; left -= unit {
			h.Write(salt)
			h.Write(pass)
		}
		if left > len(salt) {
			h.Write(salt)
			h.Write(pass[:left-len(salt)])
		} else if left > 0 {
			h.Write(salt[:left])
		}
		sum := h.Sum(nil)
		done += copy(out[done:], sum)
		clear(sum)
	}
}

// ErrSecretWiped marks a signature that was asked of a key whose [ForeignSecret] was wiped. It is not an
// [ErrForeignKey].
var ErrSecretWiped = errors.New("openpgp: the secret key was wiped")

// ForeignSecret is the opened secret of the primary of a foreign key. It holds a standard-library
// private key and hands out only a [ForeignSigner] that uses it, so that [ForeignSecret.Wipe] can
// make the handle unusable. Copies of the key that crypto/rsa, crypto/ecdsa and the garbage collector
// made inside the standard library are out of reach, and may stay in memory until the process ends;
// Wipe clears what this package can reach: the numbers of the key, word by word, and drops the key.
type ForeignSecret struct {
	mu     sync.RWMutex // a signature holds the read lock; the wipe holds the write lock
	key    crypto.Signer
	signer *ForeignSigner
}

// ForeignSigner is a [crypto.Signer] that signs with the primary key of a foreign key until the
// [ForeignSecret] it came from is wiped, and then refuses every signature with [ErrSecretWiped]. It does
// not hand out the standard-library key. It may be used from several goroutines, and a wipe waits for a
// signature that is running and then ends them all. A later part that needs what only the concrete key offers, such as decrypting with an RSA key,
// would need a method added here; the primary of a person is certify-only and signs.
type ForeignSigner struct {
	secret *ForeignSecret
	pub    crypto.PublicKey
}

// Public returns the public key: an [*rsa.PublicKey], an [ed25519.PublicKey] or an [*ecdsa.PublicKey].
func (f *ForeignSigner) Public() crypto.PublicKey {
	if f == nil {
		return nil
	}
	return f.pub
}

// Sign signs digest as the key does, passing rand and opts through, or returns [ErrSecretWiped] after the
// wipe (and on a nil signer).
func (f *ForeignSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if f == nil || f.secret == nil {
		return nil, ErrSecretWiped
	}
	f.secret.mu.RLock()
	defer f.secret.mu.RUnlock()
	key := f.secret.key
	if key == nil {
		return nil, ErrSecretWiped
	}
	return key.Sign(rand, digest, opts)
}

// Signer returns the handle that signs with the private key, a [*ForeignSigner]. It is not the
// standard-library key and cannot be converted to it. It returns nil after the wipe. A handle
// that was returned before the wipe answers [ErrSecretWiped] afterwards.
func (s *ForeignSecret) Signer() crypto.Signer {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil
	}
	return s.signer
}

// Wipe clears the numbers of the private key, word by word, and drops it: every handle from
// [ForeignSecret.Signer] then refuses to sign. It does not clear what it cannot reach. Such a copy stays
// in memory as it is until the runtime happens to reuse that memory: the garbage collector frees it
// and does not erase it. They are:
//   - the copies that crypto/rsa, crypto/ecdsa and crypto/ed25519 made, among them one that the
//     validation of an RSA key builds and one that its precomputation builds;
//   - the scratch space of the big-number checks of the primes p and q (the primality test) and of
//     the number u, and of the inverse that makes u again when a packet is written with the primes
//     in the order of the standard;
//   - the hash state of the stretching of a passphrase, which holds blocks of the passphrase;
//   - the copies that the garbage collector moved.
//
// One opening of a secret makes each of these once, and a caller that opens the same key several times
// leaves several. It is safe to call more than once.
func (s *ForeignSecret) Wipe() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wipeKey(s.key)
	s.key = nil
}

// wipeKey clears the numbers of a private key that this package made, word by word.
func wipeKey(key crypto.Signer) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		wipeRSA(k)
	case ed25519.PrivateKey:
		clear(k)
	case *ecdsa.PrivateKey:
		wipePrivate(k)
	}
}

// newForeignSecret wraps a key.
func newForeignSecret(key crypto.Signer) *ForeignSecret {
	s := &ForeignSecret{key: key}
	s.signer = &ForeignSigner{secret: s, pub: key.Public()}
	return s
}

// wipeInt sets a number to zero, word by word.
func wipeInt(n *big.Int) {
	if n == nil {
		return
	}
	clear(n.Bits())
	n.SetInt64(0)
}

// wipeRSA clears the secret numbers of an RSA key and the values precomputed from them. The key has two
// primes, so its CRTValues, which only a key of more primes fills, are empty.
func wipeRSA(k *rsa.PrivateKey) {
	if k == nil {
		return
	}
	wipeInt(k.D)
	for _, p := range k.Primes {
		wipeInt(p)
	}
	wipeInt(k.Precomputed.Dp)
	wipeInt(k.Precomputed.Dq)
	wipeInt(k.Precomputed.Qinv)
}

// OpenSecret opens the secret of the primary key and returns it as a [ForeignSecret], whose signer holds
// a standard-library private key and does not hand it out. A
// protected secret is decrypted with the passphrase (S2K usage 254, AES in CFB mode, the SHA-1 check
// of RFC 9580 section 5.5.3); an unprotected secret ignores the passphrase, which may be nil. It
// never opens the secret of a subkey.
//
// The checks run in this order. A nil or wiped key, or a passphrase over [MaxForeignPassphraseBytes],
// is an [ErrParams]. The SHA-1 check of a protected secret that fails is an [ErrWrongPassphrase]:
// the standard gives no way to tell a wrong passphrase from a damaged ciphertext, since both fail
// that one check. After it, or for an unprotected secret after its two-octet checksum (an
// [ErrForeignSecret] when it is wrong), the numbers must read to their end in the form of RFC 9580
// section 3.2, and the secret must be the secret of the public key in the same packet, or the
// result is an ErrForeignSecret: for RSA the primes multiply to the modulus, the key validates and
// the number u of the packet is the inverse of the first prime modulo the second (the standard asks for
// p below q, but an export may have the other order, and it is taken when u matches the order that it
// has; p = q is refused, because the first prime has no inverse modulo itself); for Ed25519 the
// public key derived from the secret is the public key of the packet; for P-384 the secret is in
// the range of the group and the scalar times the base point is the point of the packet.
//
// The passphrase is read and never kept or copied by this code: the caller clears its own slice. The
// key that is derived from it, the decrypted bytes and every number that was made only to check the
// secret are cleared before the function returns, with the limits that [ForeignSecret.Wipe] names.
// The scratch space of those checks and the state of the hash that stretched the passphrase are
// among what it cannot clear.
// The text of an error holds no byte of the secret or of the passphrase. It returns no key with an
// error.
func (k *ForeignKey) OpenSecret(passphrase []byte) (secret *ForeignSecret, err error) {
	defer func() {
		if r := recover(); r != nil {
			secret, err = nil, fail(ErrForeignSecret, "the secret could not be read")
		}
	}()
	var key crypto.Signer
	err = k.withNumbers(passphrase, func(numbers []byte) (err error) {
		key, err = foreignPrivateKey(k.pub, numbers, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	return newForeignSecret(key), nil
}

// withNumbers opens the secret region of the primary as [ForeignKey.OpenSecret] says (the checks
// of its first paragraph, the checksum or the SHA-1 check) and hands the numbers of the secret to
// use, which must not keep them. The buffer that held them is cleared before it returns. The
// numbers are not yet checked against the public part: that is for use.
func (k *ForeignKey) withNumbers(passphrase []byte, use func(numbers []byte) error) error {
	if k == nil || k.wiped || len(k.prot.data) == 0 {
		return fail(ErrParams, "the key has no secret to open: there is no key, or it was wiped, or it was not made by ReadForeignKey")
	}
	if len(passphrase) > MaxForeignPassphraseBytes {
		return fail(ErrParams, "the passphrase is longer than MaxForeignPassphraseBytes (%d bytes)", MaxForeignPassphraseBytes)
	}
	if k.prot.usage == usageNone {
		d := k.prot.data
		body, sum := d[:len(d)-2], d[len(d)-2:]
		if uint16(sum[0])<<8|uint16(sum[1]) != secretChecksum(body) {
			return fail(ErrForeignSecret, "the checksum of the secret is wrong")
		}
		return use(body)
	}
	plain, err := k.decryptSecret(passphrase)
	if err != nil {
		return err
	}
	defer clear(plain)
	return use(plain[:len(plain)-sha1.Size])
}

// Wiped says whether [ForeignKey.Wipe] was called on the key, so that a caller can refuse a key that
// has no secret to give before it asks a person for a passphrase. A nil key is wiped. It does not say
// that the key has a secret: a ForeignKey that [ReadForeignKey] did not make is not wiped and opens
// nothing. Like the rest of the type, it is not safe against a call of Wipe from another goroutine.
func (k *ForeignKey) Wiped() bool { return k == nil || k.wiped }

// decryptSecret derives the key, decrypts the ciphertext into a buffer of its own and checks its
// SHA-1 hash in constant time. The buffer is returned whole, hash included, for the caller to clear;
// on a wrong passphrase it is cleared here.
func (k *ForeignKey) decryptSecret(passphrase []byte) ([]byte, error) {
	p := k.prot
	key := make([]byte, cipherKeySize(p.cipher))
	defer clear(key)
	iteratedKey(s2kHashes[p.hash], p.salt[:], passphrase, s2kCount(p.count), key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fail(ErrForeignSecret, "the key of the secret is not an AES key")
	}
	//nolint:staticcheck // the secret key packet is CFB by the standard (RFC 9580, section 3.7.2.1); the SHA-1 check below is its integrity check
	stream := cipher.NewCFBDecrypter(block, p.iv)
	plain := make([]byte, len(p.data))
	stream.XORKeyStream(plain, p.data)
	cut := len(plain) - sha1.Size
	sum := sha1.Sum(plain[:cut])
	ok := subtle.ConstantTimeCompare(sum[:], plain[cut:]) == 1
	clear(sum[:])
	if !ok {
		clear(plain)
		return nil, ErrWrongPassphrase
	}
	return plain, nil
}

// foreignPrivateKey turns the numbers of a secret into a standard-library key and checks them against
// the public part. numbers is not changed and not kept. strict only concerns RSA: the standard
// asks for p below q (RFC 9580, section 5.5.3, with u the inverse of p modulo q), and a strict reader
// refuses the other order, which a tolerant one takes when u matches the order that was given.
func foreignPrivateKey(pub fkPublic, numbers []byte, strict bool) (crypto.Signer, error) {
	switch pub.alg.ID {
	case algoRSA:
		return rsaFromNumbers(pub, numbers, strict)
	case algoEdDSA:
		return ed25519FromNumbers(pub, numbers)
	case algoECDSA:
		return p384FromNumbers(pub, numbers)
	}
	return nil, fail(ErrForeignSecret, "the algorithm of the primary has no secret that is read")
}

// scalarOf reads the one number of an EdDSA or ECDSA secret and left-pads it to size.
func scalarOf(numbers []byte, size int) ([]byte, error) {
	v, rest, err := readMPI(numbers)
	if err != nil || len(rest) != 0 || len(v) > size {
		return nil, fail(ErrForeignSecret, "the secret is not one number of the size of the key")
	}
	out := make([]byte, size)
	copy(out[size-len(v):], v)
	return out, nil
}

func ed25519FromNumbers(pub fkPublic, numbers []byte) (crypto.Signer, error) {
	seed, err := scalarOf(numbers, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	if subtle.ConstantTimeCompare(priv[ed25519.SeedSize:], pub.point[1:]) != 1 {
		clear(priv)
		return nil, fail(ErrForeignSecret, "the secret is not the secret of the public key in the packet")
	}
	return priv, nil
}

func p384FromNumbers(pub fkPublic, numbers []byte) (crypto.Signer, error) {
	raw, err := scalarOf(numbers, secretScalarLen)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), raw)
	if err != nil {
		return nil, fail(ErrForeignSecret, "the secret is not a private key of the group P-384")
	}
	if own, err := pointBytes(&k.PublicKey); err != nil || !bytes.Equal(own, pub.point) {
		wipePrivate(k)
		return nil, fail(ErrForeignSecret, "the secret is not the secret of the public key in the packet")
	}
	return k, nil
}

// rsaFromNumbers reads d, p, q and u. With strict, p must be below q; without it either order is
// taken, with u the inverse of the first prime modulo the second as the order stands. p = q is
// refused in both: the first prime has no inverse modulo itself, so u cannot match ("the number u
// is not the inverse"), and with strict the order check refuses it first.
func rsaFromNumbers(pub fkPublic, numbers []byte, strict bool) (crypto.Signer, error) {
	var parts [4][]byte // d, p, q, u
	rest := numbers
	for i := range parts {
		var err error
		parts[i], rest, err = readMPI(rest)
		if err != nil || len(parts[i]) > maxRSASecretNumber {
			return nil, fail(ErrForeignSecret, "the secret is not the four numbers of an RSA key")
		}
	}
	if len(rest) != 0 {
		return nil, fail(ErrForeignSecret, "the secret has bytes after its four numbers")
	}
	e := new(big.Int).SetBytes(pub.rsaE)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() >= 1<<31 {
		return nil, fail(ErrForeignSecret, "the public exponent is not a number that crypto/rsa takes")
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(pub.rsaN), E: int(e.Int64())},
		D:         new(big.Int).SetBytes(parts[0]),
		Primes:    []*big.Int{new(big.Int).SetBytes(parts[1]), new(big.Int).SetBytes(parts[2])},
	}
	u := new(big.Int).SetBytes(parts[3])
	defer wipeInt(u)
	// The numbers are held to their canonical size, so that a secret has one spelling: u is the
	// inverse of p modulo q, which is below q by definition, and d is below the modulus. The
	// relations below hold for u + q, which nothing else bounds, and for d plus a multiple of the
	// exponent of the group. The standard library's Validate refuses d at or above the modulus too
	// (checked with Go 1.27), but this code does not lean on that. A d below the modulus is not
	// unique: programs take it modulo lambda or modulo phi, so no tighter bound is asked. A real
	// export meets both bounds: this function opens the secret of an export too, and no
	// program writes a u that is not below q or a d that is not below n.
	if strict && priv.Primes[0].Cmp(priv.Primes[1]) >= 0 {
		wipeRSA(priv)
		return nil, fail(ErrForeignSecret, "the primes of the secret are not in the order of the standard (p below q)")
	}
	if u.Cmp(priv.Primes[1]) >= 0 || priv.D.Cmp(priv.N) >= 0 {
		wipeRSA(priv)
		return nil, fail(ErrForeignSecret, "a number of the secret is not below its bound: d below the modulus, u below the second prime")
	}
	for _, q := range priv.Primes {
		if q.BitLen() < rsaPrimeMinBits || q.BitLen() > rsaPrimeMaxBits || !q.ProbablyPrime(20) {
			wipeRSA(priv)
			return nil, fail(ErrForeignSecret, "a prime of the secret is not a prime of 2040 to 2056 bits")
		}
	}
	if err := priv.Validate(); err != nil {
		wipeRSA(priv)
		return nil, fail(ErrForeignSecret, "the primes and the exponent do not make the key of the public part")
	}
	t := new(big.Int).Mul(u, priv.Primes[0])
	defer wipeInt(t)
	t.Mod(t, priv.Primes[1])
	if t.Cmp(big.NewInt(1)) != 0 {
		wipeRSA(priv)
		return nil, fail(ErrForeignSecret, "the number u of the packet is not the inverse of the first prime modulo the second")
	}
	priv.Precompute()
	return priv, nil
}

// MaxAdoptedPacketBytes is the most bytes that [OpenSecretPacket] reads: 2048. The lone secret key
// packet of the largest key that the reader takes is at most 1822 bytes (an RSA key with a modulus
// of 4096 bits, 3 bytes of exponent and the four secret numbers at their longest, with the
// three-octet header); a key that is read from an export has fewer when a number has fewer bytes.
// A longer input is an [ErrForeignLimit].
const MaxAdoptedPacketBytes = 2048

// AdoptedPublic is what the lone secret key packet of an adopted key says in public: the same
// facts that [ForeignPrimary] gives for the key in an export, so that a caller can compare the two.
type AdoptedPublic struct {
	// Fingerprint is the version 4 fingerprint: 40 lower-case hexadecimal digits.
	Fingerprint string
	// Created is the creation time of the key, in UTC.
	Created time.Time
	// Algorithm is RSA 4096, EdDSA on Ed25519 or ECDSA on P-384.
	Algorithm ForeignAlgorithm
	// PublicBody is the body of the public key packet of the primary: the version, the creation
	// time, the algorithm and its public numbers. It is a copy.
	PublicBody []byte
}

// PrimaryPublicBody returns the body of the first packet of a certificate, which must be a public
// key packet of version 4 (tag 6) whose body is the public part of a key and nothing else, in
// either header form. It reads the first packet only and judges no signature, user ID or subkey:
// the caller that compares a certificate with a key file asks for exactly this. A fault is an
// [ErrForeignForm], a packet over [MaxForeignPacketBytes] an [ErrForeignLimit]. It is a copy.
func PrimaryPublicBody(cert []byte) (body []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			body, err = nil, fail(ErrForeignForm, "the certificate could not be read")
		}
	}()
	if len(cert) == 0 {
		return nil, fail(ErrForeignForm, "the certificate is empty")
	}
	tag, _, b, _, err := splitForeignPacket(cert, 1)
	if err != nil {
		return nil, err
	}
	if tag != tagPublicKey {
		return nil, fail(ErrForeignForm, "the first packet of the certificate is not a public key packet (%s)", tagName(tag))
	}
	if _, err := parseForeignPublic("the primary key of the certificate", b, true, true); err != nil {
		return nil, err
	}
	return bytes.Clone(b), nil
}

// SecretPacket returns the secret of the primary key as ONE OpenPGP secret key packet (RFC 9580,
// section 5.5.3): tag 5, version 4, the shortest header of the new format that this package writes,
// the public part of the primary as it is in the certificate, S2K usage 0 (not protected inside)
// and the secret numbers with their two-octet checksum. It has no user ID, no signature and no
// subkey. Its public part is byte for byte the body of the first packet of [ForeignKey.Certificate].
// A caller that keeps it keeps it under its own protection and clears it.
//
// The packet is always in the canonical form of the standard. An RSA export that has its primes in the
// other order (p above q, which some programs write) is read as it stands, and written with p below q
// and u made again for that order, so that one key has one spelling in a key file.
//
// The secret is opened with passphrase as [ForeignKey.OpenSecret] opens it, with the same checks
// and refusals (a passphrase that is nil or empty does for a secret that is not protected), and
// the numbers must be those of the public key, as there. The packet is read back with
// [OpenSecretPacket] before it is returned. The key is nil, wiped or not made by [ReadForeignKey]:
// an [ErrParams]. Nothing is returned with an error; the text of an error holds no byte of the
// secret or of the passphrase. The buffers that hold the numbers are cleared before it returns,
// with the limits that [ForeignSecret.Wipe] names; the packet itself is the caller's to clear.
func (k *ForeignKey) SecretPacket(passphrase []byte) (pkt []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			clear(pkt)
			pkt, err = nil, fail(ErrForeignSecret, "the secret packet could not be written")
		}
	}()
	if k == nil {
		return nil, fail(ErrParams, "the key has no secret to open: there is no key")
	}
	pubBody, err := k.publicBody()
	if err != nil {
		return nil, err
	}
	err = k.withNumbers(passphrase, func(numbers []byte) error {
		// The numbers must be the secret of the public part, with the checks of OpenSecret, and they
		// are judged first, as they stand. Only then is an RSA export that has p above q put in the
		// order of the standard (which asks for no size that was not checked), and that result is
		// checked again. An RSA secret with p below q has passed the only check that it needs.
		canon, checked := numbers, false
		if k.pub.alg.ID == algoRSA {
			key, err := foreignPrivateKey(k.pub, numbers, false)
			if err != nil {
				return err
			}
			wipeKey(key)
			re, err := canonicalRSANumbers(numbers)
			if err != nil {
				return err
			}
			if re != nil {
				defer clear(re)
				canon = re
			} else {
				checked = true // p below q: p = q was refused above
			}
		}
		if !checked {
			key, err := foreignPrivateKey(k.pub, canon, true)
			if err != nil {
				return err
			}
			wipeKey(key)
		}
		pkt = secretPacketOf(pubBody, canon)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(pkt) > MaxAdoptedPacketBytes {
		clear(pkt)
		return nil, fail(ErrForeignLimit, "the secret packet is longer than MaxAdoptedPacketBytes (%d bytes)", MaxAdoptedPacketBytes)
	}
	secret, pub, err := OpenSecretPacket(pkt)
	if err != nil {
		clear(pkt)
		return nil, fail(ErrForeignSecret, "the secret packet does not read back as it was written")
	}
	secret.Wipe()
	if pub.Fingerprint != k.Primary.Fingerprint || !bytes.Equal(pub.PublicBody, pubBody) {
		clear(pkt)
		return nil, fail(ErrForeignSecret, "the secret packet does not read back as the key of the certificate")
	}
	return pkt, nil
}

// canonicalRSANumbers puts the four numbers of an RSA secret in the order of the standard. When p is
// below q (or equal, which the checks that follow refuse) it returns nil: the numbers stand as they
// are. When p is above q it returns new numbers, in a buffer of its own for the caller to clear: d, the
// two primes swapped, and u made again as the inverse of the new first prime modulo the new second. It
// does not judge the numbers: the caller checks the result against the public part, and the order as
// it stood before. The big numbers that it makes are cleared, with the limits that
// [ForeignSecret.Wipe] names.
func canonicalRSANumbers(numbers []byte) ([]byte, error) {
	var parts [4][]byte
	rest := numbers
	for i := range parts {
		var err error
		if parts[i], rest, err = readMPI(rest); err != nil {
			return nil, fail(ErrForeignSecret, "the secret is not the four numbers of an RSA key")
		}
	}
	if len(rest) != 0 {
		return nil, fail(ErrForeignSecret, "the secret has bytes after its four numbers")
	}
	for _, v := range parts {
		if len(v) > maxRSASecretNumber {
			return nil, fail(ErrForeignSecret, "the secret is not the four numbers of an RSA key")
		}
	}
	p, q := new(big.Int).SetBytes(parts[1]), new(big.Int).SetBytes(parts[2])
	defer wipeInt(p)
	defer wipeInt(q)
	if p.Cmp(q) <= 0 {
		return nil, nil
	}
	u := new(big.Int).ModInverse(q, p)
	if u == nil {
		return nil, fail(ErrForeignSecret, "the primes of the secret have no inverse of one modulo the other")
	}
	defer wipeInt(u)
	// made at a size that the four numbers cannot pass (each is at most maxRSASecretNumber bytes, and
	// u is below p), and never grown: a number that would not fit is a failure, so that no growth
	// leaves a copy behind
	out := make([]byte, 0, 4*(2+maxRSASecretNumber))
	out = append(out, numbers[:2+len(parts[0])]...) // d, as it stands
	for _, v := range []*big.Int{q, p, u} {
		b := v.Bytes()
		if len(out)+2+len(b) > cap(out) {
			clear(b)
			clear(out)
			return nil, fail(ErrForeignSecret, "the secret is not the four numbers of an RSA key")
		}
		out = append(out, byte(v.BitLen()>>8), byte(v.BitLen()))
		out = append(out, b...)
		clear(b)
	}
	return out, nil
}

// publicBody is the body of the first packet of the certificate, the public key packet of the
// primary, checked to be the key that the reader named: its fingerprint is the one in Primary.
func (k *ForeignKey) publicBody() ([]byte, error) {
	body, err := PrimaryPublicBody(k.cert)
	if err != nil {
		return nil, fail(ErrParams, "the key has no certificate: it was not made by ReadForeignKey")
	}
	fp, err := foreignFingerprint(body)
	if err != nil {
		return nil, err
	}
	if full, _ := fingerprintHex(fp); full != k.Primary.Fingerprint {
		return nil, fail(ErrParams, "the certificate of the key is not the certificate of its primary: it was not made by ReadForeignKey")
	}
	return body, nil
}

// secretPacketOf writes the secret key packet of a public body and the secret numbers, with usage 0
// and the checksum. The buffer is made at its final size, so that no copy of the numbers is left
// behind by a growing slice.
func secretPacketOf(pubBody, numbers []byte) []byte {
	n := len(pubBody) + 1 + len(numbers) + 2
	head := header(tagSecretKey, n)
	out := make([]byte, 0, len(head)+n)
	out = append(out, head...)
	out = append(out, pubBody...)
	out = append(out, usageNone)
	out = append(out, numbers...)
	sum := secretChecksum(numbers)
	return append(out, byte(sum>>8), byte(sum))
}

// OpenSecretPacket reads exactly the packet that [ForeignKey.SecretPacket] writes, and nothing
// else, and returns the secret as a [ForeignSecret] and what the packet says in public. The input
// is at most [MaxAdoptedPacketBytes] (an [ErrForeignLimit] above it) and is one packet and no
// byte more; the packet has the tag 5 with the shortest header of the new format, version 4, one
// of the three algorithms of the reader with its size and curve rules (RSA with a modulus of 4096
// bits, EdDSA legacy on Ed25519, ECDSA on P-384), S2K usage 0 and a correct two-octet checksum; the
// numbers must read to their end and be the secret of the public part, with the checks of
// [ForeignKey.OpenSecret] (the primes and the number u of RSA, the public key derived from the
// seed of Ed25519, the point of the scalar of P-384); the RSA primes must be in the order of the
// standard, p below q (the writer of this package always writes them so, and a packet with p above q
// is an ErrForeignSecret, as is p = q); and a second reader (go-crypto) must read
// the public part as it is read here.
//
// Every other input is refused with the kinds of the reader of an export: a packet that is not
// one secret key packet, a header that is not the shortest, or a second packet or a trailing byte
// ([ErrForeignForm]); another tag ([ErrForeignPacket], and [ErrForeignNoSecret] for a public key
// packet); another version ([ErrForeignVersion]); another algorithm, size or curve
// ([ErrForeignAlgorithm]); a secret that is protected inside ([ErrForeignProtection]); a checksum
// that is wrong or numbers that are not the secret of the public part ([ErrForeignSecret]). No text
// holds a byte of the input. Nothing is returned with an error. The caller clears pkt: nothing of
// it is kept except in the numbers of the key, which [ForeignSecret.Wipe] clears with its limits.
func OpenSecretPacket(pkt []byte) (secret *ForeignSecret, pub AdoptedPublic, err error) {
	defer func() {
		if r := recover(); r != nil {
			secret, pub, err = nil, AdoptedPublic{}, fail(ErrForeignForm, "the secret key packet could not be read")
		}
	}()
	body, err := adoptedBody(pkt)
	if err != nil {
		return nil, AdoptedPublic{}, err
	}
	p, err := parseForeignPublic("the secret key packet", body, false, true)
	if err != nil {
		return nil, AdoptedPublic{}, err
	}
	if err := checkPrimary(p); err != nil {
		return nil, AdoptedPublic{}, err
	}
	pubBody, region := body[:p.length], body[p.length:]
	if len(region) == 0 {
		return nil, AdoptedPublic{}, fail(ErrForeignNoSecret, "the secret key packet has no secret part")
	}
	if region[0] != usageNone {
		return nil, AdoptedPublic{}, fail(ErrForeignProtection, "the secret of the packet is protected inside (S2K usage %d): a lone secret key packet holds it unprotected", region[0])
	}
	if len(region) < 1+3+2 || !secretNumbersExact(p.alg.ID, region[1:]) {
		return nil, AdoptedPublic{}, fail(ErrForeignForm, "the secret of the packet does not account for its bytes")
	}
	numbers, sum := region[1:len(region)-2], region[len(region)-2:]
	if uint16(sum[0])<<8|uint16(sum[1]) != secretChecksum(numbers) {
		return nil, AdoptedPublic{}, fail(ErrForeignSecret, "the checksum of the secret is wrong")
	}
	fp, err := foreignFingerprint(pubBody)
	if err != nil {
		return nil, AdoptedPublic{}, err
	}
	if _, err := agreePublic(wrap(tagPublicKey, pubBody), pubBody, fp, false); err != nil {
		return nil, AdoptedPublic{}, err
	}
	key, err := foreignPrivateKey(p, numbers, true)
	if err != nil {
		return nil, AdoptedPublic{}, err
	}
	full, _ := fingerprintHex(fp)
	return newForeignSecret(key), AdoptedPublic{
		Fingerprint: full,
		Created:     p.created,
		Algorithm:   p.alg,
		PublicBody:  bytes.Clone(pubBody),
	}, nil
}

// adoptedBody checks the frame of a lone secret key packet and returns its body: not empty and not
// over the limit, one packet with nothing after it, tag 5, and the shortest header of the new format.
func adoptedBody(pkt []byte) ([]byte, error) {
	if len(pkt) == 0 {
		return nil, fail(ErrForeignForm, "the secret key packet is empty")
	}
	if len(pkt) > MaxAdoptedPacketBytes {
		return nil, fail(ErrForeignLimit, "the secret key packet is longer than MaxAdoptedPacketBytes (%d bytes)", MaxAdoptedPacketBytes)
	}
	tag, raw, body, rest, err := splitForeignPacket(pkt, 1)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fail(ErrForeignForm, "the input is more than one packet: it holds %d bytes after the first", len(rest))
	}
	switch tag {
	case tagSecretKey:
	case tagPublicKey:
		return nil, fail(ErrForeignNoSecret, "the packet is a public key packet, which has no secret")
	case tagSecretSubkey, tagSubkey:
		return nil, fail(ErrForeignForm, "the packet is a subkey packet: a lone secret key packet is the primary")
	default:
		return nil, fail(ErrForeignPacket, "the packet is %s, not a secret key packet", tagName(tag))
	}
	if !bytes.Equal(raw, wrap(tagSecretKey, body)) {
		return nil, fail(ErrForeignForm, "the header of the secret key packet is not the shortest one of the new format")
	}
	return body, nil
}
