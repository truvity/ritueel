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
	"hash"
	"math/big"
	"strconv"
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
func classifyPrimarySecret(region []byte) (p fkProtection, err error) {
	if len(region) == 0 {
		return p, fail(ErrForeignForm, "the secret key packet of the primary has no secret part")
	}
	usage := region[0]
	if usage == usageNone {
		if len(region) < 1+3+2 {
			return p, fail(ErrForeignForm, "the unprotected secret of the primary is cut short")
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
		return p, fail(ErrForeignForm, "the encrypted secret of the primary is shorter than its SHA-1 check and one number")
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

// ForeignSecret is the opened secret of the primary of a foreign key: a standard-library private key.
// Wipe clears it.
type ForeignSecret struct {
	key crypto.Signer
}

// Signer returns the private key as a [crypto.Signer]: an [*rsa.PrivateKey], an [ed25519.PrivateKey] or
// an [*ecdsa.PrivateKey] on P-384. It is the key itself, not a copy: [ForeignSecret.Wipe] clears it.
// It returns nil after the wipe.
func (s *ForeignSecret) Signer() crypto.Signer {
	if s == nil {
		return nil
	}
	return s.key
}

// Wipe clears the numbers of the private key, word by word, and drops it. A key that was used
// still has the copies that crypto/rsa, crypto/ecdsa and the garbage collector made, which are out
// of reach. It is safe to call more than once.
func (s *ForeignSecret) Wipe() {
	if s == nil {
		return
	}
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		wipeRSA(k)
	case ed25519.PrivateKey:
		clear(k)
	case *ecdsa.PrivateKey:
		wipePrivate(k)
	}
	s.key = nil
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

// OpenSecret opens the secret of the primary key and returns it as a standard-library private key. A
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
// the number u of the packet is the inverse of the first prime modulo the second; for Ed25519 the
// public key derived from the secret is the public key of the packet; for P-384 the secret is in
// the range of the group and the scalar times the base point is the point of the packet.
//
// The passphrase is read and never kept or copied by this code: the caller clears its own slice. The
// key that is derived from it, the decrypted bytes and every number that was made only to check the
// secret are cleared before the function returns, with the limits that [ForeignSecret.Wipe] names.
// The text of an error holds no byte of the secret or of the passphrase. It returns no key with an
// error.
func (k *ForeignKey) OpenSecret(passphrase []byte) (secret *ForeignSecret, err error) {
	defer func() {
		if r := recover(); r != nil {
			secret, err = nil, fail(ErrForeignSecret, "the secret could not be read")
		}
	}()
	if k == nil || k.wiped || len(k.prot.data) == 0 {
		return nil, fail(ErrParams, "the key has no secret to open: there is no key, or it was wiped, or it was not made by ReadForeignKey")
	}
	if len(passphrase) > MaxForeignPassphraseBytes {
		return nil, fail(ErrParams, "the passphrase is longer than MaxForeignPassphraseBytes (%d bytes)", MaxForeignPassphraseBytes)
	}
	var numbers []byte
	if k.prot.usage == usageNone {
		d := k.prot.data
		body, sum := d[:len(d)-2], d[len(d)-2:]
		if uint16(sum[0])<<8|uint16(sum[1]) != secretChecksum(body) {
			return nil, fail(ErrForeignSecret, "the checksum of the secret is wrong")
		}
		numbers = body
	} else {
		plain, err := k.decryptSecret(passphrase)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		numbers = plain[:len(plain)-sha1.Size]
	}
	key, err := foreignPrivateKey(k.pub, numbers)
	if err != nil {
		return nil, err
	}
	return &ForeignSecret{key: key}, nil
}

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
// the public part. numbers is not changed and not kept.
func foreignPrivateKey(pub fkPublic, numbers []byte) (crypto.Signer, error) {
	switch pub.alg.ID {
	case algoRSA:
		return rsaFromNumbers(pub, numbers)
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

func rsaFromNumbers(pub fkPublic, numbers []byte) (crypto.Signer, error) {
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
