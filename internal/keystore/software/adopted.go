package software

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/openpgp"
)

// An adopted key is a person's existing OpenPGP primary (RSA-4096, EdDSA on Ed25519 or ECDSA on
// P-384) that ritueel keeps, as it is, in a key file of the passphrase mode (record 0008, rules 5
// and 6): the file `<label>.openpgp.key.age` holds the lone secret key packet that
// [openpgp.ForeignKey.SecretPacket] writes, under a new passphrase. The keys that ritueel makes are
// kept in the same file name as a whole transferable secret key with a user ID; the two readers tell
// the forms apart and each refuses the other.

// The algorithm numbers of RFC 9580, section 9.1, that an adopted key has.
const (
	algRSA   = 1
	algECDSA = 19
	algEdDSA = 22
)

// rsaCheckHash is the hash of the digest that the check of an RSA key signs, and ecdsaCheckHash the
// one of an ECDSA key.
const (
	rsaCheckHash   = crypto.SHA512
	ecdsaCheckHash = crypto.SHA384
	edCheckLen     = 32
)

// Expect is what a caller knows of the key that a key file must hold, from the bundle: the
// fingerprint and the creation time of root.json and the certificate. A zero Expect, or one with an
// empty member, is refused with an [ErrParams], and so is a certificate whose first packet is not the
// public key packet of a key.
type Expect struct {
	// Fingerprint is the version 4 fingerprint, 40 lower-case hexadecimal digits.
	Fingerprint string
	// Created is the creation time of the key.
	Created time.Time
	// Cert is the public certificate. Its first packet is the public key packet of the primary, and
	// the public part of the key in the file must be that packet's body, byte for byte. The rest of
	// the certificate is not read.
	Cert []byte
}

// adoptedFacts is what a key file must say in public, from an [Expect] or from an export.
type adoptedFacts struct {
	fingerprint string
	created     time.Time
	body        []byte
}

// facts checks an Expect and returns what it expects.
func (e Expect) facts() (adoptedFacts, error) {
	if e.Fingerprint == "" || e.Created.IsZero() || len(e.Cert) == 0 {
		return adoptedFacts{}, refuse(ErrParams, "what is expected of the key is empty, or one of its members is")
	}
	body, err := openpgp.PrimaryPublicBody(e.Cert)
	if err != nil {
		return adoptedFacts{}, refuse(ErrParams, "the certificate of what is expected does not start with the public key packet of a key")
	}
	return adoptedFacts{fingerprint: e.Fingerprint, created: e.Created, body: body}, nil
}

// differs names what of the three public facts of a key in a file is not what was expected, in the
// words of the refusal. It holds no byte of a key.
func (f adoptedFacts) differs(pub openpgp.AdoptedPublic) []string {
	var out []string
	if pub.Fingerprint != f.fingerprint {
		out = append(out, "the fingerprint")
	}
	if !pub.Created.Equal(f.created) {
		out = append(out, "the creation time")
	}
	if !bytes.Equal(pub.PublicBody, f.body) {
		out = append(out, "the public part")
	}
	return out
}

// isAdoptedForm says whether a payload is the lone secret key packet of an adopted key.
func isAdoptedForm(payload []byte) bool {
	secret, _, err := openpgp.OpenSecretPacket(payload)
	if err != nil {
		return false
	}
	secret.Wipe()
	return true
}

// isBornForm says whether a payload is the transferable secret key of a key that ritueel made.
func isBornForm(payload []byte) bool {
	priv, _, _, err := openpgp.ParseSecretKey(payload)
	if err != nil {
		return false
	}
	wipe(priv)
	return true
}

// errAdoptedPayload is the refusal of a payload that is not the lone secret key packet of an
// adopted key: it says which form it found, when it is the other one.
func errAdoptedPayload(payload []byte, err error) error {
	if isBornForm(payload) {
		return refuse(ErrKeyFile, "the file holds a key that ritueel made (a transferable secret key with a user ID), not an adopted key (a lone secret key packet)")
	}
	return fmt.Errorf("%w: the secret key packet of the file is refused: %w", ErrKeyFile, err)
}

// errAdoptedSource is the refusal of an export whose secret did not give the packet, in words that
// say which file did not open.
func errAdoptedSource(err error) error {
	switch {
	case errors.Is(err, openpgp.ErrWrongPassphrase):
		return fmt.Errorf("%w: the exported file did not open with its passphrase: %w", ErrWrongPassphrase, err)
	case errors.Is(err, openpgp.ErrParams):
		return fmt.Errorf("%w: the exported key cannot be opened: %w", ErrParams, err)
	}
	return fmt.Errorf("%w: the secret of the exported key is refused: %w", ErrKeyFile, err)
}

// SaveAdopted keeps the primary of an exported key: it writes `<label>.openpgp.key.age`, an age
// file of the passphrase mode whose payload is the lone secret key packet of fk
// ([openpgp.ForeignKey.SecretPacket]). It is not the kind of file of a born key, though the name
// is: the readers tell them apart.
//
// A store of the test mode refuses it with an [ErrParams]: an adopted key is never written without
// encryption. So do a nil key, a bad label and a nil context. A file of that name that stands
// is never replaced: the name is looked at before a passphrase is asked or a byte of the key is made,
// and the refusal is an [ErrKeyExists], as for every key of the store. A file of the other mode
// in the folder is an [ErrWrongMode].
//
// The source is asked for the passphrase of the exported file only when its secret is protected (the
// role [Import]), and always for the new passphrase of the key file (the role [Choose], held to the
// rules of [CheckPassphrase]); there is no passphrase in the parameters. A passphrase that did not
// open the export is an [ErrWrongPassphrase] whose text says that the exported file did not open; a
// secret of the export that is damaged is an [ErrKeyFile]. The store does not judge the history of
// the key: a revoked key, a key that other keys revoked and an expired key are for the ceremony of
// the adoption to refuse.
//
// After the write the file is read back as every file of the store is (byte for byte, then opened
// with the new passphrase); its payload is read with [openpgp.OpenSecretPacket]; the fingerprint,
// the creation time and the public part must be those of fk; and a signature over a random digest
// must verify with the public key. A fault of any of these is an [ErrKeyFile] whose text says that
// the file was written and failed its check, and names it: the file stays where it is, and nothing
// is deleted. A write that fails after the temporary file was made names that file too, as for the
// other keys.
//
// The packet is cleared after the write; the passphrases are cleared as the package clears them
// (see "Secrets in memory"). fk is not wiped: it is the caller's.
func (s *Store) SaveAdopted(ctx context.Context, label string, fk *openpgp.ForeignKey) error {
	if s == nil {
		return refuse(ErrParams, "the store was not made by Open")
	}
	if ctx == nil {
		return refuse(ErrParams, "the context is nil")
	}
	if !labelOK(label) {
		return errLabel
	}
	if fk == nil {
		return refuse(ErrParams, "there is no key to keep")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return err
	}
	if s.mode != ModePassphrase {
		return refuse(ErrParams, "an adopted key is never written without encryption: the store is not in the passphrase mode")
	}
	if s.stop != nil {
		return s.stop
	}
	body, err := openpgp.PrimaryPublicBody(fk.Certificate())
	if err != nil {
		return refuse(ErrParams, "the exported key has no certificate: it was not made by ReadForeignKey")
	}
	want := adoptedFacts{fingerprint: fk.Primary.Fingerprint, created: fk.Primary.Created, body: body}
	name, before, err := s.target(FileOpenPGP, label, "")
	if err != nil {
		return err
	}
	pkt, err := s.adoptedPacket(ctx, label, fk)
	if err != nil {
		return err
	}
	defer clear(pkt)
	return s.writeTo(ctx, name, before, Purpose{Label: label, File: FileOpenPGP, Role: Choose}, FileOpenPGP, pkt,
		func(payload []byte) error {
			k, err := readAdoptedPayload(payload, want, "the key file does not read back as the exported key")
			if err != nil {
				return err
			}
			defer func() { _ = k.Close() }()
			return k.selfCheck()
		}, nil)
}

// adoptedPacket opens the secret of an export as a lone secret key packet. It asks the source for
// the passphrase of the exported file only when the secret is protected. The caller holds the lock.
func (s *Store) adoptedPacket(ctx context.Context, label string, fk *openpgp.ForeignKey) ([]byte, error) {
	var pass []byte
	if fk.Primary.Secret == openpgp.SecretProtected {
		var err error
		if pass, err = s.passphrase(ctx, Purpose{Label: label, File: FileOpenPGP, Role: Import}); err != nil {
			return nil, err
		}
		defer clear(pass)
	}
	pkt, err := fk.SecretPacket(pass)
	if err != nil {
		return nil, errAdoptedSource(err)
	}
	return pkt, nil
}

// OpenAdopted opens the adopted key of a label. The file is opened with the passphrase of the key
// file (the zero role of the purpose), its payload is read with [openpgp.OpenSecretPacket], and
// before any signer is returned the fingerprint, the creation time and the public part are compared
// with want. A file of another key is an [ErrKeyFile] whose text says which of the three differ
// (the fingerprint, the creation time, the public part) and holds no byte of a key; a file of a key
// that ritueel made, the other form of the file, is an [ErrKeyFile] that says so; a file that is not
// there or not of the shape is an [ErrKeyFile], a passphrase that did not open it an
// [ErrWrongPassphrase], a file of the other mode an [ErrWrongMode]. A store of the test mode, a bad
// label, a nil context and a want that is empty in a member or whose certificate does not start with
// a key packet are an [ErrParams], before any passphrase is asked.
//
// The key is the caller's to close.
func (s *Store) OpenAdopted(ctx context.Context, label string, want Expect) (*AdoptedKey, error) {
	return s.openAdopted(ctx, label, want)
}

// CheckAdopted is the check of a restore drill on a copy of the key directory: it makes the checks
// of [Store.OpenAdopted], then signs a random digest and verifies the signature with the public key,
// then wipes the key. It returns no signer.
func (s *Store) CheckAdopted(ctx context.Context, label string, want Expect) error {
	k, err := s.openAdopted(ctx, label, want)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.selfCheck()
}

// openAdopted is OpenAdopted.
func (s *Store) openAdopted(ctx context.Context, label string, want Expect) (*AdoptedKey, error) {
	if s == nil {
		return nil, refuse(ErrParams, "the store was not made by Open")
	}
	if ctx == nil {
		return nil, refuse(ErrParams, "the context is nil")
	}
	if !labelOK(label) {
		return nil, errLabel
	}
	facts, err := want.facts()
	if err != nil {
		return nil, err
	}
	if err := s.needPassphraseMode(); err != nil {
		return nil, err
	}
	payload, err := s.read(ctx, FileOpenPGP, label, "")
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	return readAdoptedPayload(payload, facts, "the key file holds another key than the one expected")
}

// needPassphraseMode refuses a store that is not in the passphrase mode, which never holds an
// adopted key.
func (s *Store) needPassphraseMode() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return err
	}
	if s.mode != ModePassphrase {
		return refuse(ErrParams, "an adopted key is never kept without encryption: the store is not in the passphrase mode")
	}
	return nil
}

// readAdoptedPayload reads the lone secret key packet of a payload and compares its public facts
// with want. what opens the text of the refusal that says which fact differs.
func readAdoptedPayload(payload []byte, want adoptedFacts, what string) (*AdoptedKey, error) {
	secret, pub, err := openpgp.OpenSecretPacket(payload)
	if err != nil {
		return nil, errAdoptedPayload(payload, err)
	}
	if d := want.differs(pub); len(d) != 0 {
		secret.Wipe()
		return nil, refuse(ErrKeyFile, "%s: %s differ", what, strings.Join(d, ", "))
	}
	return newAdoptedKey(secret, pub)
}

// AdoptedKey is the key of a person that was adopted: a [crypto.Signer] over the secret that
// [Store.OpenAdopted] opened. It does not hold the raw key: it delegates to the signer of
// internal/openpgp, which keeps it. It does not implement [keystore.Key], whose contract is ECDSA on
// P-384 with SHA-384; it answers the rest of that interface (Kind, Copyable, Warnings, Close).
//
// Sign refuses what the key is not meant to sign before the secret is used: an RSA key signs PKCS#1
// version 1.5 with SHA-256, SHA-384 or SHA-512 and never PSS; an Ed25519 key signs the message as it
// is given, with the option crypto.Hash(0); a P-384 key signs a digest of the length of SHA-256,
// SHA-384 or SHA-512 and returns the ASN.1 value. Every signature is verified with the public key
// before it is returned. It prints as a fixed text under every verb and marshals to nothing, and
// every method is safe on a nil or zero *AdoptedKey.
//
// What [AdoptedKey.Close] clears: the numbers of the key, word by word, as [openpgp.ForeignSecret.Wipe]
// does, and the handle. Go does not promise that every copy of a secret is cleared: the copies that
// crypto/rsa, crypto/ecdsa and crypto/ed25519 made while the key was made and used, and those of the
// garbage collector, are out of reach, and a scan of the memory of a process after Close can still
// find the secret.
type AdoptedKey struct{ s *adoptedState }

// adoptedState is the state of an adopted key. A copy of the AdoptedKey shares it.
type adoptedState struct {
	mu          sync.Mutex
	secret      *openpgp.ForeignSecret
	signer      crypto.Signer
	pub         crypto.PublicKey // a copy, never handed out
	fingerprint string
	created     time.Time
	algorithm   openpgp.ForeignAlgorithm
	closed      bool
	// tamper, when set (by a test in this package), changes the signature after it was made and
	// before the key checks it.
	tamper func(sig []byte) []byte
}

// adoptedKeyText is what an adopted key prints as under every verb.
const adoptedKeyText = "adopted software key (private half not shown)"

// errAdoptedSignature marks a signature that the key made and that its own public key does not verify.
var errAdoptedSignature = errors.New("software: the signature does not verify with the key's own public key")

// newAdoptedKey wraps an opened secret. It wipes the secret and fails when the key is of a kind that
// the store does not sign with.
func newAdoptedKey(secret *openpgp.ForeignSecret, pub openpgp.AdoptedPublic) (*AdoptedKey, error) {
	signer := secret.Signer()
	var public crypto.PublicKey
	if signer != nil {
		public = publicCopy(signer.Public())
	}
	if signer == nil || public == nil || (pub.Algorithm.ID != algRSA && pub.Algorithm.ID != algEdDSA && pub.Algorithm.ID != algECDSA) {
		secret.Wipe()
		return nil, refuse(ErrKeyFile, "the key of the file is not one that the store signs with")
	}
	return &AdoptedKey{s: &adoptedState{
		secret:      secret,
		signer:      signer,
		pub:         public,
		fingerprint: pub.Fingerprint,
		created:     pub.Created,
		algorithm:   pub.Algorithm,
	}}, nil
}

// publicCopy returns a copy of a public key of the three kinds, or nil for another.
func publicCopy(pub crypto.PublicKey) crypto.PublicKey {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return nil
		}
		return &rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(k))
	case *ecdsa.PublicKey:
		if k == nil {
			return nil
		}
		point, err := k.Bytes()
		if err != nil {
			return nil
		}
		c, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
		if err != nil {
			return nil
		}
		return c
	}
	return nil
}

// state returns the state of the key, or nil for a nil or zero key.
func (k *AdoptedKey) state() *adoptedState {
	if k == nil {
		return nil
	}
	return k.s
}

// Format prints the fixed text whatever the verb is.
func (AdoptedKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, adoptedKeyText)
}

// Public returns a new public key on every call: an [*rsa.PublicKey], an [ed25519.PublicKey] or an
// [*ecdsa.PublicKey]. A closed, nil or zero key returns nil.
func (k *AdoptedKey) Public() crypto.PublicKey {
	s := k.state()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return publicCopy(s.pub)
}

// Fingerprint is the version 4 fingerprint of the key: 40 lower-case hexadecimal digits. It is
// empty for a nil or zero key and is kept after Close.
func (k *AdoptedKey) Fingerprint() string {
	if s := k.state(); s != nil {
		return s.fingerprint
	}
	return ""
}

// Created is the creation time of the key, in UTC, which its fingerprint covers.
func (k *AdoptedKey) Created() time.Time {
	if s := k.state(); s != nil {
		return s.created
	}
	return time.Time{}
}

// Algorithm is the algorithm of the key with its size or its curve.
func (k *AdoptedKey) Algorithm() openpgp.ForeignAlgorithm {
	if s := k.state(); s != nil {
		return s.algorithm
	}
	return openpgp.ForeignAlgorithm{}
}

// Kind is [keystore.KindSoftware].
func (k *AdoptedKey) Kind() keystore.Kind { return keystore.KindSoftware }

// Copyable is true: every software key can be copied.
func (k *AdoptedKey) Copyable() bool { return true }

// Warnings returns the one code of the ceremony record, [keystore.WarningSoftwareCopyable], in a new
// list on every call.
func (k *AdoptedKey) Warnings() []string { return []string{keystore.WarningSoftwareCopyable} }

// Close wipes the secret as far as Go allows (see [AdoptedKey]) and makes the key refuse to sign. A
// second Close does nothing and returns nil, and so does Close of a nil or zero key.
func (k *AdoptedKey) Close() error {
	s := k.state()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.secret.Wipe()
	s.signer = nil
	return nil
}

// Sign signs with the key as the type says, after the options are guarded and before the secret is
// used; see [AdoptedKey]. The signature is verified with the public key before it is returned. The
// io.Reader argument is ignored, as in [Key.Sign], and may be nil. A nil key, a closed key and an
// option that the key does not sign with are an [ErrParams].
func (k *AdoptedKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s := k.state()
	if s == nil {
		return nil, refuse(ErrParams, "there is no key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.signer == nil {
		return nil, refuse(ErrParams, "the key is closed")
	}
	h, err := guardSign(s.algorithm.ID, digest, opts)
	if err != nil {
		return nil, err
	}
	sig, err := s.signer.Sign(rand.Reader, digest, signOpts(s.algorithm.ID, h))
	if err != nil {
		return nil, errors.New("software: the key could not sign")
	}
	if s.tamper != nil {
		sig = s.tamper(sig)
	}
	if !verifyWith(s.pub, h, digest, sig) {
		return nil, errAdoptedSignature
	}
	return sig, nil
}

// guardSign checks the options and the input of a signature of a key of an algorithm, before the
// secret is used, and returns the hash that the options name (zero for Ed25519).
func guardSign(alg uint8, digest []byte, opts crypto.SignerOpts) (crypto.Hash, error) {
	switch alg {
	case algEdDSA:
		if h, ok := opts.(crypto.Hash); !ok || h != 0 {
			return 0, refuse(ErrParams, "an Ed25519 key signs the message as it is given, with the option crypto.Hash(0)")
		}
		return 0, nil
	case algRSA, algECDSA:
		if _, pss := opts.(*rsa.PSSOptions); pss {
			return 0, refuse(ErrParams, "the key signs a plain digest, PKCS#1 version 1.5 for RSA, and never takes the options of PSS")
		}
	default:
		return 0, refuse(ErrParams, "the algorithm of the key is not one that the store signs with")
	}
	h, ok := hashOf(opts)
	if !ok || h != crypto.SHA256 && h != crypto.SHA384 && h != crypto.SHA512 {
		return 0, refuse(ErrParams, "the key signs a digest of SHA-256, SHA-384 or SHA-512 only")
	}
	if len(digest) != h.Size() {
		return 0, refuse(ErrParams, "the digest does not have the length of the hash that the option names")
	}
	return h, nil
}

// signOpts is the option that the signer of internal/openpgp is given: the hash for RSA and ECDSA,
// and crypto.Hash(0) for Ed25519, never a PSS option.
func signOpts(alg uint8, h crypto.Hash) crypto.SignerOpts {
	if alg == algEdDSA {
		return crypto.Hash(0)
	}
	return h
}

// verifyWith verifies a signature with the public key of the type that guardSign allows.
func verifyWith(pub crypto.PublicKey, h crypto.Hash, digest, sig []byte) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, h, digest, sig) == nil
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, digest, sig)
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest, sig)
	}
	return false
}

// selfCheck signs a random digest and verifies the signature with the public key. Sign does the
// verifying; a failure is an [ErrKeyFile], because the file does not hold a key that signs.
func (k *AdoptedKey) selfCheck() error {
	s := k.state()
	if s == nil {
		return refuse(ErrParams, "there is no key")
	}
	var digest []byte
	var opts crypto.SignerOpts
	switch s.algorithm.ID {
	case algEdDSA:
		digest, opts = make([]byte, edCheckLen), crypto.Hash(0)
	case algRSA:
		digest, opts = make([]byte, rsaCheckHash.Size()), rsaCheckHash
	default:
		digest, opts = make([]byte, ecdsaCheckHash.Size()), ecdsaCheckHash
	}
	if _, err := rand.Read(digest); err != nil {
		return errors.New("software: no random bytes for the check of the key")
	}
	if _, err := k.Sign(nil, digest, opts); err != nil {
		if errors.Is(err, ErrParams) {
			return err
		}
		return refuse(ErrKeyFile, "the key in the file does not sign what its public key verifies")
	}
	return nil
}

var _ crypto.Signer = (*AdoptedKey)(nil)
