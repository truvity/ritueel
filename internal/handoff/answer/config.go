package answer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/rootlist"
)

// Config is what [New] needs. Exactly one of Held and FloorAnchors is given: the full contract or the floor.
type Config struct {
	// Held is the root list that the requester holds, the last list it accepted (record 0006, rule 21). The
	// anchors and the primaries of an answer are taken from it and from nothing that the answer carries.
	// Required for the full contract.
	Held *rootlist.Held
	// CABundle is the ca-bundle.pem of the held list. Required with Held; [New] checks it with
	// [rootlist.VerifyCABundle], and a bundle that is not the bundle of the held list is an [ErrConfig].
	CABundle []byte
	// Primaries are the OpenPGP primaries that the requester holds, from its keyring, for openpgp-subkey
	// answers: the fingerprint, the public key and the creation time of each, at most [handoff.MaxPrimaries].
	// The keyring is trusted for nothing but the bytes of a key: the fingerprint is the hash of the key and
	// its creation time, and it must be on the signed list that the requester holds. Only with Held.
	Primaries []handoff.PrimaryRef

	// FloorAnchors are the CA certificates that the operator installed, one PEM file each ("The floor"), at
	// most [MaxAnchors]. Given with no Held.
	FloorAnchors [][]byte

	// Validity is the length of validity that the requester expects, in calendar months: at least Min and at
	// most Max. Required, 1 <= Min <= Max <= [MaxValidityMonths]. The contract gives "for example 12 to 14
	// months", so there is no default.
	Validity struct{ MinMonths, MaxMonths int }
	// Now is the clock. Required. It is read once for each call of [Checker.Check] and never by [New].
	Now func() time.Time
}

// anchor is a certificate of the CA bundle of the held list, or one installed on the floor.
type anchor struct {
	cert *x509.Certificate
	key  *ecdsa.PublicKey // the key of cert when it is ECDSA on P-384, and nil otherwise
	pin  string           // SHA-256 of the SubjectPublicKeyInfo, lower-case hexadecimal
}

// heldSet is the held list as the checks use it: the numbers and the pins, copied.
type heldSet struct {
	sequence int64
	expires  time.Time
	pins     []string           // the x509_spki_sha256 of every root, in the order of the list
	pgp      []string           // the openpgp_fingerprint of every root that has one
	anchors  map[string]*anchor // by pin
}

// preparedPrimary is a primary that the requester holds: its fingerprint and the key that package openpgp made
// of it (which holds its own copy).
type preparedPrimary struct {
	fingerprint string
	key         *openpgp.PrimaryKey
}

// settings is the configuration of a checker, validated and copied once by [New] in the form that the checks use.
// Nothing in it is shared with the caller, and nothing in it changes after New.
type settings struct {
	floor        bool
	held         heldSet
	primaries    []preparedPrimary
	floorAnchors []*anchor
	minMonths    int
	maxMonths    int
	now          func() time.Time
}

// New makes a Checker, and holds its own copy of everything in the Config. It refuses with [ErrConfig], and
// returns no Checker: neither or both of Held and FloorAnchors; a Held that is nil or has no list; a CABundle
// that is empty or that [rootlist.VerifyCABundle] does not accept for the list of Held (a fault of the
// requester's own trust files, never a refusal of an answer); Primaries with FloorAnchors, more than
// [handoff.MaxPrimaries] of them, a PrimaryRef with a nil key, a key that is not ECDSA on P-384, a creation time
// that is not whole seconds in the years 1970 to 2106, a fingerprint that is not the one that its key and
// creation time give, or two entries with one fingerprint; no floor certificate or more than [MaxAnchors], one
// that is not one PEM file of one certificate (read by [pki.ReadPEMFile] and [x509.ParseCertificate]), or two
// that are the same; a Validity out of its bounds; a nil clock. New reads no clock. A floor certificate that is
// not a CA, has ended, has the wrong key usage or has a key outside the list of the floor (ECDSA on P-256, P-384
// or P-521, Ed25519, or RSA of 2048 bits or more) is not refused here: the check of an answer refuses an answer
// that it would have to verify, and says why.
func New(cfg Config) (*Checker, error) {
	s := &settings{}
	floor, held := cfg.FloorAnchors != nil, cfg.Held != nil
	switch {
	case floor && held:
		return nil, fmt.Errorf("%w: both Held and FloorAnchors are given", ErrConfig)
	case !floor && !held:
		return nil, fmt.Errorf("%w: neither Held nor FloorAnchors is given", ErrConfig)
	}
	s.floor = floor
	if floor {
		if len(cfg.Primaries) != 0 {
			return nil, fmt.Errorf("%w: the floor holds no primaries", ErrConfig)
		}
		if cfg.CABundle != nil {
			return nil, fmt.Errorf("%w: the floor holds no CA bundle", ErrConfig)
		}
		if err := s.takeFloor(cfg.FloorAnchors); err != nil {
			return nil, err
		}
	} else {
		if err := s.takeHeld(cfg.Held, cfg.CABundle); err != nil {
			return nil, err
		}
		if err := s.takePrimaries(cfg.Primaries); err != nil {
			return nil, err
		}
	}
	v := cfg.Validity
	if v.MinMonths < 1 || v.MaxMonths < v.MinMonths || v.MaxMonths > MaxValidityMonths {
		return nil, fmt.Errorf("%w: the validity is not 1 <= Min <= Max <= %d months", ErrConfig, MaxValidityMonths)
	}
	s.minMonths, s.maxMonths = v.MinMonths, v.MaxMonths
	if cfg.Now == nil {
		return nil, fmt.Errorf("%w: no clock", ErrConfig)
	}
	s.now = cfg.Now
	return &Checker{s: s}, nil
}

// takeHeld reads the held list and its CA bundle. The bundle is checked against the list by package
// rootlist, and then read again for its certificates, in the order of the roots of the list.
func (s *settings) takeHeld(h *rootlist.Held, bundle []byte) error {
	if h.List == nil || len(h.List.Roots) == 0 {
		return fmt.Errorf("%w: the held list has no list or no roots", ErrConfig)
	}
	l := h.List
	if len(bundle) == 0 {
		return fmt.Errorf("%w: no CA bundle", ErrConfig)
	}
	bundle = bytes.Clone(bundle)
	if v := rootlist.VerifyCABundle(bundle, l); !v.Accepted {
		return fmt.Errorf("%w: the CA bundle is not the bundle of the held list", ErrConfig)
	}
	s.held = heldSet{sequence: l.Sequence, expires: l.ExpiresAt, anchors: make(map[string]*anchor, len(l.Roots))}
	// VerifyCABundle accepted the bundle: one plain CERTIFICATE block for each root, in the order of the
	// roots, whose key has the root's pin, and nothing else. It is read again here for the certificates.
	body := bytes.TrimPrefix(bundle, []byte(bundleFirstLine(l.Sequence)))
	for i, root := range l.Roots {
		blk, rest := pem.Decode(body)
		if blk == nil {
			return fmt.Errorf("%w: the CA bundle holds fewer certificates than the list has roots", ErrConfig)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("%w: certificate %d of the CA bundle does not parse", ErrConfig, i+1)
		}
		pin := jws.Pin(cert)
		if pin != root.X509SPKISHA256 {
			return fmt.Errorf("%w: certificate %d of the CA bundle is not the root of that position", ErrConfig, i+1)
		}
		s.held.pins = append(s.held.pins, pin)
		if root.OpenPGPFingerprint != "" {
			s.held.pgp = append(s.held.pgp, root.OpenPGPFingerprint)
		}
		s.held.anchors[pin] = &anchor{cert: cert, key: p384Key(cert), pin: pin}
		body = rest
	}
	return nil
}

// bundleFirstLine is the first line of a CA bundle for a list of the given sequence ("The CA bundle").
func bundleFirstLine(sequence int64) string {
	return fmt.Sprintf("# trust-sequence: %d\n", sequence)
}

// p384Key returns the key of a certificate when it is an ECDSA key on P-384, and nil otherwise.
func p384Key(cert *x509.Certificate) *ecdsa.PublicKey {
	k, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || k == nil || k.Curve != elliptic.P384() {
		return nil
	}
	return k
}

// takePrimaries reads the primaries that the requester holds, as package handoff reads the primaries of the
// certifier's configuration: each key is ECDSA on P-384 and has a creation time in whole seconds, and the
// fingerprint is the one that the two give.
func (s *settings) takePrimaries(refs []handoff.PrimaryRef) error {
	if len(refs) > handoff.MaxPrimaries {
		return fmt.Errorf("%w: more than %d primaries", ErrConfig, handoff.MaxPrimaries)
	}
	for i, ref := range refs {
		if ref.Key == nil {
			return fmt.Errorf("%w: the key of primary %d is nil", ErrConfig, i)
		}
		key, err := openpgp.NewPrimaryKey(ref.Key, ref.Created)
		if err != nil {
			return fmt.Errorf("%w: primary %d: %w", ErrConfig, i, err)
		}
		if !lowerHex(ref.Fingerprint, 40) || ref.Fingerprint != key.Fingerprint() {
			return fmt.Errorf("%w: the fingerprint of primary %d is not the one that its key and creation time give", ErrConfig, i)
		}
		for j, other := range s.primaries {
			if other.fingerprint == ref.Fingerprint {
				return fmt.Errorf("%w: primary %d repeats primary %d", ErrConfig, i, j)
			}
		}
		s.primaries = append(s.primaries, preparedPrimary{fingerprint: ref.Fingerprint, key: key})
	}
	return nil
}

// takeFloor reads the installed CA certificates of the floor: each is one PEM file of one certificate.
func (s *settings) takeFloor(files [][]byte) error {
	if len(files) == 0 {
		return fmt.Errorf("%w: the floor holds no CA certificate", ErrConfig)
	}
	if len(files) > MaxAnchors {
		return fmt.Errorf("%w: more than %d CA certificates on the floor", ErrConfig, MaxAnchors)
	}
	for i, file := range files {
		der, err := pki.ReadPEMFile(file, "CERTIFICATE")
		if err != nil {
			if errors.Is(err, pki.ErrPEM) {
				return fmt.Errorf("%w: floor certificate %d is not one PEM file of one certificate: %w", ErrConfig, i+1, err)
			}
			return fmt.Errorf("%w: floor certificate %d: %w", ErrInternal, i+1, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("%w: floor certificate %d does not parse", ErrConfig, i+1)
		}
		for j, other := range s.floorAnchors {
			if bytes.Equal(other.cert.Raw, cert.Raw) {
				return fmt.Errorf("%w: floor certificate %d is the same as floor certificate %d", ErrConfig, i+1, j+1)
			}
		}
		s.floorAnchors = append(s.floorAnchors, &anchor{cert: cert, key: p384Key(cert), pin: jws.Pin(cert)})
	}
	return nil
}

// primary returns the primary that the requester holds with this fingerprint.
func (s *settings) primary(fingerprint string) (preparedPrimary, bool) {
	i := slices.IndexFunc(s.primaries, func(p preparedPrimary) bool { return p.fingerprint == fingerprint })
	if i < 0 {
		return preparedPrimary{}, false
	}
	return s.primaries[i], true
}
