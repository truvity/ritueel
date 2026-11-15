//go:build linux || darwin

package ceremony_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
)

// A hand-made root certificate: the bytes are written with a small DER writer of this file, and not
// by crypto/x509 or by internal/pki, so that the checks of the artifacts are tried against a
// certificate that none of the code under test wrote. Every member of the profile is a field that a
// test can change.

// mkDER writes one DER value: the tag byte, the length in the shortest form and the content.
func mkDER(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := []byte{tag}
	n := len(body)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func mkSeq(parts ...[]byte) []byte { return mkDER(0x30, parts...) }
func mkSet(parts ...[]byte) []byte { return mkDER(0x31, parts...) }

func mkOID(id asn1.ObjectIdentifier) []byte {
	b, err := asn1.Marshal(id)
	if err != nil {
		panic(err)
	}
	return b
}

func mkInt(n *big.Int) []byte {
	b, err := asn1.Marshal(n)
	if err != nil {
		panic(err)
	}
	return b
}

func mkBool(v bool) []byte {
	if v {
		return mkDER(0x01, []byte{0xff})
	}
	return mkDER(0x01, []byte{0x00})
}

func mkOctet(b []byte) []byte { return mkDER(0x04, b) }

func mkUTC(t time.Time) []byte { return mkDER(0x17, []byte(t.UTC().Format("060102150405Z"))) }

func mkGen(t time.Time) []byte { return mkDER(0x18, []byte(t.UTC().Format("20060102150405Z"))) }

// mkName is a name of one common name, as a UTF8String.
func mkName(cn string) []byte {
	return mkSeq(mkSet(mkSeq(mkOID(asn1.ObjectIdentifier{2, 5, 4, 3}), mkDER(0x0c, []byte(cn)))))
}

// mkExt is one extension.
func mkExt(id asn1.ObjectIdentifier, critical bool, value []byte) []byte {
	parts := [][]byte{mkOID(id)}
	if critical {
		parts = append(parts, mkBool(true))
	}
	parts = append(parts, mkOctet(value))
	return mkSeq(parts...)
}

var (
	mkOIDBasic  = asn1.ObjectIdentifier{2, 5, 29, 19}
	mkOIDSKI    = asn1.ObjectIdentifier{2, 5, 29, 14}
	mkOIDUsage  = asn1.ObjectIdentifier{2, 5, 29, 15}
	mkOIDAKI    = asn1.ObjectIdentifier{2, 5, 29, 35}
	mkOIDNC     = asn1.ObjectIdentifier{2, 5, 29, 30}
	mkOIDEKU    = asn1.ObjectIdentifier{2, 5, 29, 37}
	mkOIDSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	mkOIDSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// mkSKI is the RFC 7093 method 1 identifier of a key: the leftmost 160 bits of the SHA-256 of the
// bits of the subject public key.
func mkSKI(pub *ecdsa.PublicKey) []byte {
	e, err := pub.ECDH()
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(e.Bytes())
	return sum[:20]
}

// mkPin is the SHA-256 of the SubjectPublicKeyInfo of a key, in hexadecimal.
func mkPin(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// mkCertSpec describes a root certificate. The zero value of a field means "as the profile says".
type mkCertSpec struct {
	Key     *ecdsa.PrivateKey // the key of the certificate; made if nil
	SignKey *ecdsa.PrivateKey // signs, when it is not the key of the certificate

	Name, Label string // "Example" and "A" when empty
	CN          string // the whole common name of the subject, when not empty
	IssuerCN    string // the common name of the issuer, when not empty
	Production  bool   // no " (TEST ONLY)"

	Serial    *big.Int
	NotBefore time.Time
	NotAfter  time.Time // 36 calendar months after NotBefore when zero

	// Version is the value of the version member: 2 means v3. Zero means 2. -1 leaves it out (v1).
	Version int

	// Exts replace the three extensions when not nil, in the order given.
	Exts [][]byte
	// NoExts writes a certificate with no extensions at all.
	NoExts bool

	SigAlg       asn1.ObjectIdentifier // ecdsa-with-SHA384 when nil
	SigParams    bool                  // a NULL parameter in the TBS algorithm
	OuterAlg     asn1.ObjectIdentifier // the algorithm after the TBS, when it differs
	UniqueIDs    bool
	NotBeforeGT  bool   // write notBefore as GeneralizedTime
	NotBeforeDER []byte // the whole DER of the notBefore value, when it is not the usual one
	NotAfterDER  []byte // the same for notAfter
	NotAfterGT   bool
	Trailing     []byte // appended after the certificate
	SPKI         []byte // the SubjectPublicKeyInfo, when it is not the key's
}

// mkSerial is a serial of the plan's form: 16 random-looking bytes, positive.
func mkSerial(seed byte) *big.Int {
	b := make([]byte, 16)
	for i := range b {
		b[i] = seed + byte(i)*7 + 1
	}
	b[0] &= 0x7f
	if b[0] == 0 {
		b[0] = 0x11
	}
	return new(big.Int).SetBytes(b)
}

// mkKeyP384 makes a P-384 key.
func mkKeyP384() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// mkAddMonths is written here for the check of a validity: the same day and time of the month, or the
// last day of the month when it has none.
func mkAddMonths(t time.Time, n int) time.Time {
	t = t.UTC()
	y, m, d := t.Date()
	idx := int(m) - 1 + n
	y += idx / 12
	m = time.Month(idx%12 + 1)
	last := time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if d > last {
		d = last
	}
	return time.Date(y, m, d, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}

// mkCert is the result of mkCertSpec.build: the DER and the facts that the check is given.
type mkCert struct {
	DER  []byte
	TBS  []byte
	Key  *ecdsa.PrivateKey
	Want ceremony.RootCertWant
}

// build writes the certificate and the facts of a good one for it: the want that matches the
// spec's own values. A test changes either.
func (s mkCertSpec) build() mkCert {
	key := s.Key
	if key == nil {
		key = mkKeyP384()
	}
	name, label := s.Name, s.Label
	if name == "" {
		name = "Example"
	}
	if label == "" {
		label = "A"
	}
	cn := s.CN
	if cn == "" {
		cn = name + " Root " + label
		if !s.Production {
			cn += " (TEST ONLY)"
		}
	}
	icn := s.IssuerCN
	if icn == "" {
		icn = cn
	}
	serial := s.Serial
	if serial == nil {
		serial = mkSerial(1)
	}
	nb := s.NotBefore
	if nb.IsZero() {
		nb = pfClock
	}
	na := s.NotAfter
	if na.IsZero() {
		na = mkAddMonths(nb, 36)
	}
	spki := s.SPKI
	if spki == nil {
		var err error
		spki, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			panic(err)
		}
	}
	alg := s.SigAlg
	if alg == nil {
		alg = mkOIDSHA384
	}
	algDER := mkSeq(mkOID(alg))
	if s.SigParams {
		algDER = mkSeq(mkOID(alg), []byte{0x05, 0x00})
	}
	exts := s.Exts
	if exts == nil && !s.NoExts {
		exts = [][]byte{
			mkExt(mkOIDBasic, true, mkSeq(mkBool(true))),
			mkExt(mkOIDSKI, false, mkOctet(mkSKI(&key.PublicKey))),
			mkExt(mkOIDUsage, true, []byte{0x03, 0x02, 0x01, 0x06}),
		}
	}
	version := s.Version
	if version == 0 {
		version = 2
	}
	var parts [][]byte
	if version >= 0 {
		parts = append(parts, mkDER(0xa0, mkInt(big.NewInt(int64(version)))))
	}
	nbDER, naDER := mkUTC(nb), mkUTC(na)
	if s.NotBeforeGT {
		nbDER = mkGen(nb)
	}
	if s.NotAfterGT {
		naDER = mkGen(na)
	}
	if s.NotBeforeDER != nil {
		nbDER = s.NotBeforeDER
	}
	if s.NotAfterDER != nil {
		naDER = s.NotAfterDER
	}
	parts = append(parts, mkInt(serial), algDER, mkName(icn), mkSeq(nbDER, naDER), mkName(cn), spki)
	if s.UniqueIDs {
		parts = append(parts, mkDER(0x81, []byte{0x00, 0xaa}), mkDER(0x82, []byte{0x00, 0xbb}))
	}
	if exts != nil {
		parts = append(parts, mkDER(0xa3, mkSeq(exts...)))
	}
	tbs := mkSeq(parts...)
	signer := s.SignKey
	if signer == nil {
		signer = key
	}
	digest := sha512.Sum384(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil {
		panic(err)
	}
	outer := alg
	if s.OuterAlg != nil {
		outer = s.OuterAlg
	}
	der := mkSeq(tbs, mkSeq(mkOID(outer)), mkDER(0x03, []byte{0x00}, sig))
	der = append(der, s.Trailing...)
	return mkCert{
		DER: der, TBS: tbs, Key: key,
		Want: ceremony.RootCertWant{
			Name: name, Label: label, Pin: mkPin(&key.PublicKey), Serial: serial.Text(16),
			NotBefore: nb, NotAfter: na,
		},
	}
}

// good is the certificate of the profile, with the facts for it.
func mkGoodCert() mkCert { return mkCertSpec{}.build() }

// mkSign writes a certificate of a body, signed by the key with SHA-384, as ecdsa-with-SHA384.
func mkSign(tbs []byte, key *ecdsa.PrivateKey) []byte {
	digest := sha512.Sum384(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	return mkSeq(tbs, mkSeq(mkOID(mkOIDSHA384)), mkDER(0x03, []byte{0x00}, sig))
}

// buildWithNotAfterDER is build with the DER of notAfter given.
func (s mkCertSpec) buildWithNotAfterDER(raw []byte) mkCert {
	s.NotAfterDER = raw
	return s.build()
}
