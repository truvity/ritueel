package attest

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
)

// MaxCertificateSize is the largest certificate of an attestation or of a pinned set, in bytes of DER:
// 16 KiB. The page gives no size; real certificates are about 1 KiB, so this is the number of this
// package (proposed).
const MaxCertificateSize = 16 << 10

// MaxPinned is the most certificates in one group of a [Bundle]: 64.
const MaxPinned = 64

// maxPEMSize is the largest text that [CertificatesFromPEM] reads: 1 MiB.
const maxPEMSize = 1 << 20

// ErrBundle is wrapped by every error of [NewBundle].
var ErrBundle = errors.New("attest: invalid attestation bundle")

// Applet is the applet of a token that a key lives in. Each has its own group of pinned intermediates.
type Applet string

// The two applets that attest a key.
const (
	// AppletPIV is the PIV applet.
	AppletPIV Applet = "piv"
	// AppletOpenPGP is the OpenPGP applet of a card.
	AppletOpenPGP Applet = "openpgp"
)

// The keys of Evidence.Details that the verifiers of piv and openpgp-card set. They are in one place so
// that the ceremony record and the verifiers agree on them (proposed).
const (
	// DetailSlot is the PIV slot, "9c". piv only.
	DetailSlot = "slot"
	// DetailSerial is the serial number of the token in decimal. piv only.
	DetailSerial = "serial"
	// DetailFormFactor is the form factor byte of the token in decimal. piv only, and only when the
	// certificate has the extension.
	DetailFormFactor = "form_factor"
	// DetailPolicyRead is "true" when the verifier read the firmware and the PIN and touch policy from the
	// attestation (piv) and "false" when it did not (openpgp-card).
	DetailPolicyRead = "policy_read"
	// DetailBundleVersion is [Bundle.Version] of the bundle that verified the chain.
	DetailBundleVersion = "attestation_bundle_version"
	// DetailBundleSHA256 is [Bundle.SHA256] of the bundle that verified the chain.
	DetailBundleSHA256 = "attestation_bundle_sha256"
)

// BundleSpec is what [NewBundle] takes. It holds DER bytes, because a slice of bytes is easy to copy.
type BundleSpec struct {
	// Version names this set, 1 to 32 printable ASCII characters, for example a date.
	Version string
	// Roots are the DER of each pinned maker root, at least one.
	Roots [][]byte
	// PIVIntermediates are the DER of each intermediate that a piv chain may pass.
	PIVIntermediates [][]byte
	// OpenPGPIntermediates are the DER of each intermediate that an openpgp-card chain may pass.
	OpenPGPIntermediates [][]byte
}

// Bundle is the set of certificates the certifier trusts to end a chain of attestation. It is immutable
// after [NewBundle], and one Bundle serves any number of calls at the same time. The zero Bundle holds no
// root and refuses every call.
type Bundle struct {
	version string
	digest  string
	roots   []*x509.Certificate
	piv     []*x509.Certificate
	opgp    []*x509.Certificate
}

// NewBundle parses and checks a spec, and keeps its own copy of every certificate: a change that the
// caller makes to its slices afterwards changes nothing. It refuses a spec with no root; a group of more
// than [MaxPinned] certificates; a certificate that is empty, larger than [MaxCertificateSize], does not
// parse or has bytes after its DER; a root that is not a CA that is self-signed and verifies its own
// signature; an intermediate that is not a CA; and a version outside 1 to 32 printable ASCII characters.
// The same certificate may be in both intermediate groups. The error wraps [ErrBundle].
func NewBundle(s BundleSpec) (*Bundle, error) {
	if !validVersion(s.Version) {
		return nil, fmt.Errorf("%w: the version is not 1 to 32 printable ASCII characters", ErrBundle)
	}
	if len(s.Roots) == 0 {
		return nil, fmt.Errorf("%w: no root", ErrBundle)
	}
	roots, rootDER, err := parseGroup("root", s.Roots, true)
	if err != nil {
		return nil, err
	}
	piv, pivDER, err := parseGroup("piv intermediate", s.PIVIntermediates, false)
	if err != nil {
		return nil, err
	}
	opgp, opgpDER, err := parseGroup("openpgp intermediate", s.OpenPGPIntermediates, false)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		version: s.Version,
		digest:  digestOf(rootDER, pivDER, opgpDER),
		roots:   roots,
		piv:     piv,
		opgp:    opgp,
	}, nil
}

// validVersion reports whether v is 1 to 32 printable ASCII characters.
func validVersion(v string) bool {
	if len(v) < 1 || len(v) > 32 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// parseGroup reads one group of the spec. It returns the parsed certificates and the copies of their DER,
// in the order of the spec.
func parseGroup(name string, group [][]byte, root bool) ([]*x509.Certificate, [][]byte, error) {
	if len(group) > MaxPinned {
		return nil, nil, fmt.Errorf("%w: a group holds more than %d certificates", ErrBundle, MaxPinned)
	}
	certs := make([]*x509.Certificate, 0, len(group))
	ders := make([][]byte, 0, len(group))
	for i, der := range group {
		if len(der) == 0 || len(der) > MaxCertificateSize {
			return nil, nil, fmt.Errorf("%w: %s %d is empty or larger than %d bytes", ErrBundle, name, i+1, MaxCertificateSize)
		}
		cp := bytes.Clone(der)
		c, err := x509.ParseCertificate(cp)
		if err != nil || len(c.Raw) != len(cp) {
			return nil, nil, fmt.Errorf("%w: %s %d is not one DER certificate with nothing after it", ErrBundle, name, i+1)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, nil, fmt.Errorf("%w: %s %d is not a CA certificate", ErrBundle, name, i+1)
		}
		if root && (!bytes.Equal(c.RawIssuer, c.RawSubject) || c.CheckSignatureFrom(c) != nil) {
			return nil, nil, fmt.Errorf("%w: %s %d is not self-signed or its signature does not verify", ErrBundle, name, i+1)
		}
		certs = append(certs, c)
		ders = append(ders, cp)
	}
	return certs, ders, nil
}

// digestOf is the digest of [Bundle.SHA256].
func digestOf(groups ...[][]byte) string {
	h := sha256.New()
	var n [4]byte
	for _, g := range groups {
		sorted := slices.Clone(g)
		slices.SortFunc(sorted, bytes.Compare)
		binary.BigEndian.PutUint32(n[:], uint32(len(sorted)))
		h.Write(n[:])
		for _, der := range sorted {
			binary.BigEndian.PutUint32(n[:], uint32(len(der)))
			h.Write(n[:])
			h.Write(der)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Version returns the version that the spec gave. A nil or zero Bundle gives "".
func (b *Bundle) Version() string {
	if b == nil {
		return ""
	}
	return b.version
}

// SHA256 is the digest of the bundle in lower-case hexadecimal: SHA-256 over the three groups, roots first,
// then the piv intermediates, then the openpgp intermediates. Each group is written as four bytes of its
// count (big-endian) and then its certificates sorted by their DER bytes, each as four bytes of its length
// (big-endian) and then its DER. So the order of a group does not change the digest, any certificate
// does, and so does moving a certificate from one group to another. The count of a group is not in the
// first form that was proposed; without it a certificate that moves from the last piv place to the first
// openpgp place leaves the digest as it was (proposed). A nil or zero Bundle gives "".
func (b *Bundle) SHA256() string {
	if b == nil {
		return ""
	}
	return b.digest
}

// usable reports whether the bundle was made by [NewBundle].
func (b *Bundle) usable() bool { return b != nil && len(b.roots) > 0 }

// CertificatesFromPEM returns the DER of every block of a PEM text. Only blocks labelled CERTIFICATE with
// no headers are read, and only white space may stand between them and around them. A text that holds no
// block, any other text, a block of another label or with a header, more than [MaxPinned] blocks, and a
// text longer than 1 MiB is an error. It is for tests and for the code that loads a bundle from a file.
func CertificatesFromPEM(data []byte) ([][]byte, error) {
	if len(data) > maxPEMSize {
		return nil, errors.New("attest: the PEM text is longer than 1 MiB")
	}
	var out [][]byte
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, errors.New("attest: the PEM text holds something that is not a block")
		}
		block, next := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("attest: the PEM text holds a block that does not decode")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("attest: the PEM text holds a block that is not a bare CERTIFICATE")
		}
		if len(out) == MaxPinned {
			return nil, fmt.Errorf("attest: the PEM text holds more than %d blocks", MaxPinned)
		}
		out = append(out, block.Bytes)
		rest = next
	}
	if len(out) == 0 {
		return nil, errors.New("attest: the PEM text holds no block")
	}
	return out, nil
}
