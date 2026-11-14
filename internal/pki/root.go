package pki

import (
	"crypto"
	"encoding/asn1"
	"math/big"
	"strings"
	"time"
)

const (
	// RootValidityMonths is the length of a root certificate: 36 calendar months from the
	// ceremony time (docs/reference/bundle.md, "The root certificate").
	RootValidityMonths = 36
	// MaxNameLength is the longest name of a bundle: 45 characters. The common name of a root is the
	// name, " Root " and the label (7 characters) and, for a test root, " (TEST ONLY)" (12 more), and
	// RFC 5280 limits a common name to 64: 45 + 7 + 12 = 64, so one number holds for a real and for a
	// test root and a name fails early, at the start, and not at the ceremony.
	MaxNameLength = 45
	// MaxCommonNameLength is the longest common name of RFC 5280 (ub-common-name, Appendix A.1):
	// 64 characters. It stays as the last guard behind MaxNameLength.
	MaxCommonNameLength = 64
	// testMark ends the common name of a test root.
	testMark = " (TEST ONLY)"
)

// RootParams are the parameters of the root certificate of one root key.
type RootParams struct {
	// Name is the name from ritueel.yaml: 1 to 45 characters ([MaxNameLength]), each an ASCII
	// letter, a digit, a single space or a hyphen; no space at its start or its end and no two
	// spaces in a row. A name in another script is not possible in version 1.
	Name string
	// Label is the label of the root key: one upper-case ASCII letter.
	Label string
	// Test marks a test root: its common name ends " (TEST ONLY)".
	Test bool
	// CeremonyTime is notBefore. It is in whole seconds and is not the zero time.
	CeremonyTime time.Time
	// Key is the public key of the root: ECDSA on P-384. The certificate is self-signed, so it
	// is also the key that signs the certificate.
	Key crypto.PublicKey
	// Serial is a positive number of at most 20 octets with at least 64 bits (see [NewSerial]).
	Serial *big.Int
}

// RootCommonName returns the common name of a root: "<name> Root <label>", which a test root
// ends with " (TEST ONLY)". It is the issuer and the subject of the root certificate. It returns
// an error that wraps [ErrParams] for a name, a label or a length that the profile refuses.
func RootCommonName(name, label string, test bool) (string, error) {
	if n := len(name); n < 1 || n > MaxNameLength {
		return "", fail(ErrParams, "the name has %d characters, not 1 to %d", n, MaxNameLength)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != ' ' && c != '-' {
			return "", fail(ErrParams, "the name has a character other than an ASCII letter, a digit, a space or a hyphen, at position %d", i)
		}
	}
	if name[0] == ' ' || name[len(name)-1] == ' ' {
		return "", fail(ErrParams, "the name has a space at its start or its end")
	}
	if strings.Contains(name, "  ") {
		return "", fail(ErrParams, "the name has two spaces in a row")
	}
	if len(label) != 1 || label[0] < 'A' || label[0] > 'Z' {
		return "", fail(ErrParams, "the label is not one upper-case ASCII letter")
	}
	cn := name + " Root " + label
	if test {
		cn += testMark
	}
	if len(cn) > MaxCommonNameLength {
		return "", fail(ErrParams, "the common name has %d characters, more than the %d of RFC 5280", len(cn), MaxCommonNameLength)
	}
	return cn, nil
}

// checkTime refuses a time that is zero, has a fraction of a second, or lies outside the years
// that a certificate holds (1 to 9999).
func checkTime(what string, t time.Time) error {
	switch {
	case t.IsZero():
		return fail(ErrParams, "%s is the zero time", what)
	case t.Nanosecond() != 0:
		return fail(ErrParams, "%s has a fraction of a second", what)
	case t.UTC().Year() < 1:
		return fail(ErrParams, "%s is before the year 1", what)
	case t.UTC().Year() > 9999:
		return fail(ErrParams, "%s is after the year 9999", what)
	}
	return nil
}

// RootTBS returns the DER TBSCertificate of the root certificate profile
// (docs/reference/bundle.md, "The root certificate"):
//
//   - version 3, the serial given, signature ecdsa-with-SHA384;
//   - issuer and subject the same name, one common name ([RootCommonName]), encoded as a
//     UTF8String;
//   - notBefore the ceremony time, notAfter [AddMonths](ceremony time, 36), in UTC;
//   - the key given, ECDSA on P-384;
//   - three extensions, in this order: basic constraints (critical, cA true, no path length),
//     subject key identifier (not critical, [KeyIdentifier]) and key usage (critical, keyCertSign
//     and cRLSign only). Nothing else: no name constraints and no authority key identifier.
//
// The bytes depend only on the parameters. The root key signs them with [SignRoot], and [Assemble]
// finishes the certificate. An error wraps [ErrParams].
//
// A body that RootTBS returns is one that the standard library reads as a certificate: before it
// returns, the body is put into a certificate with a placeholder signature of the right form, and
// x509.ParseCertificate must accept it and read back the same body, serial and dates. So a body
// that [Assemble] would refuse is never signed. A parameter that fails this is an [ErrParams].
//
// Copies: the serial and the key are copied at the top of the call, and the body is built from the
// copies (see "What the caller must do" in the package comment for what the caller still owes).
func RootTBS(p RootParams) ([]byte, error) {
	// What is read more than once is copied first, and the body is built from the copies only: the
	// serial and the key (a data race of the caller on them cannot make a call panic or build a body
	// from two values). The time is a value; the name and the label are strings.
	p, err := copyRoot(p)
	if err != nil {
		return nil, err
	}
	cn, err := RootCommonName(p.Name, p.Label, p.Test)
	if err != nil {
		return nil, err
	}
	if err := checkTime("the ceremony time", p.CeremonyTime); err != nil {
		return nil, err
	}
	if err := CheckSerial(p.Serial); err != nil {
		return nil, err
	}
	der, point, err := spki(p.Key)
	if err != nil {
		return nil, err
	}
	notBefore := p.CeremonyTime.UTC()
	body, err := rootBody(p.Serial, cn, notBefore, der, point)
	if err != nil {
		return nil, err
	}
	notAfter, err := AddMonths(notBefore, RootValidityMonths)
	if err != nil {
		return nil, fail(ErrParams, "the end of the validity is not a date that a certificate holds (the years 1 to 9999)")
	}
	if err := readable(body, p.Serial, notBefore, notAfter); err != nil {
		// A root name is ASCII from RootCommonName, the key and the serial are checked, and the dates are
		// in the years 1 to 9999: reaching here is a fault of this package, not of a parameter.
		return nil, failWith(ErrParams, "the body is not a certificate that the standard library reads (a fault of this package: the readings before it accepted every input)", err)
	}
	return body, nil
}

// rootBody writes the TBSCertificate of a root from its parts. It is the one place that does:
// [RootTBS] writes a body with it, and [Assemble] writes a body with it again from the
// parts it reads back, and accepts the body only when the two are the same bytes (see readBody).
// The common name has passed [RootCommonName], the serial [CheckSerial] and the key spki. The order
// of the extensions (basic constraints, subject key identifier, key usage) is decided: it is the order
// of the test vectors, and the page of the root certificate says so.
func rootBody(serial *big.Int, cn string, notBefore time.Time, spkiDER, point []byte) ([]byte, error) {
	notAfter, err := AddMonths(notBefore, RootValidityMonths)
	if err != nil {
		return nil, fail(ErrParams, "the end of the validity is not a date that a certificate holds (the years 1 to 9999)")
	}
	if err := checkEnd(notAfter); err != nil {
		return nil, err
	}
	subject := commonName(cn)
	var exts [][]byte
	for _, e := range []struct {
		id       asn1.ObjectIdentifier
		critical bool
		value    []byte
	}{
		{oidBasicConstraints, true, basicConstraintsCA},
		{oidSubjectKeyID, false, subjectKeyIDValue(keyIdentifier(point))},
		{oidKeyUsage, true, keyUsageValue(usageKeyCertSign, usageCRLSign)},
	} {
		der, err := extension(e.id, e.critical, e.value)
		if err != nil {
			return nil, failWith(ErrParams, "the body cannot be written", err)
		}
		exts = append(exts, der)
	}
	body, err := tbs(serial, subject, notBefore, notAfter, subject, spkiDER, exts)
	if err != nil {
		return nil, failWith(ErrParams, "the body cannot be written", err)
	}
	return body, nil
}
