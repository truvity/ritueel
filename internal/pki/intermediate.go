package pki

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// IntermediateValidityMonths is the length of an intermediate certificate: 13 calendar months from
// the ceremony time. The hand-off contract fixes it for version 1: the profile says "`notAfter` is 13
// calendar months later (same day and time of the month, or the last day of the month if it has
// none)" ("What is issued"), the reference policy has "Validity | 13 calendar months", and "Validity
// is the one thing the request does not carry: the certifier decides it". No request, and no
// parameter of this package, can ask for another number.
const IntermediateValidityMonths = 13

// RootRef names one root of the bundle: the DER of its subject (the RawSubject of its certificate) and
// its public key. It has the form of the issuer's two parameters, [IntermediateParams.IssuerSubject]
// and [IntermediateParams.IssuerKey], because the package needs of a root exactly its name and its key
// and nothing of its certificate, which it does not read.
type RootRef struct {
	// Subject is the raw DER of the subject of the root. It is read as an issuer is read: a name of
	// the form of a root's name (see [IntermediateParams.IssuerSubject]).
	Subject []byte
	// Key is the public key of the root: ECDSA on P-384.
	Key crypto.PublicKey
}

// IntermediateParams are the parameters of the certificate for an intermediate key.
type IntermediateParams struct {
	// CSR is the certificate request, the DER of a PKCS #10 request (not PEM; [ParseRequestFile]
	// reads a file). It is read by [ParseRequest] inside [IntermediateTBS], and nothing else is
	// trusted: a caller cannot hand over a request that was read, or edited, in another place. Its
	// subject and its public key go into the certificate unchanged; its extensions decide the
	// extensions of the certificate.
	CSR []byte
	// IssuerSubject is the raw DER of the subject of the issuing root, written as the issuer
	// byte for byte.
	IssuerSubject []byte
	// IssuerKey is the public key of the issuing root, for the authority key identifier: ECDSA
	// on P-384. It is the key that signs: [SignIntermediate] refuses another signer.
	IssuerKey crypto.PublicKey
	// Roots are all the roots of the bundle, the issuer among them: required, not empty, and holding a
	// root whose subject is IssuerSubject and whose key is IssuerKey (else [ErrParams]). Two entries
	// with one name (as [SameName] compares) and different keys, and two entries with one key and two
	// names, are an [ErrParams] too: a name is one root's and a key is one root's. An entry that is
	// listed twice, with the same bytes of its subject and the same key, passes and counts once: it
	// opens no second path, and a caller that joins two lists need not take one entry out. The package
	// cannot know the bundle, so the caller builds the list from it. A request whose key is the key of
	// any of them, or whose subject is the name of any of them as OpenSSL compares names (see
	// [SameName]), is refused with the check [CheckPolicy], not only a request for the issuer's own key
	// or name: a certificate for another root's key under this root would be a second path to that
	// root, and a name that is the name of a root is a second certificate under one name for every
	// store that is keyed by name. [SignIntermediate] builds the body again from the same parameters,
	// so the rule holds at the signing too.
	Roots []RootRef
	// CeremonyTime is notBefore. It is in whole seconds and is not the zero time. notAfter is
	// [AddMonths](ceremony time, [IntermediateValidityMonths]).
	CeremonyTime time.Time
	// Serial is a positive number of at most 20 octets with at least 64 bits (see [NewSerial]).
	Serial *big.Int
}

// IntermediateTBS returns the DER TBSCertificate of the intermediate profile
// (docs/reference/hand-off-contract.md, "What is issued"), or an error. It issues exactly what
// the request asks:
//
//   - version 3, the serial given, signature ecdsa-with-SHA384;
//   - the issuer is IssuerSubject, byte for byte; the subject and the public key are the
//     request's, byte for byte;
//   - notBefore is the ceremony time and notAfter is [AddMonths](ceremony time,
//     [IntermediateValidityMonths]);
//   - basic constraints, critical, cA true, path length 0 (the only value of version 1);
//   - key usage, critical, as requested (keyCertSign, and cRLSign and digitalSignature when
//     asked, no other bit);
//   - name constraints, critical: the extension value is copied byte for byte, after its structure
//     and its names have been read (below);
//   - extended key usage, not critical: the value as requested, the same purposes in the same order
//     (serverAuth, clientAuth or both, each once; the request must have it);
//   - subject key identifier ([KeyIdentifier] of the subject key) and authority key identifier
//     ([KeyIdentifier] of the issuer key), neither critical.
//
// The extensions come in this order: basic constraints, key usage, name constraints, extended key
// usage, subject key identifier, authority key identifier. The order is decided, and anything else
// is absent.
//
// The request is read by [ParseRequest], from its DER bytes, before anything else is built, and
// ParseRequest holds it to everything that can be asked of a request without the issuer: its form,
// its signature, its subject, its extensions and its name constraints. A request that it refuses is
// refused here with its error (an [ErrRequest]). IntermediateTBS adds what needs the issuer and the
// other parameters: the key of the request is not the key of the issuer, and the subject of the
// request is not the name of the issuer, as OpenSSL compares names (see [SameName]; it is what
// OpenSSL does and not a full string preparation, so a name that differs from the issuer in a letter
// outside ASCII, or in the Unicode form, is not refused here). Both are [ErrRequest]. A parameter of
// the caller that is wrong gives [ErrParams]: the issuer name is read for its structure, for the
// validity of its strings in their types (RFC 5280, section 4.1.2.4 and Appendix A.1; a UTF8String is
// valid UTF-8) and for the same text rule as a subject (printable ASCII, single spaces), which the
// name of a root, the only issuer there is, always holds. An error that refuses the request says
// which check of the contract it is: see [CheckOf].
//
// A body that IntermediateTBS returns is one that the standard library reads as a certificate:
// before it returns, the body is put into a certificate with a placeholder signature of the right
// form, and x509.ParseCertificate must accept it and read back the same body, serial and dates; so
// a body that [Assemble] would refuse is never signed. The body is at most 16,777,096 octets (what
// a certificate can hold); an issuer that makes it longer is an [ErrParams] whose text says that the
// issuer is too long. The end of the validity is never 9999-12-31 23:59:59Z: RFC 5280,
// section 4.1.2.5 gives that instant the meaning "no well-defined expiration date", so a ceremony
// time that would give it is an [ErrParams].
//
// What is not guaranteed: that every verifier reads the certificate. Two were tried, the standard
// library and OpenSSL (`openssl verify` in strict mode, 3.5 and 3.6), on the forms that the profile
// and the vectors use and on the forms that the tests of this package built. A verifier with
// another rule for a name form may still refuse a certificate that these two read.
//
// What a policy allows is not asked here: whether the name constraints are inside the
// requester's zones, which key purposes are allowed. The policy refuses first (hand-off contract,
// "What the certifier checks", check 9) and sees the request through [ParseRequest].
//
// Copies: the request bytes, the issuer name, the issuer key and the serial are copied at the top of
// the call, and the body is built from the copies. A change that the caller makes to them after that
// has no effect, and one body is never built from two values of one parameter. A caller that writes
// them during the call has a data race of its own, which the race detector reports; the call does
// not panic and does not return a body that is not the body of the values it copied.
func IntermediateTBS(p IntermediateParams) ([]byte, error) {
	// What is read more than once is copied first, and the body is built from the copies only: the
	// request, the issuer name, the issuer key and the serial. A change that the caller makes to them
	// after this line has no effect, and a data race of the caller on them cannot make the call panic
	// or build a body from two values. (The race itself is the caller's; the race detector reports it
	// while the copy is taken.) The time is a value.
	p, err := copyIntermediate(p)
	if err != nil {
		return nil, err
	}
	if len(p.CSR) == 0 {
		return nil, fail(ErrParams, "no certificate request")
	}
	if err := checkTime("the ceremony time", p.CeremonyTime); err != nil {
		return nil, err
	}
	if err := CheckSerial(p.Serial); err != nil {
		return nil, err
	}
	issuer, err := readName("the issuer", p.IssuerSubject, ErrParams)
	if err != nil {
		return nil, err
	}
	// The issuer is the name of a root that this package's root builder writes ("<name> Root <label>",
	// and " (TEST ONLY)" after it for a test root), which the text rule of a subject accepts (printable
	// ASCII, single spaces, parentheses included), so it is held to the same rule.
	if err := checkNameText("the issuer", issuer, ErrParams); err != nil {
		return nil, err
	}
	_, issuerPoint, err := spki(p.IssuerKey)
	if err != nil {
		return nil, err
	}
	roots, err := readRoots(p.Roots, p.IssuerSubject, issuerPoint)
	if err != nil {
		return nil, err
	}
	notBefore := p.CeremonyTime.UTC()
	notAfter, err := AddMonths(notBefore, IntermediateValidityMonths)
	if err != nil {
		return nil, fail(ErrParams, "the end of the validity is not a date that a certificate holds (the years 1 to 9999)")
	}
	if err := checkEnd(notAfter); err != nil {
		return nil, err
	}

	req, err := ParseRequest(p.CSR)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(req.point, issuerPoint) {
		return nil, failRequest(CheckPolicy, "the key of the request is the key of the issuer")
	}
	if sameName(req.name, issuer) {
		return nil, failRequest(CheckPolicy, "the subject of the request is the name of the issuer, as OpenSSL compares names")
	}
	for _, r := range roots {
		if bytes.Equal(req.point, r.point) {
			return nil, failRequest(CheckPolicy, "the key of the request is the key of a root of the bundle")
		}
		if sameName(req.name, r.name) {
			return nil, failRequest(CheckPolicy, "the subject of the request is the name of a root of the bundle, as OpenSSL compares names")
		}
	}
	body, err := intermediateBody(p.Serial, p.IssuerSubject, notBefore, notAfter, req.subject, req.spki, keyIdentifier(req.point), keyIdentifier(issuerPoint), req.asked)
	if err != nil {
		// A request is at most MaxRequestSize, so only the issuer, which is the caller's, can make the
		// body too long: the fault is the issuer's, and the text says what is too long.
		return nil, failWith(ErrParams, "the issuer is too long to write", err)
	}
	if err := readable(body, p.Serial, notBefore, notAfter); err != nil {
		// Every reading before this one has accepted its input, and none of them can accept what the
		// standard library refuses (the name strings, the key, the dates, the serial and the extension
		// values are all read first, in the kind of their source): reaching here is a fault of this package, not of the request or of a parameter.
		return nil, failWith(ErrRequest, "the body is not a certificate that the standard library reads (a fault of this package: the readings before it accepted every input)", err)
	}
	return body, nil
}

// bundleRoot is a root of the bundle as read: its name and the point of its key.
type bundleRoot struct {
	name  name
	point []byte
}

// readRoots reads the roots of the bundle that IntermediateParams holds: the list is not empty, each
// name is read as an issuer is read, each key is ECDSA on P-384, the issuer is one of them, and no
// two entries share a name or a key unless they are one entry listed twice. It
// is the one place of the rule that a request is not for any root of the bundle (it is a small change
// to take it away: the list, this function and the loop that uses it).
func readRoots(refs []RootRef, issuerSubject, issuerPoint []byte) ([]bundleRoot, error) {
	if len(refs) == 0 {
		return nil, fail(ErrParams, "no roots of the bundle are given: the list of the roots, the issuer among them, is required")
	}
	out := make([]bundleRoot, 0, len(refs))
	hasIssuer := false
	// First entry of each canonical name and of each key, to refuse a name or a key that two roots hold.
	byName := make(map[string]int, len(refs))
	byKey := make(map[string]int, len(refs))
	for i, ref := range refs {
		n, err := readName("a root of the bundle", ref.Subject, ErrParams)
		if err != nil {
			return nil, err
		}
		if err := checkNameText("a root of the bundle", n, ErrParams); err != nil {
			return nil, err
		}
		_, point, err := spki(ref.Key)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(ref.Subject, issuerSubject) && bytes.Equal(point, issuerPoint) {
			hasIssuer = true
		}
		nameID, keyID := canonicalName(n), string(point)
		jn, sameN := byName[nameID]
		jk, sameK := byKey[keyID]
		if sameN && sameK && jn == jk && bytes.Equal(refs[jn].Subject, ref.Subject) {
			continue // the same root listed again
		}
		if sameK {
			return nil, fail(ErrParams, "two roots of the bundle have the same key and are not the same entry: one key stands under two names or under two forms of one name")
		}
		if sameN {
			return nil, fail(ErrParams, "two roots of the bundle have the same name, as OpenSSL compares names, and different keys")
		}
		byName[nameID], byKey[keyID] = i, i
		out = append(out, bundleRoot{name: n, point: point})
	}
	if !hasIssuer {
		return nil, fail(ErrParams, "the roots of the bundle do not hold the issuer: no root has the subject and the key of the issuer")
	}
	return out, nil
}

// checkEnd refuses the end of a validity that is 9999-12-31 23:59:59Z. RFC 5280, section 4.1.2.5:
// "To indicate that a certificate has no well-defined expiration date, the notAfter SHOULD be
// assigned the GeneralizedTime value of 99991231235959Z." A certificate that really ends then would
// be read as one that never ends, and the issuer "MUST ensure that no valid certification path exists
// for the certificate after maintenance of status information is terminated" for it, which a
// ceremony cannot promise, so the parameters that give that instant are refused.
func checkEnd(notAfter time.Time) error {
	if notAfter.UTC().Equal(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)) {
		return fail(ErrParams, "the end of the validity is 9999-12-31 23:59:59Z, which RFC 5280, section 4.1.2.5 gives the meaning no well-defined expiry")
	}
	return nil
}

// intermediateBody writes the TBSCertificate of an intermediate from its parts. It is the one
// place that does: [IntermediateTBS] writes a body with it, and [Assemble] writes a body with it
// again from the parts it reads back, and accepts the body only when the two are the same bytes (see
// readBody).
func intermediateBody(serial *big.Int, issuer []byte, notBefore, notAfter time.Time, subject, spkiDER, subjectID, issuerID []byte, r requested) ([]byte, error) {
	var exts [][]byte
	var firstErr error
	add := func(id asn1.ObjectIdentifier, critical bool, value []byte) {
		e, err := extension(id, critical, value)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		exts = append(exts, e)
	}
	add(oidBasicConstraints, true, basicConstraintsCA0)
	add(oidKeyUsage, true, r.keyUsage)
	add(oidNameConstraints, true, r.nameConstraints)
	add(oidExtKeyUsage, false, r.extKeyUsage)
	add(oidSubjectKeyID, false, subjectKeyIDValue(subjectID))
	add(oidAuthorityKeyID, false, authorityKeyIDValue(issuerID))
	if firstErr != nil {
		return nil, firstErr
	}
	return tbs(serial, issuer, notBefore, notAfter, subject, spkiDER, exts)
}

// requested holds the values of the extensions of a request, in the form they are issued.
type requested struct {
	keyUsage        []byte // always set
	nameConstraints []byte // always set: a request has name constraints
	nc              NameConstraints
	extKeyUsage     []byte // always set: a request has the extended key usage, not critical
}

// requestedExtensions reads the extensions of a request against the profile. The request has
// basic constraints, key usage, name constraints and extended key usage, each once (the contract's
// table of the request has no "optional" for any of the four). The values that the profile fixes are
// compared byte for byte.
func requestedExtensions(list []pkix.Extension) (requested, error) {
	var r requested
	seen := map[string]bool{}
	for _, e := range list {
		id := e.Id.String()
		if seen[id] {
			return r, failRequest(CheckPolicy, "the request has the extension %s twice", id)
		}
		seen[id] = true
		switch {
		case e.Id.Equal(oidBasicConstraints):
			if !e.Critical || !bytes.Equal(e.Value, basicConstraintsCA0) {
				return r, failRequest(CheckPolicy, "the basic constraints are not critical, cA true, path length 0")
			}
		case e.Id.Equal(oidKeyUsage):
			if !e.Critical {
				return r, failRequest(CheckPolicy, "the key usage is not critical")
			}
			if err := checkKeyUsage(e.Value); err != nil {
				return r, err
			}
			r.keyUsage = e.Value
		case e.Id.Equal(oidNameConstraints):
			if !e.Critical {
				return r, failRequest(CheckPolicy, "the name constraints are not critical")
			}
			nc, err := readNameConstraints(e.Value)
			if err != nil {
				return r, err
			}
			r.nameConstraints = e.Value
			r.nc = nc
		case e.Id.Equal(oidExtKeyUsage):
			if e.Critical {
				return r, failRequest(CheckPolicy, "the extended key usage is critical: the contract's request has it not critical")
			}
			if err := checkExtKeyUsage(e.Value); err != nil {
				return r, err
			}
			r.extKeyUsage = e.Value
		default:
			return r, failRequest(CheckPolicy, "the request has an extension outside the profile: %s", id)
		}
	}
	if !seen[oidBasicConstraints.String()] {
		return r, failRequest(CheckPolicy, "the request has no basic constraints")
	}
	if r.keyUsage == nil {
		return r, failRequest(CheckPolicy, "the request has no key usage")
	}
	if r.extKeyUsage == nil {
		return r, failRequest(CheckPolicy, "the request has no extended key usage: the hand-off contract's request has it, not critical, with serverAuth, clientAuth or both")
	}
	if r.nameConstraints == nil {
		return r, failRequest(CheckPolicy, "the request has no name constraints: the hand-off contract's request has them, with at least one permitted subtree")
	}
	return r, nil
}

// checkKeyUsage accepts a key usage of keyCertSign, with cRLSign and digitalSignature as the
// request table of the contract allows, in the one DER form (the named-bit form).
func checkKeyUsage(value []byte) error {
	var bits asn1.BitString
	if rest, err := asn1.Unmarshal(value, &bits); err != nil || len(rest) != 0 {
		return failRequest(CheckPolicy, "the key usage is not one DER bit string")
	}
	var set []int
	for i := 0; i < bits.BitLength; i++ {
		if bits.At(i) == 0 {
			continue
		}
		switch i {
		case usageDigitalSignature, usageKeyCertSign, usageCRLSign:
			set = append(set, i)
		default:
			return failRequest(CheckPolicy, "the key usage has the bit %d, which is not keyCertSign, cRLSign or digitalSignature", i)
		}
	}
	hasCertSign := false
	for _, b := range set {
		hasCertSign = hasCertSign || b == usageKeyCertSign
	}
	if !hasCertSign {
		return failRequest(CheckPolicy, "the key usage has no keyCertSign")
	}
	if !bytes.Equal(keyUsageValue(set...), value) {
		return failRequest(CheckPolicy, "the key usage is not in the named-bit DER form")
	}
	return nil
}

// The two key purposes that a request may name (RFC 5280, section 4.2.1.12; hand-off contract, the
// request table): the purposes of the certificates under an intermediate, a TLS server and a TLS client.
var (
	oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// checkExtKeyUsage accepts the extended key usage that the contract's request has (decided for
// version 1): one or two object identifiers in the DER form, serverAuth, clientAuth or both, each once,
// and nothing else: not anyExtendedKeyUsage, no other purpose, no purpose twice. The order is the
// request's and is kept in the certificate.
func checkExtKeyUsage(value []byte) error {
	var oids []asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(value, &oids); err != nil || len(rest) != 0 || len(oids) == 0 {
		return failRequest(CheckPolicy, "the extended key usage is not a non-empty list of object identifiers")
	}
	if again, err := asn1.Marshal(oids); err != nil || !bytes.Equal(again, value) {
		return failRequest(CheckPolicy, "the extended key usage is not in the DER form")
	}
	for i, o := range oids {
		if !o.Equal(oidServerAuth) && !o.Equal(oidClientAuth) {
			return failRequest(CheckPolicy, "the extended key usage names a purpose other than serverAuth and clientAuth")
		}
		for _, before := range oids[:i] {
			if before.Equal(o) {
				return failRequest(CheckPolicy, "the extended key usage names a purpose twice")
			}
		}
	}
	return nil
}
