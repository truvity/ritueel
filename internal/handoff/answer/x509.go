package answer

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/rootlist"
)

// begin starts the verdict of this call with the given checks, and the warnings of the held list at the clock
// that the call read.
func (r *run) begin(names []string) {
	r.v = newVerdict(names, r.s.floor)
	if !r.s.floor {
		h := &rootlist.Held{List: &rootlist.List{ExpiresAt: r.s.held.expires}}
		r.v.Warnings = rootlist.CheckHeld(h, r.now)
	}
}

// readResultFile runs check 1 and the reading of result.json, which is the first part of check 2, for the full
// contract (X.509 and OpenPGP). It returns the result, or nil when a check failed (the verdict says which) or an
// error when a reader broke its contract. A version that cannot be read is a fault of the form of the file,
// check 2, and check 1 is then not-run, as the certifier does for its proof file.
func (r *run) readResultFile() (*result, error) {
	file, ok := r.files[FileResult]
	if !ok {
		r.v.skip(1, reasonNoVersion)
		r.v.fail(2, CodeMalformed, "the answer has no result file")
		return nil, nil
	}
	if len(file) > MaxFileSize {
		r.v.skip(1, reasonNoVersion)
		r.v.fail(2, CodeMalformed, fmt.Sprintf("the result file is longer than %d bytes", MaxFileSize))
		return nil, nil
	}
	version, err := peekVersion(file)
	if err != nil {
		r.v.skip(1, reasonNoVersion)
		r.v.fail(2, CodeMalformed, err.Error())
		return nil, nil
	}
	if version != handoff.Version {
		r.v.fail(1, CodeVersionUnsupported, fmt.Sprintf("the version of the answer is %d, and the version that was sent is %d", version, handoff.Version))
		return nil, nil
	}
	r.v.pass(1)
	res, err := readResult(file)
	if err != nil {
		var shape shapeError
		if errors.As(err, &shape) {
			r.v.fail(2, CodeMalformed, shape.Error())
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// onlyFiles reports the fault of an answer that has a file other than the given suffixes, or lacks one of them,
// in fixed words. An empty string means the files are exactly these. A file longer than MaxFileSize is a fault.
func (r *run) onlyFiles(suffixes ...string) string {
	for _, s := range suffixes {
		f, ok := r.files[s]
		if !ok {
			return "the answer has no file " + s
		}
		if len(f) > MaxFileSize {
			return fmt.Sprintf("the file %s is longer than %d bytes", s, MaxFileSize)
		}
	}
	for k := range r.files {
		if !slices.Contains(suffixes, k) {
			return "the answer has a file that does not belong to an answer of this kind"
		}
	}
	return ""
}

// forThisRequest is check 3: the answer is for this request. The type is the request's, and request_sha256 is
// the digest of the requester's own request. It reports whether the check passed.
func (r *run) forThisRequest(res *result) bool {
	if res.typ != r.a.typ {
		r.v.fail(3, CodeRequestMismatch, "the type of the answer is not the type of the request")
		return false
	}
	if res.requestSHA256 != r.a.digest {
		r.v.fail(3, CodeRequestMismatch, "request_sha256 is not the digest of the request that was sent")
		return false
	}
	r.v.pass(3)
	return true
}

// readCertFile reads `<stem>.cert.pem`: one PEM block with the label CERTIFICATE by the strict rule, and a DER
// certificate that the standard reader accepts with no byte after it. The fault is in fixed words.
func (r *run) readCertFile() (*x509.Certificate, string, error) {
	der, err := pki.ReadPEMFile(r.files[FileCert], "CERTIFICATE")
	if err != nil {
		if errors.Is(err, pki.ErrPEM) {
			return nil, "the certificate file is not one PEM block of the form of the contract", nil
		}
		return nil, "", fmt.Errorf("%w: reading the certificate file: %w", ErrInternal, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "the certificate file does not hold one certificate", nil
	}
	return cert, "", nil
}

// checkX509 judges an answer to an x509-intermediate request by the nine checks of the full contract.
func (r *run) checkX509() (Verdict, error) {
	r.begin(x509Names[:])
	res, err := r.readResultFile()
	if err != nil || res == nil {
		return r.v, err
	}
	if res.outcome == outcomeRefused {
		return r.refusedAnswer(res, FileResult)
	}
	if fault := r.onlyFiles(FileResult, FileCert); fault != "" {
		r.v.fail(2, CodeMalformed, fault)
		return r.v, nil
	}
	cert, fault, err := r.readCertFile()
	if err != nil {
		return r.v, err
	}
	if fault != "" {
		r.v.fail(2, CodeMalformed, fault)
		return r.v, nil
	}
	r.v.pass(2)
	if !r.forThisRequest(res) {
		return r.v, nil
	}

	// Check 4: the certificate verifies to an anchor of the held list. This is the first of the two signature
	// verifications of an accepted answer; check 8 is the second.
	anc := r.verifiesToAnchor(res, cert)
	if anc == nil {
		return r.v, nil
	}
	r.v.pass(4)

	// Check 5: the public key is the key of the request.
	if fault := r.keyFault(cert); fault != "" {
		r.v.fail(5, CodeKeyMismatch, fault)
		return r.v, nil
	}
	r.v.pass(5)

	// Check 6: the profile is what was asked.
	if fault := profileFault(cert, r.a.csr, false); fault != "" {
		r.v.fail(6, CodeProfile, fault)
		return r.v, nil
	}
	r.v.pass(6)

	// Check 7: the validity.
	if fault := r.validityFault(cert.NotBefore, cert.NotAfter); fault != "" {
		r.v.fail(7, CodeValidity, fault)
		return r.v, nil
	}
	r.v.pass(7)

	// Check 8: the certificate is exactly the form of the page. pki.Assemble reads a body by the reader of the
	// builders and builds it again, so the two cannot disagree about what the page says; it also verifies the
	// signature once more, with the key of the anchor.
	whole, err := pki.Assemble(cert.RawTBSCertificate, cert.Signature, anc.key)
	if err != nil || !bytes.Equal(whole, cert.Raw) {
		r.v.fail(8, CodeProfile, "the certificate is not exactly the form of the page: serial, extensions, key identifiers, signature or the 13 months")
		return r.v, nil
	}
	r.v.pass(8)

	// Check 9: the digests and the dates of result.json match the files.
	if fault := r.digestsFault(res, FileCert); fault != "" {
		r.v.fail(9, CodeMalformed, fault)
		return r.v, nil
	}
	if !res.validFrom.Equal(cert.NotBefore) || !res.validUntil.Equal(cert.NotAfter) {
		r.v.fail(9, CodeMalformed, "valid_from or valid_until is not the validity of the certificate")
		return r.v, nil
	}
	r.v.pass(9)
	r.v.accept(Info{
		Type:          handoff.TypeX509,
		Stem:          r.stem,
		ValidFrom:     cert.NotBefore.UTC(),
		ValidUntil:    cert.NotAfter.UTC(),
		Issuer:        anc.pin,
		TrustSequence: res.trustSequence,
	})
	return r.v, nil
}

// refusedAnswer judges an answer in which the certifier refused the request: checks 1 to 3 have run on the
// form and the digest, the answer holds only the given files, and the rest of the checks are not-run. It is not
// accepted, and it is not a fault of the answer.
func (r *run) refusedAnswer(res *result, suffixes ...string) (Verdict, error) {
	if fault := r.onlyFiles(suffixes...); fault != "" {
		r.v.fail(2, CodeMalformed, fault)
		return r.v, nil
	}
	r.v.pass(2)
	if !r.forThisRequest(res) {
		return r.v, nil
	}
	r.v.refusedByCertifier(3, res.reasons)
	return r.v, nil
}

// verifiesToAnchor is check 4: in this order, issuer is a pin of the held list; trust_sequence is at most the
// sequence of the held list ("the requester holds a root list at least that recent", record 0006, rule 14); the
// certificate of the CA bundle with that pin is valid at the clock; the issuer name of the certificate is the
// subject of that certificate, as bytes; and the signature, which is ecdsa-with-SHA384, verifies over the body
// with its key. Only the anchor that the pin names is tried: no anchor is chosen by a name or by an order
// (record 0006, rules 23 and 52). It returns the anchor, or nil with the verdict failed.
func (r *run) verifiesToAnchor(res *result, cert *x509.Certificate) *anchor {
	fail := func(detail string) *anchor {
		r.v.fail(4, CodeIssuer, detail)
		return nil
	}
	if !slices.Contains(r.s.held.pins, res.issuer) {
		return fail("issuer is not a root of the root list that the requester holds")
	}
	if res.trustSequence > r.s.held.sequence {
		return fail(fmt.Sprintf("the answer needs trust sequence %d, and the root list that the requester holds is %d", res.trustSequence, r.s.held.sequence))
	}
	anc := r.s.held.anchors[res.issuer]
	if anc == nil || anc.key == nil {
		return fail("the anchor of the issuer is not an ECDSA key on P-384")
	}
	if r.now.Before(anc.cert.NotBefore) || r.now.After(anc.cert.NotAfter) {
		return fail("the anchor that the issuer names is not valid now")
	}
	if !bytes.Equal(cert.RawIssuer, anc.cert.RawSubject) {
		return fail("the issuer name of the certificate is not the name of the anchor")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return fail("the certificate is not signed with ecdsa-with-SHA384")
	}
	if err := anc.cert.CheckSignature(x509.ECDSAWithSHA384, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fail("the signature of the certificate does not verify with the key of the anchor")
	}
	return anc
}

// keyFault is check 5: the key of the certificate is an ECDSA key on P-384 and is the key of the request. It
// returns the fault in fixed words, or an empty string.
func (r *run) keyFault(cert *x509.Certificate) string {
	k := p384Key(cert)
	if k == nil {
		return "the key of the certificate is not an ECDSA key on P-384"
	}
	if !k.Equal(r.a.csr.PublicKey()) {
		return "the key of the certificate is not the key of the request"
	}
	return ""
}

// The object identifiers of the extensions of the profile.
var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// extName names an extension of the profile in words, and any other as "an extension" (its identifier is not
// a byte of the answer's text, but the name is shorter and enough).
func extName(id asn1.ObjectIdentifier) string {
	switch {
	case id.Equal(oidBasicConstraints):
		return "basic constraints"
	case id.Equal(oidKeyUsage):
		return "key usage"
	case id.Equal(oidNameConstraints):
		return "name constraints"
	case id.Equal(oidExtKeyUsage):
		return "extended key usage"
	case id.Equal(oidSubjectKeyID):
		return "subject key identifier"
	case id.Equal(oidAuthorityKeyID):
		return "authority key identifier"
	}
	return "an extension outside the profile"
}

// findExtension returns the extension with the identifier and how many there are.
func findExtension(list []pkix.Extension, id asn1.ObjectIdentifier) (pkix.Extension, int) {
	var found pkix.Extension
	n := 0
	for _, e := range list {
		if e.Id.Equal(id) {
			found = e
			n++
		}
	}
	return found, n
}

// profileFault is check 6, and slot 6 of the floor: the certificate is what the request asked, in fixed words.
// It returns the first fault, or an empty string. For the full contract (floor false) the certificate is version
// 3; its subject is the subject of the request, byte for byte; each of the four extensions of the request stands
// exactly once with the criticality and the value that the request has; the subject key identifier and the
// authority key identifier stand once, not critical; and no other extension stands at all. For the floor the
// four extensions are held the same way, and no extension beside them is critical: the key identifiers and the
// rest are the CA's own. A certificate with more than MaxExtensions extensions is refused before any extension
// is compared.
func profileFault(cert *x509.Certificate, req *pki.Request, floor bool) string {
	if cert.Version != 3 {
		return "the certificate is not version 3"
	}
	if !bytes.Equal(cert.RawSubject, req.Subject()) {
		return "the subject of the certificate is not the subject of the request"
	}
	if len(cert.Extensions) > MaxExtensions {
		return fmt.Sprintf("the certificate has more than %d extensions", MaxExtensions)
	}
	asked := req.Extensions()
	for _, want := range asked {
		got, n := findExtension(cert.Extensions, want.Id)
		switch {
		case n == 0:
			return "the certificate has no " + extName(want.Id)
		case n > 1: // the certificate parser of the standard library refuses an extension twice first, today
			return "the certificate has the " + extName(want.Id) + " twice"
		case got.Critical != want.Critical:
			return "the " + extName(want.Id) + " has another criticality than the one of the request"
		case !bytes.Equal(got.Value, want.Value):
			return "the value of the " + extName(want.Id) + " is not the one of the request"
		}
	}
	if floor {
		for _, e := range cert.Extensions {
			if e.Critical && !slices.ContainsFunc(asked, func(a pkix.Extension) bool { return a.Id.Equal(e.Id) }) {
				return "the certificate has a critical extension beside those of the profile"
			}
		}
		return ""
	}
	for _, id := range []asn1.ObjectIdentifier{oidSubjectKeyID, oidAuthorityKeyID} {
		got, n := findExtension(cert.Extensions, id)
		switch {
		case n == 0:
			return "the certificate has no " + extName(id)
		case n > 1: // the parser refuses an extension twice first, today
			return "the certificate has the " + extName(id) + " twice"
		case got.Critical: // the parser refuses a critical key identifier first, today
			return "the " + extName(id) + " is critical"
		}
	}
	if len(cert.Extensions) != len(asked)+2 {
		return "the certificate has an extension outside the profile"
	}
	return ""
}

// validityFault is check 7, and slot 7 of the floor, for a certificate: it is valid now (RFC 5280, section
// 4.1.2.5: the period is inclusive, so a certificate that ends at this second has not ended), and its length
// from notBefore to notAfter is between Min and Max calendar months. A certificate that has not started is a
// fault, with no tolerance for a clock that is behind. It returns the fault in fixed words.
func (r *run) validityFault(from, until time.Time) string {
	if r.now.Before(from) {
		return "the certificate is not valid yet"
	}
	if r.now.After(until) {
		return "the certificate has ended"
	}
	return r.s.lengthFault(from, until, "the certificate")
}

// lengthFault tells whether the length from from to until is between Min and Max calendar months, counted as
// the profile counts them ([pki.AddMonths]).
func (s *settings) lengthFault(from, until time.Time, what string) string {
	lo, err := pki.AddMonths(from, s.minMonths)
	if err != nil {
		return "the length of the validity of " + what + " cannot be measured"
	}
	hi, err := pki.AddMonths(from, s.maxMonths)
	if err != nil {
		return "the length of the validity of " + what + " cannot be measured"
	}
	if until.Before(lo) || until.After(hi) {
		return fmt.Sprintf("the length of the validity of %s is not between %d and %d months", what, s.minMonths, s.maxMonths)
	}
	return ""
}

// digestsFault is the first part of check 9: artifacts is exactly one entry, named for the file of the answer
// and holding the SHA-256 of its bytes ("one for each file of the answer other than this one"). It returns the
// fault in fixed words. The name is held to its form when result.json is read, and no byte of it is shown.
func (r *run) digestsFault(res *result, suffix string) string {
	if len(res.artifacts) != 1 {
		return "artifacts is not exactly one entry"
	}
	a := res.artifacts[0]
	if a.name != r.stem+"."+suffix {
		return "the artifact is not named for the file of the answer"
	}
	if a.sha256 != digestHex(r.files[suffix]) {
		return "the digest of the artifact is not the digest of the file"
	}
	return ""
}
