package answer

import (
	"bytes"
	"crypto/x509"

	"ritueel.id/ritueel/internal/handoff"
)

// checkFloor judges an answer to an x509-intermediate request by the floor ("The floor: PKCS#10 in, X.509 out"):
// the answer is one file, `<stem>.cert.pem`, issued by any CA that can be configured to the profile, and there
// is no result file. The nine slots are those of the full contract; slots 1, 3, 8 and 9 cannot be run and are
// fixed as not-run, with their reasons, and are never reported as passed. [Checker.Check] has already refused a
// request that is not of type x509-intermediate and an answer that has a result file.
//
// The anchors are the certificates that the operator installed, and nothing else. No chain is built: the issuing
// certificate must itself be installed. The page says that the certificate verifies to a certificate that the
// operator installed and does not say that a path is built through others, so the smallest refusal is built (see
// issuerInstalled).
func (r *run) checkFloor() (Verdict, error) {
	r.begin(floorNames[:])
	// Slot 2: the files. The answer is one certificate file and nothing else.
	if fault := r.onlyFiles(FileCert); fault != "" {
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

	// Slot 4: the certificate verifies to a CA certificate that the operator installed.
	anc, fault := r.issuerInstalled(cert)
	if anc == nil {
		r.v.fail(4, CodeIssuer, fault)
		return r.v, nil
	}
	r.v.pass(4)

	// Slot 5: the public key is the key of the request.
	if fault := r.keyFault(cert); fault != "" {
		r.v.fail(5, CodeKeyMismatch, fault)
		return r.v, nil
	}
	r.v.pass(5)

	// Slot 6: the profile, with nothing critical beside the four extensions of the request.
	if fault := profileFault(cert, r.a.csr, true); fault != "" {
		r.v.fail(6, CodeProfile, fault)
		return r.v, nil
	}
	r.v.pass(6)

	// Slot 7: the validity, with the same Min and Max as the full contract.
	if fault := r.validityFault(cert.NotBefore, cert.NotAfter); fault != "" {
		r.v.fail(7, CodeValidity, fault)
		return r.v, nil
	}
	r.v.pass(7)

	r.v.accept(Info{
		Type:       handoff.TypeX509,
		Stem:       r.stem,
		ValidFrom:  cert.NotBefore.UTC(),
		ValidUntil: cert.NotAfter.UTC(),
		Issuer:     anc.pin,
	})
	return r.v, nil
}

// issuerInstalled is slot 4 of the floor: among the installed certificates, one whose key verifies the
// signature of the certificate, that is valid at the clock, and that [x509.Certificate.CheckSignatureFrom]
// accepts as its issuer. That one call judges that the installed certificate is a CA with the certificate-signing
// key usage (when it names a key usage) and refuses a signature made with SHA-1 or MD5. The issuer name of the
// certificate is only a filter on the installed set: it picks the candidates, at most MaxAnchors, and what decides
// is that the key of an installed certificate verifies the signature, so no anchor is chosen by a name alone
// (record 0006, rule 23). It returns the anchor, or nil and the fault in fixed words.
func (r *run) issuerInstalled(cert *x509.Certificate) (*anchor, string) {
	fault := "the certificate does not verify to a CA certificate that the operator installed"
	for _, anc := range r.s.floorAnchors {
		if !bytes.Equal(anc.cert.RawSubject, cert.RawIssuer) {
			continue
		}
		if r.now.Before(anc.cert.NotBefore) || r.now.After(anc.cert.NotAfter) {
			fault = "the installed CA certificate that issued it is not valid now"
			continue
		}
		if err := cert.CheckSignatureFrom(anc.cert); err != nil {
			continue
		}
		return anc, ""
	}
	return nil, fault
}
