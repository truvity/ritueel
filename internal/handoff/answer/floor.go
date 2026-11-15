package answer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
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
// signature of the certificate, that is valid at the clock, that is held to the list of keys and signature
// algorithms of the floor (see [floorListFault]), and that [x509.Certificate.CheckSignatureFrom] accepts as its
// issuer. That one call judges that the installed certificate is a CA with the certificate-signing key usage
// (when it names a key usage) and that its key verifies the signature. The issuer name of the certificate is only
// a filter on the installed set: it picks the candidates, at most MaxAnchors, and what decides is that the key of
// an installed certificate verifies the signature, so no anchor is chosen by a name alone (record 0006, rule 23).
// The list is applied to each candidate before its signature is verified, so no signature is verified with a key
// or an algorithm outside the list. When several candidates fail for different reasons, the fault that stands is
// the one of the furthest step: not valid now, then the key, then the signature algorithm; a signature that does
// not verify leaves the fault as it stands. It returns the anchor, or nil and the fault in fixed words.
func (r *run) issuerInstalled(cert *x509.Certificate) (*anchor, string) {
	const (
		faultNone     = "the certificate does not verify to a CA certificate that the operator installed"
		faultNotValid = "the installed CA certificate that issued it is not valid now"
	)
	fault, step := faultNone, 0
	note := func(f string, s int) {
		if s > step {
			fault, step = f, s
		}
	}
	for _, anc := range r.s.floorAnchors {
		if !bytes.Equal(anc.cert.RawSubject, cert.RawIssuer) {
			continue
		}
		if r.now.Before(anc.cert.NotBefore) || r.now.After(anc.cert.NotAfter) {
			note(faultNotValid, 1)
			continue
		}
		if f := floorListFault(anc.cert, cert); f != "" {
			if f == floorKeyFault {
				note(f, 2)
			} else {
				note(f, 3)
			}
			continue
		}
		if err := cert.CheckSignatureFrom(anc.cert); err != nil {
			continue
		}
		return anc, ""
	}
	return nil, fault
}

// The words of the refusals of the list of the floor.
const (
	floorKeyFault = "the key of the installed CA certificate is not ECDSA on P-256, P-384 or P-521, Ed25519, or RSA of 2048 bits or more"
	floorSigFault = "the signature algorithm of the certificate is not ECDSA or RSA with SHA-256, SHA-384 or SHA-512, or Ed25519"
)

// floorListFault is the one place where the list of keys and signature algorithms of the floor stands. It is the
// sentence of the page docs/reference/hand-off-contract.md, "The floor": "The requester accepts a CA certificate
// with an ECDSA key on P-256, P-384 or P-521, an Ed25519 key, or an RSA key of 2048 bits or more, signed with
// SHA-256, SHA-384 or SHA-512, or with Ed25519. It refuses any other key or signature, a SHA-1 or MD5 signature
// included." The key is the key of the installed CA certificate ca; the signature algorithm is the one of the
// answer, cert. The signature algorithm is read from the certificate as the standard library parsed it (an
// ECDSA or RSA signature, PKCS #1 version 1.5 or PSS, with one of the three hashes, or Ed25519); a signature
// algorithm that the library does not know is refused. It returns the fixed words of the rule that is broken and
// or an empty string when both are on the list. The full contract does not use it: it keeps ECDSA on P-384 with SHA-384 only.
func floorListFault(ca, cert *x509.Certificate) string {
	switch k := ca.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if c := k.Curve; c != elliptic.P256() && c != elliptic.P384() && c != elliptic.P521() {
			return floorKeyFault
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N == nil || k.N.BitLen() < 2048 {
			return floorKeyFault
		}
	default:
		return floorKeyFault
	}
	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.PureEd25519:
		return ""
	}
	return floorSigFault
}
