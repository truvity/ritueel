package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"time"
)

// A body is a TBSCertificate that a builder of this package returns: the output of [RootTBS] or of
// [IntermediateTBS]. [Assemble] accepts nothing else, so that a certificate is never put together
// from bytes of another form than the one this package writes. ([SignRoot] and [SignIntermediate] do
// not read a body: they build it again from the parameters.)
//
// Whether a body is one of them is decided by building it again. readBody reads the parts of the
// bytes it is given (the serial, the names, the dates, the key, the extensions), holds each part to
// the rules that the builder holds its own input to, writes a body from those parts with the
// builder's own writer, and accepts the bytes only if the two bodies are the same bytes. So a
// body that has an extra extension, a different order, a critical flag that the profile does not
// have, a name the builder would have refused, a length that is not the shortest, or any other
// difference, however small, is not accepted; and the rules cannot be one thing in the builder and
// another in the check, because there is one function for each.
//
// What the check cannot know is who asked for the body: it proves the form and not the origin. The
// request that an intermediate was built from is not in the body, so a body whose subject key has no
// request behind it passes. An intermediate body names its issuer by its authority key identifier,
// and a root body is self-signed, so the check also says which key may have signed it
// ([bodyInfo.issuedBy]).

// bodyInfo is what a body says about itself that a signature has to match.
type bodyInfo struct {
	root bool
	// key is the public key of the subject of a root: the key that signs it.
	key *ecdsa.PublicKey
	// authorityKeyID is the key identifier of the issuer of an intermediate.
	authorityKeyID []byte
}

// issuedBy tells whether pub is the key that signs the body: for a root body (the issuer is the
// subject, and there is no authority key identifier) the key in the body; for an intermediate body
// the key whose key identifier ([KeyIdentifier]) is the authority key identifier of the body.
func (b *bodyInfo) issuedBy(pub *ecdsa.PublicKey) bool {
	if b.root {
		return b.key.Equal(pub)
	}
	id, err := KeyIdentifier(pub)
	return err == nil && bytes.Equal(id, b.authorityKeyID)
}

// checkTBS accepts one DER SEQUENCE that starts with the version [0] 2, a serial, and the
// algorithm ecdsa-with-SHA384, the one that Assemble writes after it (RFC 5280, section 4.1.1.2:
// the two must be equal). The errors wrap kind.
func checkTBS(tbs []byte, kind error) error {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(tbs, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return fail(kind, "the TBSCertificate is not one DER sequence")
	}
	var version, serial, alg asn1.RawValue
	body := outer.Bytes
	for _, part := range []*asn1.RawValue{&version, &serial, &alg} {
		if body, err = asn1.Unmarshal(body, part); err != nil {
			return fail(kind, "the TBSCertificate does not start with a version, a serial and an algorithm")
		}
	}
	if !bytes.Equal(version.FullBytes, short(tagVersion, integer(big.NewInt(2)))) {
		return fail(kind, "the TBSCertificate is not version 3")
	}
	if !bytes.Equal(alg.FullBytes, algECDSAWithSHA384) {
		return fail(kind, "the algorithm of the TBSCertificate is not ecdsa-with-SHA384")
	}
	return nil
}

// placeholderSignature is a DER ECDSA-Sig-Value of the right form (r and s both 1). It is never
// returned: it only lets readBody and readable build a whole certificate.
var placeholderSignature = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}

// certificateOf puts a body into a certificate with a signature.
func certificateOf(body, signature []byte) ([]byte, error) {
	bits, err := tlv(tagBitString, []byte{0}, signature)
	if err != nil {
		return nil, err
	}
	return seq(body, algECDSAWithSHA384, bits)
}

// readable puts the body into a certificate with a placeholder signature and has the standard
// library read it. It returns an error unless the library accepts it as a version 3 certificate
// with ecdsa-with-SHA384, whose body bytes, serial and dates are the ones given. The builders call
// it last, so that nothing is signed that [Assemble] would refuse to put together.
func readable(body []byte, serial *big.Int, notBefore, notAfter time.Time) error {
	parsed, err := parseBody(body)
	if err != nil {
		return err
	}
	switch {
	case parsed.SerialNumber.Cmp(serial) != 0:
		return errors.New("the serial read back is not the one made")
	case !parsed.NotBefore.Equal(notBefore) || !parsed.NotAfter.Equal(notAfter):
		return errors.New("the dates read back are not the ones made")
	}
	return nil
}

// parseBody has the standard library read a body, in a certificate with a placeholder signature,
// and returns the certificate. It is an error unless the library accepts it as a version 3
// certificate with ecdsa-with-SHA384 that holds exactly these bytes as its body.
func parseBody(body []byte) (*x509.Certificate, error) {
	cert, err := certificateOf(body, placeholderSignature)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	switch {
	case !bytes.Equal(parsed.RawTBSCertificate, body):
		return nil, errors.New("the body read back is not the body made")
	case parsed.Version != 3 || parsed.SignatureAlgorithm != x509.ECDSAWithSHA384:
		return nil, errors.New("the version or the algorithm read back is not the one made")
	}
	return parsed, nil
}

// readBody decides whether tbs is a body that a builder returns (see above) and says which key may
// sign it. Every error wraps kind; the cause, when there is one, is wrapped too.
func readBody(tbs []byte, kind error) (*bodyInfo, error) {
	if len(tbs) > maxBodyLen {
		return nil, fail(kind, "the body is longer than %d octets, the most that a certificate can hold", maxBodyLen)
	}
	if err := checkTBS(tbs, kind); err != nil {
		return nil, err
	}
	parsed, err := parseBody(tbs)
	if err != nil {
		return nil, rekind(kind, "the body is not a certificate that the standard library reads", err)
	}
	if err := CheckSerial(parsed.SerialNumber); err != nil {
		return nil, rekind(kind, "the serial of the body is not one of the profile", err)
	}
	for _, t := range []struct {
		what string
		at   time.Time
	}{{"notBefore", parsed.NotBefore}, {"notAfter", parsed.NotAfter}} {
		if err := checkTime(t.what+" of the body", t.at); err != nil {
			return nil, rekind(kind, "a date of the body is not one of the profile", err)
		}
	}
	if !parsed.NotAfter.After(parsed.NotBefore) {
		return nil, fail(kind, "the body ends before it starts")
	}
	pub, err := p384(parsed.PublicKey)
	if err != nil {
		return nil, rekind(kind, "the key of the body is not ECDSA on P-384", err)
	}
	canonical, point, err := spki(pub)
	if err != nil || !bytes.Equal(canonical, parsed.RawSubjectPublicKeyInfo) {
		return nil, fail(kind, "the key of the body is not in the canonical form")
	}

	var rebuilt []byte
	var info *bodyInfo
	if bytes.Equal(parsed.RawIssuer, parsed.RawSubject) {
		info = &bodyInfo{root: true, key: pub}
		rebuilt, err = rebuildRoot(parsed, canonical, point, kind)
	} else {
		info = &bodyInfo{}
		rebuilt, info.authorityKeyID, err = rebuildIntermediate(parsed, canonical, point, kind)
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rebuilt, tbs) {
		return nil, fail(kind, "the body is not the body that a builder of this package writes from its parts")
	}
	return info, nil
}

// rebuildRoot writes a body again from the parts of a self-signed body: the name is the common
// name of a root, which [RootCommonName] has to be able to make.
func rebuildRoot(parsed *x509.Certificate, canonical, point []byte, kind error) ([]byte, error) {
	subject, err := readName("the subject of the body", parsed.RawSubject, kind)
	if err != nil {
		return nil, err
	}
	if len(subject) != 1 || len(subject[0]) != 1 || !subject[0][0].typ.Equal(oidCommonName) || subject[0][0].tag != tagUTF8String {
		return nil, fail(kind, "the name of a root body is not one common name as a UTF8String")
	}
	cn := string(subject[0][0].value)
	if !isRootCommonName(cn) {
		return nil, fail(kind, "the common name of a root body is not one that RootCommonName makes")
	}
	body, err := rootBody(parsed.SerialNumber, cn, parsed.NotBefore, canonical, point)
	if err != nil {
		return nil, rekind(kind, "the body cannot be written", err)
	}
	return body, nil
}

// isRootCommonName tells whether cn is a name that [RootCommonName] returns: "<name> Root <label>",
// with the mark of a test root at its end for a test root.
func isRootCommonName(cn string) bool {
	rest := cn
	test := strings.HasSuffix(rest, testMark)
	if test {
		rest = strings.TrimSuffix(rest, testMark)
	}
	const tail = len(" Root X")
	if len(rest) <= tail || rest[len(rest)-tail:len(rest)-1] != " Root " {
		return false
	}
	got, err := RootCommonName(rest[:len(rest)-tail], rest[len(rest)-1:], test)
	return err == nil && got == cn
}

// rebuildIntermediate writes a body again from the parts of a body that has another issuer than its
// subject, holding each part to the rule that [IntermediateTBS] holds it to, and returns the
// authority key identifier that the body names.
func rebuildIntermediate(parsed *x509.Certificate, canonical, point []byte, kind error) ([]byte, []byte, error) {
	issuer, err := readName("the issuer of the body", parsed.RawIssuer, kind)
	if err != nil {
		return nil, nil, err
	}
	if err := checkNameText("the issuer of the body", issuer, kind); err != nil {
		return nil, nil, err
	}
	subject, err := readName("the subject of the body", parsed.RawSubject, kind)
	if err != nil {
		return nil, nil, err
	}
	if err := checkNameText("the subject of the body", subject, kind); err != nil {
		return nil, nil, err
	}
	// The end is the start moved by the 13 months of the profile, as the builder makes it.
	if end, err := AddMonths(parsed.NotBefore, IntermediateValidityMonths); err != nil || !end.Equal(parsed.NotAfter) {
		return nil, nil, fail(kind, "the validity of the body is not 13 calendar months from its start")
	}
	if err := checkEnd(parsed.NotAfter); err != nil {
		return nil, nil, rekind(kind, "the end of the validity of the body is not one of the profile", err)
	}
	// The last two extensions of an intermediate are the subject and the authority key identifier;
	// the others are the extensions of the request, which the profile reads as it reads a request.
	list := parsed.Extensions
	if n := len(list); n < 4 || !list[n-2].Id.Equal(oidSubjectKeyID) || !list[n-1].Id.Equal(oidAuthorityKeyID) {
		return nil, nil, fail(kind, "the body does not end with a subject key identifier and an authority key identifier")
	}
	asked, err := requestedExtensions(list[:len(list)-2])
	if err != nil {
		return nil, nil, rekind(kind, "the extensions of the body are not those of the profile", err)
	}
	aki := parsed.AuthorityKeyId
	if len(aki) != keyIDLen {
		return nil, nil, fail(kind, "the authority key identifier of the body is not 20 octets")
	}
	subjectID := keyIdentifier(point)
	if bytes.Equal(aki, subjectID) {
		return nil, nil, fail(kind, "the key of the body is the key of its issuer")
	}
	if sameName(subject, issuer) {
		return nil, nil, fail(kind, "the subject of the body is the name of its issuer, as OpenSSL compares names")
	}
	body, err := intermediateBody(parsed.SerialNumber, parsed.RawIssuer, parsed.NotBefore, parsed.NotAfter, parsed.RawSubject, canonical, subjectID, aki, asked)
	if err != nil {
		return nil, nil, rekind(kind, "the body cannot be written", err)
	}
	return body, aki, nil
}
