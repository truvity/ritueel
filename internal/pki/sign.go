package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"
	"slices"
)

// TBSDigest is the SHA-384 of the DER TBSCertificate: what the key signs. A card or a cloud key
// is given exactly this digest and nothing else (hand-off contract, "Keys and hashes").
func TBSDigest(tbs []byte) []byte {
	sum := sha512.Sum384(tbs)
	return sum[:]
}

// TBSSHA256 is the SHA-256 of the DER TBSCertificate as 64 lower-case hexadecimal digits: the
// "tbs_sha256" of a plan (docs/reference/ceremony-record.md, "The plan").
func TBSSHA256(tbs []byte) string {
	sum := sha256.Sum256(tbs)
	return hex.EncodeToString(sum[:])
}

// SignRoot signs the root body tbs through s and returns the signature, a DER ECDSA-Sig-Value. It
// signs only the body of these parameters: it builds the body again with [RootTBS] from p and signs
// only when that body is tbs, byte for byte. So the body that a person was shown, and whose
// [TBSSHA256] a plan names, is the body that is signed, and it is the body of the root key p.Key,
// with the name, the serial and the time that p says. The signer's public key must be p.Key, the key
// in the body, and is checked before the signer is called: a card that is not the root's is refused
// before the touch. Every refusal comes before the key is used. rnd is passed to s; crypto/rand is
// used when it is nil. The signature is made and checked as [SignIntermediate] says.
//
// An error from [RootTBS] is returned as it is (an [ErrParams]); a body that is not the one of the
// parameters, and a signer that is not p.Key, are an [ErrParams].
//
// Copies: the serial, the key and the body tbs are copied at the top of the call. The signer is
// asked for its public key once, and the key is copied before it is compared with the key that the
// body was built from, so a signer that changes the key object it handed out, or a caller that
// changes the key it passed, cannot make the card sign a body that does not name it. The signer's
// own methods are the signer's: a call of Sign that never returns is the caller's to bound.
func SignRoot(rnd io.Reader, s crypto.Signer, p RootParams, tbs []byte) ([]byte, error) {
	// The parameters and the body are copied first and only the copies are used: the key that is
	// compared with the signer's is the key that the body was built from, and the body that is
	// compared is the one that is signed.
	p, err := copyRoot(p)
	if err != nil {
		return nil, err
	}
	if tbs, err = copyBytes(tbs); err != nil {
		return nil, err
	}
	own, err := RootTBS(p)
	if err != nil {
		return nil, err
	}
	key, err := p384(p.Key)
	if err != nil {
		return nil, err
	}
	return signBody(rnd, s, key, own, tbs)
}

// SignIntermediate signs the intermediate body tbs through s and returns the signature, a DER
// ECDSA-Sig-Value. It signs only the body of these parameters: it builds the body again with
// [IntermediateTBS] from p, the request (as DER, the bytes that a policy was run on and whose SHA-256
// is the request_sha256) and everything else, and signs only when that body is tbs, byte for byte.
// So the body that a person was shown is the body that is signed, and it is the body of that request
// and of no other: a body read from a file, or one for a key that nobody holds a request for, is not
// signed. The signer's public key must be p.IssuerKey, the key whose identifier the body holds as its
// authority key identifier, and is checked before the signer is called: the wrong card of three is
// refused before the touch. Every refusal comes before the key is used. rnd is passed to s;
// crypto/rand is used when it is nil.
//
// The surface is two functions, one for each kind of body, and no function that signs a body alone:
// a body alone is only a form, which this package can check but whose origin it cannot know, and the
// parameters are what give it an origin. [Assemble] takes no parameters because it uses no key: it
// reads a body and a signature and verifies one against the other.
//
// After the signer returns, the signature is verified over the digest of the body, computed again
// from the package's own copy of the body (the signer is given a copy of the digest and never sees the
// body, so nothing a signer does to its arguments changes what is verified), with a copy of the key
// that was checked. No signature that does not verify is returned. An error from the signer is
// returned wrapped, so errors.Is and errors.As see it. A signature that does not verify, or is not
// the DER form (a signer that returns the raw r and s), is an error that wraps [ErrSignature].
//
// A signature with a high s is accepted. ECDSA allows both s and n-s for every signature, X.509
// does not ask for the low form (RFC 5480 and RFC 5758 say nothing of it), and a card or a cloud
// key may return either; both verify, so refusing one would refuse some honest signers.
//
// An error from [IntermediateTBS] is returned as it is: an [ErrRequest] for a request that is not
// issued, an [ErrParams] for a parameter. A body that is not the one of the parameters, and a signer
// that is not p.IssuerKey, are an [ErrParams].
//
// Copies: the request bytes, the issuer name, the issuer key, the serial and the body tbs are copied
// at the top of the call, and the signer's public key is asked for once and copied before it is
// compared (see [SignRoot]). The key that the signer is compared with is the copy that the body was
// built from.
func SignIntermediate(rnd io.Reader, s crypto.Signer, p IntermediateParams, tbs []byte) ([]byte, error) {
	// The parameters and the body are copied first and only the copies are used (see SignRoot).
	p, err := copyIntermediate(p)
	if err != nil {
		return nil, err
	}
	if tbs, err = copyBytes(tbs); err != nil {
		return nil, err
	}
	own, err := IntermediateTBS(p)
	if err != nil {
		return nil, err
	}
	key, err := p384(p.IssuerKey)
	if err != nil {
		return nil, err
	}
	return signBody(rnd, s, key, own, tbs)
}

// signBody signs own, which a builder has just written from the parameters, when the body that the
// caller has is the same bytes and the signer is the key that the parameters name as the one that
// signs.
func signBody(rnd io.Reader, s crypto.Signer, want *ecdsa.PublicKey, own, tbs []byte) ([]byte, error) {
	if isNil(s) {
		return nil, fail(ErrParams, "no signer")
	}
	if rnd == nil {
		rnd = rand.Reader
	} else if isNil(rnd) {
		return nil, fail(ErrParams, "the source of random numbers is a nil value")
	}
	if !bytes.Equal(own, tbs) {
		return nil, fail(ErrParams, "the body is not the body that the parameters give")
	}
	// The signer's key is asked for once, and what it returns is copied before anything is compared:
	// the signer cannot change the key that is checked by changing the object it handed out. The key
	// it is compared with, want, is the copy that the body was built from.
	pub, err := p384(s.Public())
	if err != nil {
		return nil, fail(ErrParams, "the public key of the signer is not an ECDSA key on P-384")
	}
	if !pub.Equal(want) {
		return nil, fail(ErrParams, "the key of the signer is not the key that signs the body of these parameters")
	}
	sig, err := s.Sign(rnd, TBSDigest(own), crypto.SHA384)
	if err != nil {
		return nil, failWith(ErrSignature, "the signer failed", err)
	}
	sig = slices.Clone(sig)
	if err := checkSignatureForm(sig); err != nil {
		return nil, err
	}
	// The digest is computed again from the body: the one that the signer was given may have been
	// written to.
	if !ecdsa.VerifyASN1(pub, TBSDigest(own), sig) {
		return nil, fail(ErrSignature, "the signature does not verify with the public key of the signer")
	}
	return sig, nil
}

// checkSignatureForm accepts a DER ECDSA-Sig-Value for P-384 in its one shortest form: a
// SEQUENCE of two positive INTEGERs below the order of the curve, and nothing after it.
func checkSignatureForm(sig []byte) error {
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &v)
	if err != nil || len(rest) != 0 || v.R == nil || v.S == nil {
		return fail(ErrSignature, "the signature is not a DER ECDSA value")
	}
	n := elliptic.P384().Params().N
	if v.R.Sign() <= 0 || v.S.Sign() <= 0 || v.R.Cmp(n) >= 0 || v.S.Cmp(n) >= 0 {
		return fail(ErrSignature, "the signature has a value outside the order of P-384")
	}
	if again, err := asn1.Marshal(v); err != nil || !bytes.Equal(again, sig) {
		return fail(ErrSignature, "the signature is not in the shortest DER form")
	}
	return nil
}

// Assemble returns the DER certificate
//
//	Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
//
// with ecdsa-with-SHA384 as the algorithm, from a body, a signature and the public key of the issuer.
// The signature is placed in the BIT STRING as it is. It makes no certificate that it would not
// accept as a whole:
//
//   - tbs must be of the form that [RootTBS] and [IntermediateTBS] write: the body is read, held to
//     the rules of the builders, and written again with their writers, and the two must be the same
//     bytes (see readBody). That is a check of form and not of origin: Assemble has no request and
//     no parameters, so it cannot know that a request stands behind the body. It uses no key, and a
//     certificate that it puts together signs nothing; [SignRoot] and [SignIntermediate] are where
//     a key is protected;
//   - issuer is the public key of the issuer, ECDSA on P-384: for a root body the key in the body,
//     for an intermediate body the key whose [KeyIdentifier] is the authority key identifier of
//     the body;
//   - the signature must be in the one DER form with values inside the order of P-384, and must
//     verify with issuer over the SHA-384 of tbs, computed here. A signature that was made for
//     another body, or by another key, is refused, whoever made it;
//   - the result must parse as an X.509 certificate that holds exactly these bytes as its
//     TBSCertificate.
//
// The issuer key is a parameter because an intermediate body holds only the identifier of its issuer's
// key, so the key cannot be read from the body, and without it the signature could not be verified.
// Copies: the body, the signature and the issuer key are copied at the top of the call. A signature
// with a high s is accepted, as in [SignIntermediate]. A body or a signature that is
// refused, and a key that is not the issuer's, give an error that
// wraps [ErrSignature]; an issuer that is not an ECDSA key on P-384 wraps [ErrParams].
func Assemble(tbs, signature []byte, issuer crypto.PublicKey) ([]byte, error) {
	// What is read more than once is copied first: the body, the signature and the key.
	tbs, err := copyBytes(tbs)
	if err != nil {
		return nil, err
	}
	if signature, err = copyBytes(signature); err != nil {
		return nil, err
	}
	pub, err := p384(issuer)
	if err != nil {
		return nil, fail(ErrParams, "the public key of the issuer is not an ECDSA key on P-384")
	}
	info, err := readBody(tbs, ErrSignature)
	if err != nil {
		return nil, err
	}
	if !info.issuedBy(pub) {
		return nil, fail(ErrSignature, "the key given is not the key that the body names as its issuer")
	}
	if err := checkSignatureForm(signature); err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(pub, TBSDigest(tbs), signature) {
		return nil, fail(ErrSignature, "the signature does not verify over the body with the key of the issuer")
	}
	cert, err := certificateOf(tbs, signature)
	if err != nil {
		return nil, failWith(ErrSignature, "the certificate cannot be written", err)
	}
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, failWith(ErrSignature, "the certificate does not parse", err)
	}
	if !bytes.Equal(parsed.RawTBSCertificate, tbs) || parsed.SignatureAlgorithm != x509.ECDSAWithSHA384 || !bytes.Equal(parsed.Signature, signature) {
		return nil, fail(ErrSignature, "the certificate does not hold the parts it was made of")
	}
	return cert, nil
}
