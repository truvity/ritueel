package trustset

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"

	"ritueel.id/ritueel/internal/jws"
)

// Signer is one root key's signature, whatever key store holds the key. One Signer stands for one
// root key. A Signer is untrusted: its certificate is read for the public key and the pin, and
// every signature it returns is verified with the key of that certificate before it is used.
type Signer interface {
	// Label is the label of the root key: one of A to Z.
	Label() string
	// Certificate is the certificate that goes into x5c: the key's own certificate. It is read to
	// take the public key and the pin; it is not trusted.
	Certificate() *x509.Certificate
	// SignES384 signs the JWS signing input (protected || "." || BASE64URL(payload)) and returns r
	// and s as 96 bytes. It may wait for a person (a touch). It is called at most once for one
	// document, and never before every refusal that can be found without the key has been made.
	SignES384(input []byte) ([]byte, error)
}

// keySigner is a Signer over a crypto.Signer.
type keySigner struct {
	label string
	cert  *x509.Certificate
	key   crypto.Signer
}

// NewKeySigner adapts a keystore.Key (any crypto.Signer on P-384 that signs a SHA-384 digest and
// returns an ASN.1 ECDSA value) to a Signer. It refuses a nil key, a nil certificate, a certificate
// whose key is not the key's public key, a key that is not ECDSA on P-384, and a label that is
// not one of A to Z. SignES384 hashes the input with SHA-384, calls the key with crypto.SHA384,
// reads the ASN.1 value with encoding/asn1 (two positive integers below the order of the curve,
// nothing after them, in the one shortest form) and returns r and s each as 48 bytes. The Signer
// never gives its key, and prints nothing but its label.
func NewKeySigner(label string, cert *x509.Certificate, key crypto.Signer) (Signer, error) {
	if !isLabel(label) {
		return nil, fail(ErrParams, "the label is not one upper-case letter A to Z")
	}
	if key == nil {
		return nil, fail(ErrParams, "there is no key")
	}
	own, pub, err := ownCertificate(cert)
	if err != nil {
		return nil, err
	}
	keyPub, err := publicOf(key)
	if err != nil {
		return nil, err
	}
	if !pub.Equal(keyPub) {
		return nil, fail(ErrParams, "the certificate holds another key than the key")
	}
	return &keySigner{label: label, cert: own, key: key}, nil
}

// publicOf returns the public key of a crypto.Signer, which must be ECDSA on P-384. A key whose
// method panics (a nil pointer in an interface) is refused, not followed.
func publicOf(key crypto.Signer) (pub *ecdsa.PublicKey, err error) {
	defer func() {
		if recover() != nil {
			pub, err = nil, fail(ErrParams, "the key has no public key")
		}
	}()
	p, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || p == nil || p.Curve != elliptic.P384() {
		return nil, fail(ErrParams, "the key is not an ECDSA key on P-384")
	}
	if _, err := p.Bytes(); err != nil {
		return nil, fail(ErrParams, "the key is not a point on P-384")
	}
	return p, nil
}

// Label returns the label of the root key.
func (k *keySigner) Label() string { return k.label }

// Certificate returns the certificate of the root key.
func (k *keySigner) Certificate() *x509.Certificate { return k.cert }

// SignES384 signs input with the key and returns r and s as 96 bytes.
func (k *keySigner) SignES384(input []byte) ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fail(ErrSign, "there is no key")
	}
	digest := sha512.Sum384(input)
	der, err := k.key.Sign(rand.Reader, digest[:], crypto.SHA384)
	if err != nil {
		return nil, failWith(ErrSign, "the key could not sign", err)
	}
	return rawSignature(der)
}

// Format prints the label and nothing else, whatever the verb: a key that a program prints with
// %v or %#v must not show its parts.
func (k *keySigner) Format(f fmt.State, _ rune) {
	label := "?"
	if k != nil {
		label = k.label
	}
	_, _ = fmt.Fprintf(f, "trustset.Signer(%s)", label)
}

// rawSignature turns the ASN.1 ECDSA value of a key into r and s, 48 bytes each. It takes two
// positive integers below the order of the curve in the one shortest form and nothing after them.
func rawSignature(der []byte) ([]byte, error) {
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil || len(rest) != 0 || v.R == nil || v.S == nil {
		return nil, fail(ErrSign, "the signature of the key is not one ASN.1 ECDSA value")
	}
	// The reader of Go takes some forms that DER does not; the value must be what is written again.
	if again, err := asn1.Marshal(v); err != nil || !bytes.Equal(again, der) {
		return nil, fail(ErrSign, "the signature of the key is not in the one shortest ASN.1 form")
	}
	order := elliptic.P384().Params().N
	if v.R.Sign() <= 0 || v.S.Sign() <= 0 || v.R.Cmp(order) >= 0 || v.S.Cmp(order) >= 0 {
		return nil, fail(ErrSign, "r or s of the signature is not from 1 to the order of the curve minus 1")
	}
	out := make([]byte, jws.SignatureSize)
	v.R.FillBytes(out[:jws.SignatureSize/2])
	v.S.FillBytes(out[jws.SignatureSize/2:])
	return out, nil
}

// ownCertificate takes a certificate from outside: not nil, of at most MaxBytes, and read again
// from a copy of its own DER, so that the key and the pin that are used are the ones the DER holds
// and not those of a struct that someone filled, and so that nothing the caller does later reaches
// them. The key must be ECDSA on P-384. It returns the certificate
// that was read again and its key.
func ownCertificate(cert *x509.Certificate) (*x509.Certificate, *ecdsa.PublicKey, error) {
	if cert == nil {
		return nil, nil, fail(ErrParams, "there is no certificate")
	}
	if len(cert.Raw) == 0 || len(cert.Raw) > MaxBytes {
		return nil, nil, fail(ErrParams, "the certificate has no DER or is longer than %d bytes", MaxBytes)
	}
	// A parsed certificate keeps the bytes it was parsed from; parse a copy, so that a caller who
	// changes its bytes later changes nothing in the signer.
	own, err := x509.ParseCertificate(slices.Clone(cert.Raw))
	if err != nil {
		return nil, nil, fail(ErrParams, "the certificate is not one DER certificate")
	}
	if err := checkKey(own); err != nil {
		return nil, nil, fail(ErrParams, "the certificate: %v", err)
	}
	pub, _ := own.PublicKey.(*ecdsa.PublicKey)
	return own, pub, nil
}

// signerInfo is what the builder takes from a Signer before it asks it to sign.
type signerInfo struct {
	label string
	cert  *x509.Certificate
	pub   *ecdsa.PublicKey
	pin   string
}

// inspect reads the label and the certificate of a Signer, once, and takes the key and the pin
// from the certificate. A nil Signer, a label that is not A to Z and a certificate that is nil or
// whose key is not ECDSA on P-384 are ErrParams; a Signer that panics is ErrSign. No key is asked.
func inspect(s Signer) (info signerInfo, err error) {
	if s == nil {
		return signerInfo{}, fail(ErrParams, "there is no signer")
	}
	defer func() {
		if recover() != nil {
			info, err = signerInfo{}, fail(ErrSign, "the signer panicked")
		}
	}()
	label, cert := s.Label(), s.Certificate()
	if !isLabel(label) {
		return signerInfo{}, fail(ErrParams, "the label of the signer is not one upper-case letter A to Z")
	}
	own, pub, err := ownCertificate(cert)
	if err != nil {
		return signerInfo{}, err
	}
	return signerInfo{label: label, cert: own, pub: pub, pin: jws.Pin(own)}, nil
}

// ask asks the signer once for a signature over input and returns it only when it is 96 bytes and
// verifies with the key of the certificate. The signer gets a copy of input, a copy of its answer
// is what is verified and returned, and a panic is an error. Every fault is ErrSign.
func ask(s Signer, info signerInfo, input []byte) (sig []byte, err error) {
	defer func() {
		if recover() != nil {
			sig, err = nil, fail(ErrSign, "the signer of %s panicked", info.label)
		}
	}()
	got, err := s.SignES384(slices.Clone(input))
	if err != nil {
		return nil, failWith(ErrSign, "the signer of "+info.label+" failed", err)
	}
	if len(got) != jws.SignatureSize {
		return nil, fail(ErrSign, "the signer of %s returned %d bytes, ES384 needs %d", info.label, len(got), jws.SignatureSize)
	}
	sig = slices.Clone(got)
	if err := jws.VerifyES384(info.pub, input, sig); err != nil {
		return nil, fail(ErrSign, "the signature of %s does not verify with the key of its certificate", info.label)
	}
	return sig, nil
}
