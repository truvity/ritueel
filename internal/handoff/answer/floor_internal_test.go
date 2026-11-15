package answer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

// The list of the floor, read directly: the key and the algorithm are the fields of a certificate that was
// built by hand, so that a case that no parsed certificate can show (a key with no modulus, an algorithm number
// that the library does not name) is still held to the sentence of the page "The floor".

const (
	listedOK = ""
	listKeyF = floorKeyFault
	listSigF = floorSigFault
)

// the fixed words, as the page of the tests names them
func TestTheWordsOfTheFloorListAreTheFixedWords(t *testing.T) {
	if floorKeyFault != "the key of the installed CA certificate is not ECDSA on P-256, P-384 or P-521, Ed25519, or RSA of 2048 bits or more" {
		t.Errorf("key words %q", floorKeyFault)
	}
	if floorSigFault != "the signature algorithm of the certificate is not ECDSA or RSA with SHA-256, SHA-384 or SHA-512, or Ed25519" {
		t.Errorf("signature words %q", floorSigFault)
	}
	if floorKeyFault == floorSigFault {
		t.Error("the two rules have the same words")
	}
}

// modulus returns an odd number of exactly n bits.
func modulus(n int) *big.Int {
	m := new(big.Int).Lsh(big.NewInt(1), uint(n-1))
	return m.Or(m, big.NewInt(1))
}

func TestFloorListFaultHoldsTheKeyToTheSentence(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		key  any
		want string
	}{
		{"ECDSA on P-224", &p224.PublicKey, listKeyF},
		{"ECDSA on P-256", &ecdsa.PublicKey{Curve: elliptic.P256()}, listedOK},
		{"ECDSA on P-384", &ecdsa.PublicKey{Curve: elliptic.P384()}, listedOK},
		{"ECDSA on P-521", &ecdsa.PublicKey{Curve: elliptic.P521()}, listedOK},
		{"ECDSA with no curve", &ecdsa.PublicKey{}, listKeyF},
		{"Ed25519", ed, listedOK},
		{"a pointer to an Ed25519 key", &ed, listKeyF},
		{"RSA of 1 bit", &rsa.PublicKey{N: modulus(1), E: 65537}, listKeyF},
		{"RSA of 1024 bits", &rsa.PublicKey{N: modulus(1024), E: 65537}, listKeyF},
		{"RSA of 2047 bits", &rsa.PublicKey{N: modulus(2047), E: 65537}, listKeyF},
		{"RSA of 2048 bits", &rsa.PublicKey{N: modulus(2048), E: 65537}, listedOK},
		{"RSA of 2049 bits", &rsa.PublicKey{N: modulus(2049), E: 65537}, listedOK},
		{"RSA of 3072 bits", &rsa.PublicKey{N: modulus(3072), E: 65537}, listedOK},
		{"RSA of 16384 bits", &rsa.PublicKey{N: modulus(16384), E: 65537}, listedOK},
		{"RSA with no modulus", &rsa.PublicKey{}, listKeyF},
		{"RSA with a zero modulus", &rsa.PublicKey{N: new(big.Int)}, listKeyF},
		{"RSA as a value, not a pointer", rsa.PublicKey{N: modulus(2048), E: 65537}, listKeyF},
		{"ECDSA as a value, not a pointer", ecdsa.PublicKey{Curve: elliptic.P256()}, listKeyF},
		{"no key", nil, listKeyF},
		{"a key of another type", struct{}{}, listKeyF},
	} {
		t.Run(c.name, func(t *testing.T) {
			ca := &x509.Certificate{PublicKey: c.key}
			cert := &x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA256}
			if got := floorListFault(ca, cert); got != c.want {
				t.Errorf("fault %q, want %q", got, c.want)
			}
		})
	}
}

// Every signature algorithm that the library names, and numbers that it does not, against the ten rows of the
// sentence: ECDSA and RSA (PKCS #1 version 1.5 and PSS) with SHA-256, SHA-384 and SHA-512, and Ed25519.
func TestFloorListFaultHoldsTheSignatureToTheSentence(t *testing.T) {
	listed := map[x509.SignatureAlgorithm]bool{
		x509.ECDSAWithSHA256: true, x509.ECDSAWithSHA384: true, x509.ECDSAWithSHA512: true,
		x509.SHA256WithRSA: true, x509.SHA384WithRSA: true, x509.SHA512WithRSA: true,
		x509.SHA256WithRSAPSS: true, x509.SHA384WithRSAPSS: true, x509.SHA512WithRSAPSS: true,
		x509.PureEd25519: true,
	}
	ca := &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384()}}
	n := 0
	for alg := x509.SignatureAlgorithm(-3); alg < 40; alg++ {
		want := listSigF
		if listed[alg] {
			want, n = listedOK, n+1
		}
		if got := floorListFault(ca, &x509.Certificate{SignatureAlgorithm: alg}); got != want {
			t.Errorf("%v (%d): fault %q, want %q", alg, int(alg), got, want)
		}
	}
	if n != 10 {
		t.Errorf("%d rows of the list were met, the sentence has 10", n)
	}
	// Named refusals, so that a failure says which row broke.
	for _, alg := range []x509.SignatureAlgorithm{
		x509.UnknownSignatureAlgorithm, x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1,
		x509.DSAWithSHA256, x509.ECDSAWithSHA1,
	} {
		if got := floorListFault(ca, &x509.Certificate{SignatureAlgorithm: alg}); got != listSigF {
			t.Errorf("%v: fault %q", alg, got)
		}
	}
}

// The key rule is asked first: a certificate that breaks both rules is refused with the key words, and a key that
// is on the list with an algorithm that is not gives the algorithm words.
func TestFloorListFaultAsksTheKeyFirst(t *testing.T) {
	weak := &x509.Certificate{PublicKey: &rsa.PublicKey{N: modulus(1024), E: 65537}}
	good := &x509.Certificate{PublicKey: &rsa.PublicKey{N: modulus(2048), E: 65537}}
	sha1 := &x509.Certificate{SignatureAlgorithm: x509.SHA1WithRSA}
	sha256 := &x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA}
	for _, c := range []struct {
		name     string
		ca, cert *x509.Certificate
		want     string
	}{
		{"both broken", weak, sha1, listKeyF},
		{"the key broken", weak, sha256, listKeyF},
		{"the algorithm broken", good, sha1, listSigF},
		{"neither broken", good, sha256, listedOK},
	} {
		if got := floorListFault(c.ca, c.cert); got != c.want {
			t.Errorf("%s: fault %q, want %q", c.name, got, c.want)
		}
	}
}
