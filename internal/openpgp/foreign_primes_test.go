package openpgp_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the fingerprint of a version 4 key is a SHA-1 by the standard
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// 8. The two primes of the RSA primary are checked for their size and for being prime. The keys of these
// tests are made by hand: the "primes" are products of Mersenne primes, which are known without a search,
// so that no large prime is looked for. Such a key signs and opens as RSA does when its factors are
// known, so its self-signature is good and the file is read; the refusal is the one of OpenSecret.

// fkMersenne are the exponents of Mersenne primes between 13 and 2281.
var fkMersenne = []int{13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281}

func fkM(k int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(k)), big.NewInt(1))
}

// fkSubsets lists the subsets of the exponents (not in used) whose sum is in [lo, hi], at most limit of
// them, by a bounded walk.
func fkSubsets(avail []int, lo, hi, limit int) [][]int {
	var out [][]int
	var walk func(i, sum int, cur []int)
	walk = func(i, sum int, cur []int) {
		if len(out) >= limit || sum > hi {
			return
		}
		if sum >= lo {
			out = append(out, append([]int(nil), cur...))
		}
		for j := i; j < len(avail); j++ {
			walk(j+1, sum+avail[j], append(cur, avail[j]))
		}
	}
	walk(0, 0, nil)
	return out
}

func fkProduct(exps []int) *big.Int {
	p := big.NewInt(1)
	for _, k := range exps {
		p.Mul(p, fkM(k))
	}
	return p
}

func fkWithout(all, drop []int) []int {
	var out []int
	for _, k := range all {
		in := false
		for _, d := range drop {
			in = in || d == k
		}
		if !in {
			out = append(out, k)
		}
	}
	return out
}

// fkRSAKeyOf is an RSA key of 4096 bits whose two numbers p < q are given with the factors that make
// each, so that the exponent of the private key can be made. The numbers need not be prime.
type fkRSAKeyOf struct {
	p, q, n, d, u *big.Int
	e             int
}

// fkMakeRSA makes the numbers of the key from the factors of p and of q (each a prime or a Mersenne prime).
func fkMakeRSA(t testing.TB, pf, qf []*big.Int) (fkRSAKeyOf, bool) {
	t.Helper()
	one := big.NewInt(1)
	p, q := big.NewInt(1), big.NewInt(1)
	for _, f := range pf {
		p.Mul(p, f)
	}
	for _, f := range qf {
		q.Mul(q, f)
	}
	if p.Cmp(q) > 0 {
		p, q = q, p
		pf, qf = qf, pf
	}
	n := new(big.Int).Mul(p, q)
	if n.BitLen() != 4096 {
		return fkRSAKeyOf{}, false
	}
	// the carmichael function of n from the factors
	lambda := big.NewInt(1)
	for _, f := range append(append([]*big.Int{}, pf...), qf...) {
		m := new(big.Int).Sub(f, one)
		g := new(big.Int).GCD(nil, nil, lambda, m)
		lambda.Mul(lambda, new(big.Int).Div(m, g))
	}
	e := big.NewInt(65537)
	if new(big.Int).GCD(nil, nil, e, lambda).Cmp(one) != 0 {
		return fkRSAKeyOf{}, false
	}
	d := new(big.Int).ModInverse(e, lambda)
	u := new(big.Int).ModInverse(p, q)
	if d == nil || u == nil {
		return fkRSAKeyOf{}, false
	}
	return fkRSAKeyOf{p: p, q: q, n: n, d: d, u: u, e: 65537}, true
}

// file writes the primary secret key packet (unprotected), a user ID and a self-signature that the key
// makes with PKCS#1 v1.5 and SHA-256, computed here with big numbers.
func (k fkRSAKeyOf) file(t testing.TB) []byte {
	t.Helper()
	pub := append([]byte{4, 0x65, 0x53, 0xF1, 0x00, 1}, fkMPI(k.n.Bytes())...)
	pub = append(pub, fkMPI(big.NewInt(int64(k.e)).Bytes())...)
	area := fkUnprotectedArea(k.d.Bytes(), k.p.Bytes(), k.q.Bytes(), k.u.Bytes())
	fp := sha1.Sum(append([]byte{0x99, byte(len(pub) >> 8), byte(len(pub))}, pub...)) //nolint:gosec // see the import

	hashed := fkSubpacket(2, false, fkU32(uint32(fkEpoch.Unix()))...)
	hashed = append(hashed, fkSubpacket(33, false, append([]byte{4}, fp[:]...)...)...)
	hashed = append(hashed, fkSubpacket(27, false, 3)...)
	h := sha256.New()
	h.Write([]byte{0x99, byte(len(pub) >> 8), byte(len(pub))})
	h.Write(pub)
	h.Write([]byte{0xB4})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(fkUser))))
	h.Write([]byte(fkUser))
	tail := append([]byte{4, 0x13, 1, 8, byte(len(hashed) >> 8), byte(len(hashed))}, hashed...)
	h.Write(tail)
	h.Write([]byte{4, 0xFF})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(tail))))
	digest := h.Sum(nil)
	// EMSA-PKCS1-v1_5 with SHA-256 (RFC 8017, section 9.2)
	prefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	em := make([]byte, 512)
	em[1] = 1
	tlen := len(prefix) + len(digest)
	for i := 2; i < 512-tlen-1; i++ {
		em[i] = 0xFF
	}
	copy(em[512-tlen:], append(bytes.Clone(prefix), digest...))
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), k.d, k.n)
	body := append(bytes.Clone(tail), 0, 0)
	body = append(body, digest[:2]...)
	body = append(body, fkMPI(s.Bytes())...)
	return fkJoin(fkPacket{5, append(pub, area...)}, fkPacket{13, []byte(fkUser)}, fkPacket{2, body})
}

func TestForeignRSAPrimesAreChecked(t *testing.T) {
	b := fkNamed(t, "rsa4096")
	own := b.secrets(t).Primary // d, p, q, u of the template
	p0, q0 := new(big.Int).SetBytes(own[1]), new(big.Int).SetBytes(own[2])
	if p0.BitLen() < 2040 || p0.BitLen() > 2056 || q0.BitLen() < 2040 || q0.BitLen() > 2056 {
		t.Fatalf("the template has primes of %d and %d bits", p0.BitLen(), q0.BitLen())
	}

	open := func(what string, k fkRSAKeyOf, want string) {
		t.Helper()
		file := k.file(t)
		key, err := openpgp.ReadForeignKey(file)
		if err != nil {
			t.Fatalf("%s: the file is not read, so its self-signature is not good: %v", what, err)
		}
		s, err := key.OpenSecret(nil)
		if want == "" {
			if err != nil {
				t.Errorf("%s: %v", what, err)
				return
			}
			fkSignAndVerify(t, s.Signer(), fkCertPublic(t, key.Certificate()))
			s.Wipe()
			return
		}
		if s != nil || !errors.Is(err, openpgp.ErrForeignSecret) {
			t.Errorf("%s: %v, want an ErrForeignSecret and no key", what, err)
			return
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: the text %q does not say %q", what, err, want)
		}
		fkCheckText(t, what, err, b, k.d.Bytes(), k.p.Bytes(), k.q.Bytes())
	}

	// the control: the primes of the template, packed here and signed here
	ctl, ok := fkMakeRSA(t, []*big.Int{p0}, []*big.Int{q0})
	if !ok {
		t.Fatal("the key of the template is not made again")
	}
	open("the primes of go-crypto, packed by the tests", ctl, "")

	prime := "not a prime of 2040 to 2056 bits"
	// a composite number of the size of a prime, as p and as q
	var comp []int
	for _, set := range fkSubsets(fkMersenne, 2046, 2056, 400) {
		pf := []*big.Int{}
		for _, k := range set {
			pf = append(pf, fkM(k))
		}
		if k, ok := fkMakeRSA(t, pf, []*big.Int{q0}); ok && fkProduct(set).BitLen() >= 2040 {
			comp = set
			open("p is a product of Mersenne primes of "+fkItoa(fkProduct(set).BitLen())+" bits", k, prime)
			break
		}
	}
	if comp == nil {
		t.Fatal("no product of Mersenne primes of the size of a prime makes a modulus of 4096 bits with the prime of the template")
	}
	for _, set := range fkSubsets(fkMersenne, 2046, 2056, 400) {
		qf := []*big.Int{}
		for _, k := range set {
			qf = append(qf, fkM(k))
		}
		if k, ok := fkMakeRSA(t, []*big.Int{p0}, qf); ok && fkProduct(set).BitLen() >= 2040 {
			open("q is a product of Mersenne primes of "+fkItoa(fkProduct(set).BitLen())+" bits", k, prime)
			break
		}
	}

	// a prime of 1024 bits (found in a few tries: a prime of that size is quick) and a composite of 3072 bits
	// whose product has 4096 bits: the size is what is refused first
	found := false
	for _, set := range fkSubsets(fkMersenne, 3070, 3076, 60) {
		qf := []*big.Int{}
		for _, k := range set {
			qf = append(qf, fkM(k))
		}
		for try := 0; try < 12 && !found; try++ {
			small, err := rand.Prime(rand.Reader, 1024)
			if err != nil {
				t.Fatal(err)
			}
			if k, ok := fkMakeRSA(t, []*big.Int{small}, qf); ok {
				open("numbers of "+fkItoa(k.p.BitLen())+" and "+fkItoa(k.q.BitLen())+" bits", k, prime)
				found = true
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("no prime of 1024 bits and product of Mersenne primes of 3072 bits make a modulus of 4096 bits")
	}
	// a real prime that is too large (the Mersenne prime of 2203 bits) with a composite of the rest
	found = false
	for _, set := range fkSubsets(fkWithout(fkMersenne, []int{2203}), 1888, 1900, 400) {
		qf := []*big.Int{}
		for _, k := range set {
			qf = append(qf, fkM(k))
		}
		if k, ok := fkMakeRSA(t, []*big.Int{fkM(2203)}, qf); ok {
			open("a prime of 2203 bits and a composite of "+fkItoa(fkProduct(set).BitLen()), k, prime)
			found = true
			break
		}
	}
	if !found {
		t.Log("no composite of about 1893 bits completes the Mersenne prime of 2203 bits to a modulus of 4096 bits: that case is not made")
	}
}

func fkItoa(n int) string { return big.NewInt(int64(n)).String() }
