package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The secret against the public part, which matters most: a packet whose numbers read well and are
// not the secret of the public key that stands in front of them must be refused by name, whatever
// is wrong, and no byte of any of the numbers may be in the text.

func TestOpenSecretPacketRefusesEveryAlgorithmByteButItsOwn(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, _ := alLone(t, b, false)
		hl := alHeaderLen(pkt)
		for v := 0; v < 256; v++ {
			if byte(v) == b.want.ID {
				continue
			}
			in := bytes.Clone(pkt)
			in[hl+5] = byte(v)
			// an algorithm whose public part the reader does not delimit is an algorithm that is not read; the
			// ones that it delimits read the bytes of the key as their own numbers, which is a form that
			// does not hold or a key that is not one of the three
			if _, delimited := map[int]bool{1: true, 2: true, 3: true, 16: true, 17: true, 18: true, 19: true, 22: true}[v]; delimited {
				alRefuses(t, fmt.Sprintf("algorithm %d", v), b, in, nil)
				continue
			}
			alRefuses(t, fmt.Sprintf("algorithm %d", v), b, in, nil, openpgp.ErrForeignAlgorithm)
		}
	})
}

// alMake makes a key packet of go-crypto: the packet of the primary, with its secret not protected.
func alMake(t testing.TB, algo gpacket.PublicKeyAlgorithm, curve gpacket.Curve, bits int) []byte {
	t.Helper()
	cfg := fkConfig(algo, curve, bits)
	e, err := pgp.NewEntity("Quokka Tester", "", "quokka@example.org", cfg)
	if err != nil {
		t.Fatalf("go-crypto makes no key (%v %v %d): %v", algo, curve, bits, err)
	}
	var buf bytes.Buffer
	if err := e.PrivateKey.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	ps := fkSplit(t, buf.Bytes())
	if len(ps) != 1 || ps[0].Tag != 5 || ps[0].Body[0] != 4 {
		t.Fatalf("go-crypto writes %d packets for a primary", len(ps))
	}
	return wrap(5, ps[0].Body)
}

func TestOpenSecretPacketRefusesAKeyOfAnotherAlgorithmSizeOrCurve(t *testing.T) {
	cases := []struct {
		name  string
		algo  gpacket.PublicKeyAlgorithm
		curve gpacket.Curve
		bits  int
	}{
		{"RSA 2048", gpacket.PubKeyAlgoRSA, "", 2048},
		{"RSA 3072", gpacket.PubKeyAlgoRSA, "", 3072},
		{"ECDSA P-256", gpacket.PubKeyAlgoECDSA, gpacket.CurveNistP256, 0},
		{"ECDSA P-521", gpacket.PubKeyAlgoECDSA, gpacket.CurveNistP521, 0},
		{"ECDSA brainpoolP256r1", gpacket.PubKeyAlgoECDSA, gpacket.CurveBrainpoolP256, 0},
		{"ECDSA brainpoolP384r1", gpacket.PubKeyAlgoECDSA, gpacket.CurveBrainpoolP384, 0},
		{"ECDSA brainpoolP512r1", gpacket.PubKeyAlgoECDSA, gpacket.CurveBrainpoolP512, 0},
		{"ECDSA secp256k1", gpacket.PubKeyAlgoECDSA, gpacket.CurveSecP256k1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := alMake(t, c.algo, c.curve, c.bits)
			p, err := alParse(pkt)
			if err != nil && c.algo != gpacket.PubKeyAlgoRSA {
				// the packet is a good packet of its kind; only the packet of RSA 2048 or 3072 may have
				// its first number shorter
				t.Logf("alParse: %v", err)
			}
			_ = p
			alRefuses(t, c.name, nil, pkt, alNumbersOf(pkt), openpgp.ErrForeignAlgorithm)
		})
	}
	// the native keys of RFC 9580, with sizes that are fixed
	for name, c := range map[string]struct {
		alg byte
		n   int
	}{"Ed25519 (native)": {27, 32}, "Ed448 (native)": {28, 57}} {
		pub := fkRandom(t, c.n)
		sec := fkRandom(t, c.n)
		var sum uint16
		for _, v := range sec {
			sum += uint16(v)
		}
		body := append([]byte{4, 0x65, 0x53, 0xF1, 0x00, c.alg}, pub...)
		body = append(body, 0)
		body = append(body, sec...)
		body = append(body, byte(sum>>8), byte(sum))
		alRefuses(t, name, nil, wrap(5, body), [][]byte{sec}, openpgp.ErrForeignAlgorithm)
	}
}

// alNumbersOf finds the secret numbers of a good packet of go-crypto by reading it with go-crypto.
func alNumbersOf(pkt []byte) [][]byte {
	read, err := gpacket.Read(bytes.NewReader(pkt))
	if err != nil {
		return nil
	}
	sk, ok := read.(*gpacket.PrivateKey)
	if !ok {
		return nil
	}
	if k, ok := sk.PrivateKey.(*rsa.PrivateKey); ok {
		return [][]byte{k.D.Bytes(), k.Primes[0].Bytes(), k.Primes[1].Bytes()}
	}
	return nil
}

var (
	alOtherOnce sync.Once
	alOtherP    *big.Int
	alOtherQ    *big.Int
)

// alOtherPrimes are two primes of 2048 bits that are not those of the template.
func alOtherPrimes(t testing.TB) (*big.Int, *big.Int) {
	t.Helper()
	alOtherOnce.Do(func() {
		var err error
		if alOtherP, err = rand.Prime(rand.Reader, 2048); err != nil {
			return
		}
		alOtherQ, err = rand.Prime(rand.Reader, 2048)
		if err != nil {
			alOtherP = nil
		}
	})
	if alOtherP == nil {
		t.Fatal("no primes")
	}
	return alOtherP, alOtherQ
}

// alRSANumbers writes d, p, q and u of the primes p < q for the exponent e, or nil when the exponent
// does not suit them.
func alRSANumbers(p, q *big.Int, e int64) [][]byte {
	if p.Cmp(q) > 0 {
		p, q = q, p
	}
	one := big.NewInt(1)
	pm, qm := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
	g := new(big.Int).GCD(nil, nil, pm, qm)
	lambda := new(big.Int).Div(new(big.Int).Mul(pm, qm), g)
	d := new(big.Int).ModInverse(big.NewInt(e), lambda)
	u := new(big.Int).ModInverse(p, q)
	if d == nil || u == nil {
		return nil
	}
	return [][]byte{d.Bytes(), p.Bytes(), q.Bytes(), u.Bytes()}
}

func flipLast(v []byte) []byte {
	c := bytes.Clone(v)
	c[len(c)-1] ^= 1
	return c
}

func TestOpenSecretPacketRefusesRSANumbersThatAreNotTheSecretOfTheKey(t *testing.T) {
	b := fkNamed(t, "rsa4096")
	_, _, good := alLone(t, b, false)
	v := good.values()
	d, p, q, u := v[0], v[1], v[2], v[3]
	one := big.NewInt(1)
	// the secret of another key of the same size, and a key of the same q
	op, oq := alOtherPrimes(t)
	other := alRSANumbers(op, oq, 65537)
	shared := alRSANumbers(op, new(big.Int).SetBytes(q), 65537)
	// a composite that is the size of a prime, from two primes of 1024 bits
	r1, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	comp := new(big.Int).Mul(r1, r2)
	compU := new(big.Int).ModInverse(comp, new(big.Int).SetBytes(q))
	// the primes in the other order, with u made again
	swapped := new(big.Int).ModInverse(new(big.Int).SetBytes(q), new(big.Int).SetBytes(p))
	cases := []struct {
		name string
		nums [][]byte
		word string
		kind error // the kind of the refusal; ErrForeignSecret when it is nil
	}{
		{"d changed in its last bit", [][]byte{flipLast(d), p, q, u}, "do not make the key", nil},
		{"d changed in its first byte", [][]byte{append([]byte{d[0] ^ 1}, d[1:]...), p, q, u}, "do not make the key", nil},
		{"d of one", [][]byte{{1}, p, q, u}, "do not make the key", nil},
		{"d the public exponent", [][]byte{{1, 0, 1}, p, q, u}, "do not make the key", nil},
		{"d that is p", [][]byte{p, p, q, u}, "do not make the key", nil},
		{"p and q swapped, u kept", [][]byte{d, q, p, u}, "number u", nil},
		{"p and q swapped, d and u kept as they are", [][]byte{d, q, p, d[:len(u)]}, "number u", nil},
		{"p twice", [][]byte{d, p, p, u}, "do not make the key", nil},
		{"q twice", [][]byte{d, q, q, u}, "do not make the key", nil},
		{"p of another key", [][]byte{d, op.Bytes(), q, u}, "do not make the key", nil},
		{"q of another key", [][]byte{d, p, oq.Bytes(), u}, "do not make the key", nil},
		{"p and q of another key, d and u kept", [][]byte{d, op.Bytes(), oq.Bytes(), u}, "do not make the key", nil},
		{"the whole secret of another key", other, "do not make the key", nil},
		{"the secret of a key that shares q", shared, "do not make the key", nil},
		{"u changed in its last bit", [][]byte{d, p, q, flipLast(u)}, "number u", nil},
		{"u of one", [][]byte{d, p, q, {1}}, "number u", nil},
		{"u of two", [][]byte{d, p, q, {2}}, "number u", nil},
		{"u that is p", [][]byte{d, p, q, p}, "number u", nil},
		{"u that is the inverse of q", [][]byte{d, p, q, swapped.Bytes()}, "number u", nil},
		{"u of the other key", [][]byte{d, p, q, other[3]}, "number u|not below its bound", nil},
		{"u of 513 bytes, which is over the bound of the packet", [][]byte{d, p, q, append([]byte{1}, bytes.Repeat([]byte{1}, 512)...)}, "MaxAdoptedPacketBytes", openpgp.ErrForeignLimit},
		{"a composite for p", [][]byte{d, comp.Bytes(), q, compU.Bytes()}, "not a prime", nil},
		{"a composite for q", [][]byte{d, p, comp.Bytes(), u}, "not a prime|not below its bound", nil},
		{"p of one", [][]byte{d, one.Bytes(), q, u}, "not a prime", nil},
		{"p of two bytes", [][]byte{d, {0xFF, 0xFD}, q, u}, "not a prime", nil},
		{"p shifted to 2032 bits", [][]byte{d, new(big.Int).Rsh(new(big.Int).SetBytes(p), 16).Bytes(), q, u}, "not a prime", nil},
		{"p and q as one number, the modulus", [][]byte{d, p, new(big.Int).Mul(new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)).Bytes(), u}, "MaxAdoptedPacketBytes", openpgp.ErrForeignLimit},
		{"the four numbers in another order", [][]byte{p, q, d, u}, "not a prime|not below its bound", nil},
		{"u first", [][]byte{u, d, p, q}, "not a prime|not below its bound", nil},
		{"three numbers", [][]byte{d, p, q}, "does not account for its bytes", openpgp.ErrForeignForm},
		{"five numbers", [][]byte{d, p, q, u, {1}}, "does not account for its bytes", openpgp.ErrForeignForm},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := good.clone()
			q.Sec = nil
			for _, n := range c.nums {
				q.Sec = append(q.Sec, fkMPI(n))
			}
			kind := c.kind
			if kind == nil {
				kind = openpgp.ErrForeignSecret
			}
			err := alRefusal(t, c.name, b, q.packet(), c.nums, kind)
			if err != nil && !alSays(err, c.word) {
				t.Errorf("the text does not say %q: %v", c.word, err)
			}
		})
	}
}

// REPORTED DEFECT, not fixed here. RFC 9580, section 5.5.3, writes the secret of an RSA key as d, p, q
// and u with p < q and u the inverse of p modulo q. OpenSecretPacket (and OpenSecret, which has the same
// check) reads the primes in either order: with p > q and u made again as the inverse of the new first
// prime it returns a key, and SecretPacket would write that order back. The key is the right key and
// signs correctly; what is wrong is that the packet is not the one that the standard describes, and that
// a packet "exactly as SecretPacket writes it" has two spellings. The test is skipped unless
// RITUEEL_TEST_REPORTED=1.
func TestReportedRSAPrimesInTheOrderOfTheStandardOnly(t *testing.T) {
	alReported(t)
	b := fkNamed(t, "rsa4096")
	_, _, good := alLone(t, b, false)
	v := good.values()
	p, q := new(big.Int).SetBytes(v[1]), new(big.Int).SetBytes(v[2])
	if p.Cmp(q) >= 0 {
		t.Fatalf("the template has p >= q")
	}
	u := new(big.Int).ModInverse(q, p)
	swapped := good.clone()
	swapped.Sec[1], swapped.Sec[2], swapped.Sec[3] = fkMPI(v[2]), fkMPI(v[1]), fkMPI(u.Bytes())
	alRefuses(t, "p greater than q, u made again", b, swapped.packet(), [][]byte{u.Bytes()}, openpgp.ErrForeignSecret)
}

func TestOpenSecretPacketRefusesEd25519SecretsThatAreNotTheSecret(t *testing.T) {
	b := fkNamed(t, "ed25519")
	_, _, good := alLone(t, b, false)
	seed := good.values()[0]
	other, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 255))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		piece []byte
		kind  error
		extra []byte
	}{
		{"the seed of another key", fkMPI(key.Seed()), openpgp.ErrForeignSecret, key.Seed()},
		{"a random seed", fkMPI(other.FillBytes(make([]byte, 32))), openpgp.ErrForeignSecret, other.Bytes()},
		{"the seed with its last bit changed", fkMPI(flipLast(seed)), openpgp.ErrForeignSecret, nil},
		{"the seed with its first bit changed", fkMPI(append([]byte{seed[0] ^ 0x01}, seed[1:]...)), openpgp.ErrForeignSecret, nil},
		{"the seed and the public key, as go-crypto and others keep a private key", fkMPI(append(bytes.Clone(seed), good.Pub[1][3:]...)), openpgp.ErrForeignSecret, nil},
		{"a seed of 33 bytes", fkMPI(append([]byte{1}, seed...)), openpgp.ErrForeignSecret, nil},
		{"a seed of one", fkMPI([]byte{1}), openpgp.ErrForeignSecret, nil},
		{"a seed of all ones", fkMPI(bytes.Repeat([]byte{0xFF}, 32)), openpgp.ErrForeignSecret, nil},
		{"the scalar of a P-384 key", fkMPI(alScalar(t, p384)), openpgp.ErrForeignSecret, alScalar(t, p384)},
		{"a number of zero bits", []byte{0, 0}, openpgp.ErrForeignForm, nil},
		{"one zero byte, in a form that is not the shortest", []byte{0, 8, 0}, openpgp.ErrForeignKey, nil},
		{"one zero byte counted as one bit", []byte{0, 1, 0}, openpgp.ErrForeignKey, nil},
		{"the seed with a zero byte in front", append([]byte{byte((len(seed)*8 + 8) >> 8), byte((len(seed)*8 + 8))}, append([]byte{0}, seed...)...), openpgp.ErrForeignKey, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := good.clone()
			q.Sec = [][]byte{c.piece}
			alRefuses(t, c.name, b, q.packet(), [][]byte{c.piece[2:], c.extra}, c.kind)
		})
	}
	// the secret of an Ed25519 key in front of the public part of another one
	_, pub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q := good.clone()
	q.Pub[1] = fkMPI(append([]byte{0x40}, pub.Public().(ed25519.PublicKey)...))
	alRefuses(t, "the public key of another key", b, q.packet(), nil, openpgp.ErrForeignSecret)
}

func TestOpenSecretPacketRefusesP384SecretsThatAreNotTheSecret(t *testing.T) {
	b := fkNamed(t, "p384")
	_, _, good := alLone(t, b, false)
	d := good.values()[0]
	order := elliptic.P384().Params().N
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	own := new(big.Int).SetBytes(d)
	cases := []struct {
		name  string
		piece []byte
		kind  error
		word  string
	}{
		{"the scalar of another key", fkMPI(alScalar(t, other)), openpgp.ErrForeignSecret, "not the secret of the public key"},
		{"the scalar with its last bit changed", fkMPI(flipLast(d)), openpgp.ErrForeignSecret, "not the secret of the public key"},
		{"the scalar plus one", fkMPI(new(big.Int).Add(own, big.NewInt(1)).Bytes()), openpgp.ErrForeignSecret, "not the secret of the public key"},
		{"the scalar of one", fkMPI([]byte{1}), openpgp.ErrForeignSecret, "not the secret of the public key"},
		{"the scalar of two", fkMPI([]byte{2}), openpgp.ErrForeignSecret, "not the secret of the public key"},
		{"the order minus one", fkMPI(new(big.Int).Sub(order, big.NewInt(1)).Bytes()), openpgp.ErrForeignSecret, "not the secret of the public key"},
		{"the order", fkMPI(order.Bytes()), openpgp.ErrForeignSecret, "not a private key of the group"},
		{"the order plus one", fkMPI(new(big.Int).Add(order, big.NewInt(1)).Bytes()), openpgp.ErrForeignSecret, "not a private key of the group"},
		{"the scalar plus the order, which has the same point", fkMPI(new(big.Int).Add(own, order).Bytes()), openpgp.ErrForeignSecret, ""},
		{"the largest number of 48 bytes", fkMPI(bytes.Repeat([]byte{0xFF}, 48)), openpgp.ErrForeignSecret, "not a private key of the group"},
		{"a scalar of 49 bytes", fkMPI(append([]byte{1}, d...)), openpgp.ErrForeignSecret, "one number"},
		{"a seed of Ed25519", fkMPI(seed.Seed()), openpgp.ErrForeignSecret, "not the secret of the public key"},
		{"zero, as a number of zero bits", []byte{0, 0}, openpgp.ErrForeignForm, ""},
		{"zero, as one zero byte of one bit", []byte{0, 1, 0}, openpgp.ErrForeignKey, ""},
		{"zero, as one zero byte of eight bits", []byte{0, 8, 0}, openpgp.ErrForeignKey, ""},
		{"zero, as 48 zero bytes", append([]byte{0x01, 0x80}, make([]byte, 48)...), openpgp.ErrForeignKey, ""},
		{"the scalar with a zero byte in front", append([]byte{byte((len(d)*8 + 8) >> 8), byte((len(d)*8 + 8))}, append([]byte{0}, d...)...), openpgp.ErrForeignKey, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := good.clone()
			q.Sec = [][]byte{c.piece}
			err := alRefusal(t, c.name, b, q.packet(), [][]byte{c.piece[2:], alScalar(t, other), seed.Seed()}, c.kind)
			if err != nil && c.word != "" && !strings.Contains(err.Error(), c.word) {
				t.Errorf("the text does not say %q: %v", c.word, err)
			}
		})
	}
	// the secret in front of the public point of another key of the same curve, and of a point that is
	// not on the curve
	q := good.clone()
	pt := other.PublicKey
	raw, _ := pt.Bytes()
	q.Pub[1] = fkMPI(raw)
	alRefuses(t, "the public point of another key", b, q.packet(), nil, openpgp.ErrForeignSecret)
	off := good.clone()
	pointOff := bytes.Clone(good.Pub[1][2:])
	pointOff[len(pointOff)-1] ^= 1
	off.Pub[1] = fkMPI(pointOff)
	alRefuses(t, "a point that is not on the curve", b, off.packet(), nil, openpgp.ErrForeignForm)
}

// alSays says whether the text of an error holds one of the words, which are written with | between.
func alSays(err error, words string) bool {
	for _, w := range strings.Split(words, "|") {
		if strings.Contains(err.Error(), w) {
			return true
		}
	}
	return false
}

// The numbers of an RSA secret are held to their bounds: u is below the second prime and d below the
// modulus, so that the secret has one spelling. u + q and d + a multiple of the group exponent satisfy
// every relation of the key, and are refused by the bound only.
func TestOpenSecretPacketHoldsTheRSANumbersToTheirBounds(t *testing.T) {
	b := fkNamed(t, "rsa4096")
	_, pkt, good := alLone(t, b, false)
	v := good.values()
	d, p, q, u := new(big.Int).SetBytes(v[0]), new(big.Int).SetBytes(v[1]), new(big.Int).SetBytes(v[2]), new(big.Int).SetBytes(v[3])
	n := new(big.Int).SetBytes(good.Pub[0][2:])
	one := big.NewInt(1)
	pm, qm := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
	lambda := new(big.Int).Div(new(big.Int).Mul(pm, qm), new(big.Int).GCD(nil, nil, pm, qm))
	// the relations of the key hold for each of these
	e := big.NewInt(65537)
	uPlusQ := new(big.Int).Add(u, q)
	k := new(big.Int).Div(new(big.Int).Sub(n, d), lambda)
	k.Add(k, one)
	dBig := new(big.Int).Add(d, new(big.Int).Mul(k, lambda))
	for _, x := range []*big.Int{new(big.Int).Mod(new(big.Int).Mul(e, dBig), lambda)} {
		if x.Cmp(one) != 0 {
			t.Fatalf("the test number is not an exponent of the key")
		}
	}
	if new(big.Int).Mod(new(big.Int).Mul(uPlusQ, p), q).Cmp(one) != 0 {
		t.Fatalf("the test number is not u modulo q")
	}
	cases := []struct {
		name string
		nums [][]byte
	}{
		{"u plus q", [][]byte{v[0], v[1], v[2], uPlusQ.Bytes()}},
		{"u plus twice q", [][]byte{v[0], v[1], v[2], new(big.Int).Add(uPlusQ, q).Bytes()}},
		{"u equal to q", [][]byte{v[0], v[1], v[2], v[2]}},
		{"d plus a multiple of the group exponent that reaches the modulus", [][]byte{dBig.Bytes(), v[1], v[2], v[3]}},
		{"d plus the modulus", [][]byte{new(big.Int).Add(d, n).Bytes(), v[1], v[2], v[3]}},
		{"d equal to the modulus", [][]byte{n.Bytes(), v[1], v[2], v[3]}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := good.clone()
			x.Sec = nil
			for _, num := range c.nums {
				x.Sec = append(x.Sec, fkMPI(num))
			}
			err := alRefusal(t, c.name, b, x.packet(), c.nums, openpgp.ErrForeignSecret)
			// a d that is over the modulus by more than the length of the modulus is refused for its length
			// before its value is looked at: the key is made at random, and so is which one of the two
			word := "not below its bound"
			if len(c.nums[0]) > 512 {
				word = "four numbers"
			}
			if err != nil && !strings.Contains(err.Error(), word) {
				t.Errorf("the text does not say %q: %v", word, err)
			}
		})
	}
	// the canonical packet is read, and so is a d that is another exponent of the key below the modulus:
	// d plus the group exponent, when that is below the modulus
	alAccepted(t, "the canonical packet", pkt)
	if dl := new(big.Int).Add(d, lambda); dl.Cmp(n) < 0 {
		x := good.clone()
		x.Sec[0] = fkMPI(dl.Bytes())
		alAccepted(t, "d plus the group exponent, below the modulus", x.packet())
	}
}

// The packet of the largest key that the reader takes is within MaxAdoptedPacketBytes: a modulus of
// 4096 bits with the smallest and the largest prime that the reader allows, d and u at their bounds.
func TestTheLargestRSA4096PacketThatIsReadFitsItsBound(t *testing.T) {
	one := big.NewInt(1)
	e := big.NewInt(65537)
	var p, q, n, lambda *big.Int
	for {
		var err error
		if p, err = rand.Prime(rand.Reader, 2040); err != nil {
			t.Fatal(err)
		}
		if q, err = rand.Prime(rand.Reader, 2056); err != nil {
			t.Fatal(err)
		}
		n = new(big.Int).Mul(p, q)
		pm, qm := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
		lambda = new(big.Int).Div(new(big.Int).Mul(pm, qm), new(big.Int).GCD(nil, nil, pm, qm))
		if n.BitLen() == 4096 && new(big.Int).GCD(nil, nil, e, lambda).Cmp(one) == 0 {
			break
		}
	}
	d := new(big.Int).ModInverse(e, lambda)
	// the largest exponent of the key that is below the modulus
	for new(big.Int).Add(d, lambda).Cmp(n) < 0 {
		d.Add(d, lambda)
	}
	u := new(big.Int).ModInverse(p, q)
	x := alPacket{
		Head: []byte{4, 0x65, 0x53, 0xF1, 0x00, 1},
		Pub:  [][]byte{fkMPI(n.Bytes()), fkMPI(e.Bytes())},
		Sec:  [][]byte{fkMPI(d.Bytes()), fkMPI(p.Bytes()), fkMPI(q.Bytes()), fkMPI(u.Bytes())},
	}
	pkt := x.packet()
	t.Logf("the packet of the largest key is %d bytes, the bound is %d", len(pkt), openpgp.MaxAdoptedPacketBytes)
	if len(pkt) > openpgp.MaxAdoptedPacketBytes {
		t.Fatalf("the packet is %d bytes, over the bound", len(pkt))
	}
	if _, err := alParse(pkt); err != nil {
		t.Fatalf("the packet is not canonical: %v", err)
	}
	alAccepted(t, "the largest key", pkt)
}

// alScalar is the secret scalar of a key of the standard library, as its bytes.
func alScalar(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
