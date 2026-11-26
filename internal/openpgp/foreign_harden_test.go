package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The cut between the public and the secret part of a secret subkey packet is made by the length
// fields of the public part. A field that claims more bytes than it has moves the cut into the secret,
// and what lies in front of the cut goes to the certificate. These tests build that input for every
// algorithm with a length field at the end of its public part, and hold that the file is refused or,
// when it is read, that the certificate holds no byte of the secret area beyond its first two.

// fkSubSecret is a secret subkey packet of one algorithm: the body, where the public part ends, and
// the offset of the length field at the end of the public part, which is the one that is stretched.
type fkSubSecret struct {
	name   string
	body   []byte
	pubLen int
	last   int // the offset of the header of the last MPI of the public part
	first  int // the offset of the header of the first MPI of the public part
	oid    int // the offset of the length octet of the curve, or 0
	usage  byte
}

// area is the secret area of the packet.
func (s fkSubSecret) area() []byte { return s.body[s.pubLen:] }

// fkRSANumbers makes the numbers of a small RSA key with the public exponent e: two primes of 512 bits
// whose predecessors have no common factor with e. The keys are made once for the test binary.
type fkRSAMade struct {
	n, e, d, p, q, u []byte
}

var fkRSACache sync.Map

func fkRSAWith(t testing.TB, e int64) fkRSAMade {
	t.Helper()
	if v, ok := fkRSACache.Load(e); ok {
		return v.(fkRSAMade)
	}
	bigE := big.NewInt(e)
	one := big.NewInt(1)
	prime := func() *big.Int {
		for i := 0; i < 200; i++ { // bounded: a prime of 512 bits is found in a few tries
			p, err := rand.Prime(rand.Reader, 512)
			if err != nil {
				t.Fatal(err)
			}
			if new(big.Int).GCD(nil, nil, bigE, new(big.Int).Sub(p, one)).Cmp(one) == 0 {
				return p
			}
		}
		t.Fatal("no prime of 512 bits that suits the exponent")
		return nil
	}
	p, q := prime(), prime()
	for p.Cmp(q) == 0 {
		q = prime()
	}
	if p.Cmp(q) > 0 {
		p, q = q, p
	}
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	d := new(big.Int).ModInverse(bigE, phi)
	u := new(big.Int).ModInverse(p, q)
	m := fkRSAMade{n: new(big.Int).Mul(p, q).Bytes(), e: bigE.Bytes(), d: d.Bytes(), p: p.Bytes(), q: q.Bytes(), u: u.Bytes()}
	fkRSACache.Store(e, m)
	return m
}

// fkUnprotectedArea writes usage 0, the numbers as MPIs and their checksum.
func fkUnprotectedArea(numbers ...[]byte) []byte {
	enc := fkEncode(numbers...)
	var sum uint16
	for _, c := range enc {
		sum += uint16(c)
	}
	return append(append([]byte{0}, enc...), byte(sum>>8), byte(sum))
}

// fkAreaOfUsage writes the secret area of a subkey with the numbers, in the form of usage 0, 254 or 255.
func fkAreaOfUsage(t testing.TB, usage byte, numbers ...[]byte) []byte {
	t.Helper()
	if usage == 0 {
		return fkUnprotectedArea(numbers...)
	}
	a := fkProtectRegion(t, fkEncode(numbers...), fkPass, 9, crypto.SHA256, 8, 0x60)
	a[0] = usage // 255 is the same shape: the reader never decrypts a subkey
	return a
}

// fkRSASub is a secret RSA subkey packet with the exponent e.
func fkRSASub(t testing.TB, e int64, usage byte) fkSubSecret {
	t.Helper()
	m := fkRSAWith(t, e)
	pub := append([]byte{4, 0x65, 0x53, 0xF1, 0x00, 1}, fkMPI(m.n)...)
	last := len(pub)
	pub = append(pub, fkMPI(m.e)...)
	body := append(bytes.Clone(pub), fkAreaOfUsage(t, usage, m.d, m.p, m.q, m.u)...)
	return fkSubSecret{name: fmt.Sprintf("RSA e=%d usage %d", e, usage), body: body, pubLen: len(pub), last: last, first: 6, usage: usage}
}

// fkRealSub is a subkey of go-crypto's making (an ECDH or an EdDSA donor, or a subkey of a template),
// with its secret area in the form of the usage.
func fkRealSub(t testing.TB, name string, pub fkPacket, sec fkPacket, usage byte, oidAt int, lastLen int, kdf bool) fkSubSecret {
	t.Helper()
	area := sec.Body[len(pub.Body):]
	if usage != 0 {
		// the donor's secret as numbers, protected in the form of the usage
		numbers := fkReadMPIs(t, area[1:])
		area = fkAreaOfUsage(t, usage, numbers...)
	}
	tail := lastLen + 2
	if kdf {
		tail += 4
	}
	return fkSubSecret{name: fmt.Sprintf("%s usage %d", name, usage), body: append(bytes.Clone(pub.Body), area...), pubLen: len(pub.Body),
		last: len(pub.Body) - tail, first: len(pub.Body) - tail, oid: oidAt, usage: usage}
}

// fkFakeSub is a secret subkey of DSA or ElGamal with numbers of the right sizes and no meaning.
func fkFakeSub(t testing.TB, alg byte, usage byte) fkSubSecret {
	t.Helper()
	pub := []byte{4, 0x65, 0x53, 0xF1, 0x00, alg}
	var last int
	switch alg {
	case 17: // DSA 2048
		pub = append(pub, fkBig(t, 256)...)
		pub = append(pub, fkBig(t, 32)...)
		pub = append(pub, fkBig(t, 256)...)
		last = len(pub)
		pub = append(pub, fkBig(t, 256)...)
	default: // ElGamal 2048
		pub = append(pub, fkBig(t, 256)...)
		pub = append(pub, fkBig(t, 4)...)
		last = len(pub)
		pub = append(pub, fkBig(t, 256)...)
	}
	x := fkRandom(t, 32)
	x[0] |= 0x80
	body := append(bytes.Clone(pub), fkAreaOfUsage(t, usage, x)...)
	return fkSubSecret{name: fmt.Sprintf("alg %d usage %d", alg, usage), body: body, pubLen: len(pub), last: last, first: 6, usage: usage}
}

// stretch claims k more bytes for the MPI at the offset, and nothing else changes: the bytes that it
// takes are the first k bytes of what follows.
func (s fkSubSecret) stretch(at, k int) []byte {
	b := bytes.Clone(s.body)
	bits := int(b[at])<<8 | int(b[at+1])
	bits += 8 * k
	b[at], b[at+1] = byte(bits>>8), byte(bits)
	return b
}

// fkHead is the primary, a user ID and its self-signature of a template, which every file here starts with.
func fkCraftedFile(t testing.TB, b *fkBase, subBody []byte) []byte {
	t.Helper()
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	return fkJoin(append(head, fkPacket{7, subBody})...)
}

// fkCertSubkeyBody is the body of the first subkey packet of a certificate.
func fkCertSubkeyBody(t testing.TB, cert []byte) []byte {
	t.Helper()
	for _, p := range splitPackets(t, cert) {
		if p.Tag == 14 {
			return p.Body
		}
	}
	t.Fatal("the certificate holds no subkey")
	return nil
}

func TestForeignCraftedSubkeys(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, sig, _ := fkDonors(t)
	p384 := fkNamed(t, "p384")
	var p384Sub fkSubSecret
	{
		// the ECDSA signing subkey of the P-384 template, as go-crypto writes it
		var pubBuf, secBuf bytes.Buffer
		sk := p384.ent.Subkeys[1]
		if err := sk.PublicKey.Serialize(&pubBuf); err != nil {
			t.Fatal(err)
		}
		if err := sk.PrivateKey.Serialize(&secBuf); err != nil {
			t.Fatal(err)
		}
		pub, sec := fkSplit(t, pubBuf.Bytes())[0], fkSplit(t, secBuf.Bytes())[0]
		p384Sub = fkSubSecret{body: sec.Body, pubLen: len(pub.Body), last: len(pub.Body) - 97 - 2, oid: 6}
	}
	_ = p384Sub

	type maker func(usage byte) fkSubSecret
	makers := []struct {
		name string
		make maker
		// ks are the stretches that are held
		ks []int
	}{
		{"RSA, e of 1 byte (3)", func(u byte) fkSubSecret { return fkRSASub(t, 3, u) }, nil},
		{"RSA, e of 1 byte (17)", func(u byte) fkSubSecret { return fkRSASub(t, 17, u) }, nil},
		{"RSA, e of 2 bytes (257)", func(u byte) fkSubSecret { return fkRSASub(t, 257, u) }, nil},
		{"RSA, e of 3 bytes (65537)", func(u byte) fkSubSecret { return fkRSASub(t, 65537, u) }, nil},
		{"DSA, y", func(u byte) fkSubSecret { return fkFakeSub(t, 17, u) }, nil},
		{"ElGamal, y", func(u byte) fkSubSecret { return fkFakeSub(t, 16, u) }, nil},
		{"ECDH Curve25519, point", func(u byte) fkSubSecret {
			return fkRealSub(t, "ECDH", enc[0].pub, enc[0].sec, u, 6, 33, true)
		}, nil},
		{"EdDSA Ed25519, point", func(u byte) fkSubSecret {
			return fkRealSub(t, "EdDSA", sig[0].pub, sig[0].sec, u, 6, 33, false)
		}, nil},
	}
	ks := []int{1, 2, 3, 4, 5, 8, 16, 40, 100}
	type row struct {
		what    string
		outcome string
		leaked  int
	}
	reasons := map[string]int{}
	var rows []row
	accepted := 0
	for _, m := range makers {
		for _, usage := range []byte{0, 254, 255} {
			s := m.make(usage)
			// the control: the packet as it is, which must be read, so that a refusal below is not a
			// refusal of a packet that was never right
			ctl := fkRead(t, fkCraftedFile(t, b, s.body))
			if len(ctl.Subkeys) != 1 || ctl.Subkeys[0].Form != openpgp.SubkeyWithSecret {
				t.Fatalf("%s: the control subkey is %+v", s.name, ctl.Subkeys)
			}
			if got := fkCertSubkeyBody(t, ctl.Certificate()); !bytes.Equal(got, s.body[:s.pubLen]) {
				t.Fatalf("%s: the control certificate does not hold the public part exactly", s.name)
			}
			for _, at := range []struct {
				name string
				off  int
			}{{"last", s.last}, {"first", s.first}} {
				for _, k := range ks {
					if s.pubLen+k > len(s.body) {
						continue
					}
					what := fmt.Sprintf("%s, usage %d, the %s length field claims %d more", m.name, usage, at.name, k)
					file := fkCraftedFile(t, b, s.stretch(at.off, k))
					key, err := openpgp.ReadForeignKey(file)
					if err != nil {
						if key != nil || !errors.Is(err, openpgp.ErrForeignKey) {
							t.Errorf("%s: %v with a key %v", what, err, key != nil)
						}
						fkCheckText(t, what, err, b)
						switch {
						case errors.Is(err, openpgp.ErrForeignAlgorithm):
							reasons["ErrForeignAlgorithm"]++
						case errors.Is(err, openpgp.ErrForeignProtection):
							reasons["ErrForeignProtection"]++
						case errors.Is(err, openpgp.ErrForeignForm):
							reasons["ErrForeignForm"]++
						default:
							reasons["another kind"]++
						}
						rows = append(rows, row{what, "refused", 0})
						continue
					}
					// accepted: hold the certificate to the bound
					accepted++
					cert := key.Certificate()
					body := fkCertSubkeyBody(t, cert)
					leaked := len(body) - s.pubLen
					bodyOK := len(body) >= s.pubLen && bytes.Equal(body, s.stretch(at.off, k)[:len(body)])
					area := s.area()
					if !bodyOK || leaked > 2 {
						t.Errorf("%s: ACCEPTED, and the certificate holds %d bytes of the secret area (body ok %v)", what, leaked, bodyOK)
					}
					if len(area) > 2 {
						if where, bad := fkLeaks(cert, area[2:]); bad {
							t.Errorf("%s: ACCEPTED, and the certificate holds a run of the secret area beyond its first two bytes (%s)", what, where)
						}
					}
					rows = append(rows, row{what, "ACCEPTED", leaked})
				}
			}
		}
	}
	// the table: every case, refused or accepted
	refused := 0
	for _, r := range rows {
		if r.outcome == "refused" {
			refused++
		} else {
			t.Logf("%s: %s, %d bytes of the secret area in the certificate", r.what, r.outcome, r.leaked)
		}
	}
	t.Logf("%d crafted subkeys: %d refused, %d accepted; the kinds of the refusals: %v", len(rows), refused, accepted, reasons)
}

// The same stretch for the curve: the length octet of the object identifier is raised, so that the
// identifier takes bytes of the point, and an identifier that is not a known curve.
func TestForeignCraftedCurves(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, sig, _ := fkDonors(t)
	p384 := fkNamed(t, "p384")
	var pub, sec fkPacket
	{
		var pubBuf, secBuf bytes.Buffer
		sk := p384.ent.Subkeys[1]
		if err := sk.PublicKey.Serialize(&pubBuf); err != nil {
			t.Fatal(err)
		}
		if err := sk.PrivateKey.Serialize(&secBuf); err != nil {
			t.Fatal(err)
		}
		pub, sec = fkSplit(t, pubBuf.Bytes())[0], fkSplit(t, secBuf.Bytes())[0]
	}
	subs := []struct {
		name string
		sub  func(usage byte) fkSubSecret
	}{
		{"ECDSA P-384", func(u byte) fkSubSecret { return fkRealSub(t, "ECDSA", pub, sec, u, 6, 97, false) }},
		{"ECDH Curve25519", func(u byte) fkSubSecret { return fkRealSub(t, "ECDH", enc[1].pub, enc[1].sec, u, 6, 33, true) }},
		{"EdDSA Ed25519", func(u byte) fkSubSecret { return fkRealSub(t, "EdDSA", sig[1].pub, sig[1].sec, u, 6, 33, false) }},
	}
	accepted := 0
	for _, sc := range subs {
		for _, usage := range []byte{0, 254, 255} {
			s := sc.sub(usage)
			ctl := fkRead(t, fkCraftedFile(t, b, s.body))
			if len(ctl.Subkeys) != 1 {
				t.Fatalf("%s: the control is not read", s.name)
			}
			check := func(what string, body []byte) {
				t.Helper()
				key, err := openpgp.ReadForeignKey(fkCraftedFile(t, b, body))
				if err != nil {
					if key != nil || !errors.Is(err, openpgp.ErrForeignKey) {
						t.Errorf("%s: %v", what, err)
					}
					fkCheckText(t, what, err, b)
					return
				}
				accepted++
				cert := key.Certificate()
				cb := fkCertSubkeyBody(t, cert)
				leaked := len(cb) - s.pubLen
				area := s.area()
				if leaked > 2 || !bytes.Equal(cb, body[:len(cb)]) {
					t.Errorf("%s: ACCEPTED, the certificate holds %d bytes of the secret area", what, leaked)
				}
				if where, bad := fkLeaks(cert, area[2:]); bad {
					t.Errorf("%s: ACCEPTED, a run of the secret area is in the certificate (%s)", what, where)
				}
				t.Logf("%s: ACCEPTED, %d bytes of the secret area in the certificate", what, leaked)
			}
			for _, k := range []int{1, 2, 3, 4, 8, 20, 60, 100} {
				body := bytes.Clone(s.body)
				if int(body[s.oid])+k >= 0xFF {
					continue
				}
				body[s.oid] += byte(k)
				check(fmt.Sprintf("%s, usage %d, the curve identifier is %d bytes longer", sc.name, usage, k), body)
			}
			// an identifier of the length of a curve that is not one that the reader knows
			body := bytes.Clone(s.body)
			for i := 0; i < int(body[s.oid]); i++ {
				body[s.oid+1+i] ^= 0x55
			}
			check(fmt.Sprintf("%s, usage %d, a curve that is not known", sc.name, usage), body)
			// the identifier of another known curve: the point has not its length
			other := bytes.Clone(s.body)
			if sc.name == "ECDSA P-384" {
				copy(other[s.oid:], []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x23}) // P-521
			} else {
				copy(other[s.oid:], []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}) // P-384 for a key of 33 bytes: the identifier is shorter, so the bytes move
			}
			check(fmt.Sprintf("%s, usage %d, the identifier of another curve", sc.name, usage), other)
		}
	}
	t.Logf("curve cases: %d accepted", accepted)
}

// A PUBLIC subkey of an unknown algorithm is read and copied as it is; a SECRET subkey or a stub of an
// unknown algorithm refuses the file, whatever follows.
func TestForeignSubkeyOfUnknownAlgorithmSecretAndStub(t *testing.T) {
	b := fkNamed(t, "ed25519")
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	pub := []byte{4, 0x65, 0x53, 0xF1, 0x00, 99, 0, 8, 0xAB, 1, 2, 3}
	public := fkJoin(append(slicesClone(head), fkPacket{14, pub})...)
	k := fkRead(t, public)
	if got := fkCertSubkeyBody(t, k.Certificate()); !bytes.Equal(got, pub) {
		t.Errorf("a public subkey of an unknown algorithm is not copied as it is")
	}
	for name, area := range map[string][]byte{
		"a stub, dummy":          fkStubRegion(255, 1, nil),
		"a stub, card":           fkStubRegion(254, 2, fkSerial),
		"unprotected":            fkUnprotectedArea([]byte{1, 2, 3}),
		"protected":              fkAreaOfUsage(t, 254, []byte{1, 2, 3}),
		"the area of the length": append([]byte{0}, fkRandom(t, 30)...),
	} {
		file := fkJoin(append(slicesClone(head), fkPacket{7, append(bytes.Clone(pub), area...)})...)
		err := fkRefused(t, "a secret subkey of an unknown algorithm, "+name, file, b, openpgp.ErrForeignAlgorithm)
		if err != nil && !bytes.Contains([]byte(err.Error()), []byte("99")) {
			t.Errorf("%s: the text does not name the algorithm: %v", name, err)
		}
	}
}

func slicesClone(ps []fkPacket) []fkPacket { return append([]fkPacket(nil), ps...) }

// The secret area of a subkey must be a known form that accounts for its packet.
func TestForeignSubkeySecretAreaForms(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, _, _ := fkDonors(t)
	d := enc[2]
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	numbers := fkReadMPIs(t, d.sec.Body[len(d.pub.Body)+1:])
	file := func(area []byte) []byte {
		return fkJoin(append(slicesClone(head), fkPacket{7, append(bytes.Clone(d.pub.Body), area...)})...)
	}
	unprot := fkUnprotectedArea(numbers...)
	prot := func(usage, cipher, s2k, hash byte, ivLen, dataLen int) []byte {
		a := []byte{usage, cipher, s2k, hash}
		a = append(a, fkRandom(t, 8)...)
		a = append(a, 0x60)
		a = append(a, fkRandom(t, ivLen+dataLen)...)
		return a
	}
	mod := func(f func(a []byte) []byte) []byte { return f(bytes.Clone(unprot)) }
	type c struct {
		name   string
		area   []byte
		kind   error // nil: read
		form   openpgp.SubkeyForm
		wantIn string
	}
	cases := []c{
		{"unprotected, as it is", unprot, nil, openpgp.SubkeyWithSecret, ""},
		{"unprotected, one byte short", unprot[:len(unprot)-1], openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, one byte long", append(bytes.Clone(unprot), 0), openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, three bytes long", append(bytes.Clone(unprot), 1, 2, 3), openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, with no checksum", unprot[:len(unprot)-2], openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, the number claims a byte more", mod(func(a []byte) []byte { a[2]++; return a }), openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, the number claims 8 bits less", mod(func(a []byte) []byte {
			bits := (int(a[1])<<8 | int(a[2])) - 8
			a[1], a[2] = byte(bits>>8), byte(bits)
			return a
		}), openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, the number claims no bits", mod(func(a []byte) []byte { a[1], a[2] = 0, 0; return a }), openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, the number claims 65535 bits", mod(func(a []byte) []byte { a[1], a[2] = 0xFF, 0xFF; return a }), openpgp.ErrForeignForm, 0, "accounts for"},
		{"unprotected, two numbers where one is", fkUnprotectedArea(numbers[0], numbers[0]), openpgp.ErrForeignForm, 0, "accounts for"},
		{"usage 0 and nothing else", []byte{0}, openpgp.ErrForeignForm, 0, "accounts for"},
		{"no area at all", nil, openpgp.ErrForeignForm, 0, "no secret part"},
		{"protected, as it is", prot(254, 9, 3, 8, 16, 40), nil, openpgp.SubkeyWithSecret, ""},
		{"protected, with ciphertext of 20 bytes, the least", prot(254, 9, 3, 8, 16, 20), nil, openpgp.SubkeyWithSecret, ""},
		{"protected, with ciphertext of 19 bytes", prot(254, 9, 3, 8, 16, 19), openpgp.ErrForeignForm, 0, "accounts for"},
		{"protected, with an IV of 15 bytes and nothing else", prot(254, 9, 3, 8, 15, 0), openpgp.ErrForeignForm, 0, "accounts for"},
		{"protected, with no IV and no ciphertext", prot(254, 9, 3, 8, 0, 0), openpgp.ErrForeignForm, 0, "accounts for"},
		{"usage 255, with an IV and 2 bytes", prot(255, 9, 3, 8, 16, 2), nil, openpgp.SubkeyWithSecret, ""},
		{"usage 255, with an IV and 1 byte", prot(255, 9, 3, 8, 16, 1), openpgp.ErrForeignForm, 0, "accounts for"},
		{"a named cipher that is not AES (CAST5), with its IV of 8 bytes", prot(254, 3, 3, 8, 8, 20), nil, openpgp.SubkeyWithSecret, ""},
		{"a named cipher of a block of 8 bytes with an IV of 7 and 20", prot(254, 3, 3, 8, 7, 20), openpgp.ErrForeignForm, 0, "accounts for"},
		{"cipher 0", prot(254, 0, 3, 8, 16, 40), openpgp.ErrForeignForm, 0, "accounts for"},
		{"cipher 5", prot(254, 5, 3, 8, 16, 40), openpgp.ErrForeignForm, 0, "accounts for"},
		{"cipher 6", prot(254, 6, 3, 8, 16, 40), openpgp.ErrForeignForm, 0, "accounts for"},
		{"cipher 14", prot(254, 14, 3, 8, 16, 40), openpgp.ErrForeignForm, 0, "accounts for"},
		{"cipher 99", prot(254, 99, 3, 8, 16, 40), openpgp.ErrForeignForm, 0, "accounts for"},
		{"an S2K of a type that is not known", prot(254, 9, 7, 8, 16, 40), openpgp.ErrForeignForm, 0, "accounts for"},
		{"a simple S2K, complete", append([]byte{254, 9, 0, 8}, fkRandom(t, 16+40)...), nil, openpgp.SubkeyWithSecret, ""},
		{"a salted S2K, complete", append([]byte{254, 9, 1, 8}, fkRandom(t, 8+16+40)...), nil, openpgp.SubkeyWithSecret, ""},
		{"an iterated S2K cut short in its count", []byte{254, 9, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8}, openpgp.ErrForeignForm, 0, "accounts for"},
		{"an S2K cut short after its type", []byte{254, 9, 3}, openpgp.ErrForeignForm, 0, "accounts for"},
		{"usage and cipher only", []byte{254, 9}, openpgp.ErrForeignForm, 0, "accounts for"},
		{"usage 253, with a cipher, a mode and an S2K", append([]byte{253, 9, 2, 3, 8}, fkRandom(t, 8+1+30)...), nil, openpgp.SubkeyWithSecret, ""},
		{"usage 253, cut short in the S2K", []byte{253, 9, 2, 3, 8, 1}, openpgp.ErrForeignForm, 0, "accounts for"},
		{"a stub, dummy, usage 255", fkStubRegion(255, 1, nil), nil, openpgp.SubkeyStub, ""},
		{"a stub, dummy, usage 254", fkStubRegion(254, 1, nil), nil, openpgp.SubkeyStub, ""},
		{"a stub, card, with a serial number", fkStubRegion(255, 2, fkSerial), nil, openpgp.SubkeyStub, ""},
		{"a stub cut short in its three letters", []byte{255, 0, 101, 2, 'G', 'N'}, openpgp.ErrForeignForm, 0, "accounts for"},
		{"a stub with other letters", []byte{255, 0, 101, 2, 'X', 'N', 'U', 1}, openpgp.ErrForeignForm, 0, "accounts for"},
	}
	// each legacy usage octet: an old form that names a cipher, which is not read
	for _, u := range []byte{1, 2, 3, 4, 7, 8, 9, 10, 13, 14, 100, 101, 128, 200, 252} {
		cases = append(cases, c{fmt.Sprintf("legacy usage %d", u), append([]byte{u}, unprot[1:]...), openpgp.ErrForeignProtection, 0, "legacy S2K usage"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := file(tc.area)
			if tc.kind == nil {
				k, err := openpgp.ReadForeignKey(f)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if len(k.Subkeys) != 1 || k.Subkeys[0].Form != tc.form {
					t.Errorf("subkeys %+v, want one of the form %v", k.Subkeys, tc.form)
				}
				if got := fkCertSubkeyBody(t, k.Certificate()); !bytes.Equal(got, d.pub.Body) {
					t.Error("the certificate does not hold the public part exactly")
				}
				return
			}
			err := fkRefused(t, tc.name, f, b, tc.kind)
			if err != nil && !bytes.Contains([]byte(err.Error()), []byte(tc.wantIn)) {
				t.Errorf("the text %q does not say %q", err, tc.wantIn)
			}
		})
	}
}

// The unprotected secret of the primary is held to its length fields too, when the file is read.
func TestForeignPrimaryUnprotectedAreaIsWalked(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		file := b.file(t, fkProt{})
		ps := fkSplit(t, file)
		pub := b.pubBody(t)
		region := ps[0].Body[len(pub):]
		for name, area := range map[string][]byte{
			"one byte short": region[:len(region)-1],
			"one byte long":  append(bytes.Clone(region), 0),
			"no checksum":    region[:len(region)-2],
			"first number claims more": func() []byte {
				r := bytes.Clone(region)
				r[2] += 8
				return r
			}(),
		} {
			_ = fkRefused(t, "an unprotected primary that is "+name, b.withRegion(t, area), b, openpgp.ErrForeignForm)
		}
		for _, u := range []byte{1, 2, 7, 9, 100, 252} {
			r := bytes.Clone(region)
			r[0] = u
			_ = fkRefused(t, fmt.Sprintf("the primary with the legacy usage %d", u), b.withRegion(t, r), b, openpgp.ErrForeignProtection)
		}
	})
}
