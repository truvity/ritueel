package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // a SHA-1 binding is one of the cases
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"sync"
	"testing"

	gecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The inputs that a reviewer built to get the secret of a subkey, or any secret, into Certificate():
// a packet cut by its own length fields, a signature reused, a packet relabelled, bytes hidden in a
// packet that the reader copies without reading. Each is held as a property that does not depend on how
// the reader meets it: it refuses the file, or the key that it returns has a certificate in which no run
// of the secret area and no serial number is found.

// fkAttack is one crafted file with the secret that it tries to get out.
type fkAttack struct {
	name string
	file []byte
	// secret are the byte strings whose runs (of eight) must not be in the certificate, serial whether
	// the serial pattern must not be either.
	secret [][]byte
	serial bool
	// check, when it is set, is held to a key that the reader returned, with the packets of its
	// certificate: what the file is expected to keep and to lose.
	check func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP)
}

var fkAttackTable struct {
	sync.Mutex
	rows []string
}

// fkRunAttacks reads each file and holds the property; it records the error that each ends in.
func fkRunAttacks(t *testing.T, b *fkBase, attacks []fkAttack) {
	t.Helper()
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			before := bytes.Clone(a.file)
			key, err := openpgp.ReadForeignKey(a.file)
			if !bytes.Equal(a.file, before) {
				t.Fatal("the file was changed")
			}
			if err != nil {
				if key != nil || !errors.Is(err, openpgp.ErrForeignKey) {
					t.Fatalf("%v with a key %v", err, key != nil)
				}
				fkCheckText(t, a.name, err, b, a.secret...)
				fkAttackTable.Lock()
				fkAttackTable.rows = append(fkAttackTable.rows, fmt.Sprintf("%s: refused, %s", a.name, fkKindName(err)))
				fkAttackTable.Unlock()
				return
			}
			ps := fkCertProperty(t, a.name, key, a.secret...)
			for _, hay := range fkStrings(key) {
				for _, form := range fkHexForms(fkSerial) {
					if bytes.Contains(hay, form) {
						t.Fatal("the serial number is in a field of the key")
					}
				}
			}
			if a.check != nil {
				a.check(t, key, ps)
			}
			fkAttackTable.Lock()
			fkAttackTable.rows = append(fkAttackTable.rows, fmt.Sprintf("%s: read, a clean certificate of %d packets", a.name, len(ps)))
			fkAttackTable.Unlock()
		})
	}
}

// fkKindName names the narrowest kind of a refusal.
func fkKindName(err error) string {
	for _, k := range []struct {
		e error
		n string
	}{
		{openpgp.ErrForeignAlgorithm, "ErrForeignAlgorithm"},
		{openpgp.ErrForeignProtection, "ErrForeignProtection"}, {openpgp.ErrForeignLimit, "ErrForeignLimit"},
		{openpgp.ErrForeignSelfSignature, "ErrForeignSelfSignature"}, {openpgp.ErrForeignForm, "ErrForeignForm"},
	} {
		if errors.Is(err, k.e) {
			return k.n
		}
	}
	return "ErrForeignKey"
}

// bitsOf is the bit count of a number of n bytes whose first byte is first.
func fkBitsOf(n int, first byte) int {
	bl := 0
	for c := first; c != 0; c >>= 1 {
		bl++
	}
	return (n-1)*8 + bl
}

func fkHdr(bits int) []byte { return []byte{byte(bits >> 8), byte(bits)} }

// fkFakeArea is an unprotected secret area of tiny numbers and its checksum: it passes every structural
// check of an area for the algorithm that has that many numbers.
func fkFakeArea(count int) []byte {
	nums := make([][]byte, count)
	for i := range nums {
		nums[i] = []byte{byte(i + 2)}
	}
	return fkUnprotectedArea(nums...)
}

// fkStretchedModulus is the reviewer's RSA input: the modulus claims n, e and the whole secret area; an
// exponent 00 11 01 00 01 and a fake secret area follow, so that the packet is well formed.
func fkStretchedModulus(s fkSubSecret) []byte {
	from := 8
	m := len(s.body) - from
	out := bytes.Clone(s.body[:6])
	out = append(out, fkHdr(fkBitsOf(m, s.body[from]))...)
	out = append(out, s.body[from:]...)
	out = append(out, 0x00, 0x11, 0x01, 0x00, 0x01)
	return append(out, fkFakeArea(4)...)
}

// fkStretchedFirst is the same for ElGamal (p, g, y) and DSA (p, q, g, y): the first number claims all the
// rest and the area, and the numbers that follow it are tiny.
func fkStretchedFirst(s fkSubSecret, rest int) []byte {
	from := 8
	m := len(s.body) - from
	out := bytes.Clone(s.body[:6])
	out = append(out, fkHdr(fkBitsOf(m, s.body[from]))...)
	out = append(out, s.body[from:]...)
	for i := 0; i < rest; i++ {
		out = append(out, fkMPI([]byte{byte(i + 3)})...)
	}
	return append(out, fkFakeArea(1)...)
}

// fkStretchedAt is a number in the middle that claims what follows it and the area, with the numbers
// that it swallowed written again, tiny, after it.
func fkStretchedAt(s fkSubSecret, at, rest int) []byte {
	m := len(s.body) - (at + 2)
	out := bytes.Clone(s.body[:at])
	out = append(out, fkHdr(fkBitsOf(m, s.body[at+2]))...)
	out = append(out, s.body[at+2:]...)
	for i := 0; i < rest; i++ {
		out = append(out, fkMPI([]byte{byte(i + 3)})...)
	}
	return append(out, fkFakeArea(1)...)
}

// fkDSASub is a DSA subkey whose g and y are short, so that a stretched g stays below the length of p.
func fkDSASub(t testing.TB, usage byte, pBytes, gBytes, yBytes int) fkSubSecret {
	t.Helper()
	pub := []byte{4, 0x65, 0x53, 0xF1, 0x00, 17}
	pub = append(pub, fkBig(t, pBytes)...)
	pub = append(pub, fkBig(t, 32)...)
	gAt := len(pub)
	pub = append(pub, fkBig(t, gBytes)...)
	yAt := len(pub)
	pub = append(pub, fkBig(t, yBytes)...)
	x := fkRandom(t, 32)
	x[0] |= 0x80
	body := append(bytes.Clone(pub), fkAreaOfUsage(t, usage, x)...)
	return fkSubSecret{name: fmt.Sprintf("DSA usage %d", usage), body: body, pubLen: len(pub), last: yAt, first: 6, oid: gAt, usage: usage}
}

// fkElGamalSub is an ElGamal subkey whose g and y are short, so that a stretched g or y stays below
// the length of p.
func fkElGamalSub(t testing.TB, usage byte, pBytes, gBytes, yBytes int) fkSubSecret {
	t.Helper()
	pub := []byte{4, 0x65, 0x53, 0xF1, 0x00, 16}
	pub = append(pub, fkBig(t, pBytes)...)
	gAt := len(pub)
	pub = append(pub, fkBig(t, gBytes)...)
	yAt := len(pub)
	pub = append(pub, fkBig(t, yBytes)...)
	x := fkRandom(t, 32)
	x[0] |= 0x80
	body := append(bytes.Clone(pub), fkAreaOfUsage(t, usage, x)...)
	return fkSubSecret{name: fmt.Sprintf("ElGamal usage %d", usage), body: body, pubLen: len(pub), last: yAt, first: 6, oid: gAt, usage: usage}
}

// fkECDHSwitch is the reviewer's curve switch: a Curve25519 subkey labelled with the identifier of a
// larger curve and a point of that curve's length that starts with 0x04 and holds the rest of the
// packet (the point, the KDF field and the whole secret area); then a KDF field and a fake area follow.
func fkECDHSwitch(t testing.TB, s fkSubSecret, oid []byte, pointLen int) []byte {
	t.Helper()
	rest := s.body[6+11:] // the point, the KDF field and the area of the real subkey
	if len(rest) > pointLen-1 {
		return nil // the rest of the packet does not fit a point of this curve: no such input
	}
	point := append([]byte{0x04}, rest...)
	point = append(point, fkRandom(t, pointLen-len(point))...)
	out := bytes.Clone(s.body[:6])
	out = append(out, oid...)
	out = append(out, fkHdr(fkBitsOf(pointLen, 0x04))...)
	out = append(out, point...)
	out = append(out, 3, 1, 8, 7)
	return append(out, fkFakeArea(1)...)
}

func TestForeignReviewersStretchedPackets(t *testing.T) {
	b := fkNamed(t, "ed25519")
	fkRunAttacks(t, b, fkReviewerAttacks(t))
	fkLogTable(t)
}

// fkLogTable logs the outcome of each crafted input that was run, and clears the table.
func fkLogTable(t *testing.T) {
	t.Helper()
	fkAttackTable.Lock()
	defer fkAttackTable.Unlock()
	for _, r := range fkAttackTable.rows {
		t.Log(r)
	}
	fkAttackTable.rows = nil
}

// fkReviewerAttacks are the stretched and relabelled packets of the reviewers.
func fkReviewerAttacks(t testing.TB) []fkAttack {
	b := fkNamed(t, "ed25519")
	enc, _, _ := fkDonors(t)
	p521 := []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x23}
	p384 := []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}
	var attacks []fkAttack
	add := func(name string, s fkSubSecret, body []byte, serial bool) {
		if body == nil {
			return
		}
		bound := s.bound(t, b, body)
		// the outcome of every one of these: the file is read, the crafted subkey is left out of the
		// certificate (the genuine binding does not verify over the bytes that the stretched packet cuts)
		// and the certificate is the primary, its user ID and its self-signature
		left := func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP) {
			if len(fkCertTagsOf(ps, 14)) != 0 || k.Subkeys[0].InCertificate || k.Subkeys[0].Fingerprint != "" {
				t.Errorf("the crafted subkey is in the certificate: %+v", k.Subkeys[0])
			}
		}
		attacks = append(attacks, fkAttack{name: name, file: bound, secret: [][]byte{s.area()[2:]}, serial: serial, check: left})
		// and with no binding at all
		attacks = append(attacks, fkAttack{name: name + ", no binding", file: fkCraftedFile(t, b, body), secret: [][]byte{s.area()[2:]}, serial: serial, check: left})
	}
	for _, usage := range []byte{0, 254, 255} {
		s := fkRSASub(t, 65537, usage)
		add(fmt.Sprintf("RSA, the modulus claims n, e and the area, usage %d", usage), s, fkStretchedModulus(s), false)
		s17 := fkRSASub(t, 17, usage)
		add(fmt.Sprintf("RSA e=17, the modulus stretched, usage %d", usage), s17, fkStretchedModulus(s17), false)

		eg := fkElGamalSub(t, usage, 256, 4, 40)
		add(fmt.Sprintf("ElGamal, p stretched, usage %d", usage), eg, fkStretchedFirst(eg, 2), false)
		add(fmt.Sprintf("ElGamal, g stretched, usage %d", usage), eg, fkStretchedAt(eg, eg.oid, 1), false)
		add(fmt.Sprintf("ElGamal, y stretched, usage %d", usage), eg, fkStretchedAt(eg, eg.last, 0), false)

		// DSA with a p of 2048 bits in the end: p, q, g and y of 100, 32, 30 and some bytes
		area := len(fkAreaOfUsage(t, usage, bytes.Repeat([]byte{0x80}, 32)))
		y := 88 - area
		if y < 1 {
			y = 1
		}
		ds := fkDSASub(t, usage, 100, 30, y)
		total := len(ds.body) - 8
		add(fmt.Sprintf("DSA, p stretched (to %d bytes), usage %d", total, usage), ds, fkStretchedFirst(ds, 3), false)
		// a DSA whose p is exactly 256 bytes when stretched over everything
		dsBig := fkDSASub(t, usage, 256, 40, 40)
		add(fmt.Sprintf("DSA with a p of 2048 bits, g stretched, usage %d", usage), dsBig, fkStretchedAt(dsBig, dsBig.oid, 1), false)
		add(fmt.Sprintf("DSA with a p of 2048 bits, y stretched, usage %d", usage), dsBig, fkStretchedAt(dsBig, dsBig.last, 0), false)
	}
	// the ECDH switch, for a subkey with a secret (protected and not) and for a stub that carries a serial
	for _, form := range []struct {
		name  string
		usage byte
		stub  bool
	}{{"unprotected", 0, false}, {"protected", 254, false}, {"a stub with a serial number", 255, true}} {
		s := fkRealSub(t, "ECDH", enc[4].pub, enc[4].sec, form.usage, 6, 33, true)
		if form.stub {
			s.body = append(bytes.Clone(enc[4].pub.Body), fkStubRegion(255, 2, fkSerial)...)
		}
		add("ECDH Curve25519 relabelled as P-521, "+form.name, s, fkECDHSwitch(t, s, p521, 133), form.stub)
		add("ECDH Curve25519 relabelled as P-384, "+form.name, s, fkECDHSwitch(t, s, p384, 97), form.stub)
	}
	return attacks
}

// A signature of the primary that is real, put after a crafted subkey in the place of its binding, does not
// confirm it: the binding of another subkey, a self-signature of a user ID, a revocation of a subkey, a
// back-signature.
func TestForeignReusedSignaturesDoNotConfirm(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, sig, _ := fkDonors(t)
	ps := fkSplit(t, b.file(t, fkProt{}))
	s := fkRSASub(t, 65537, 0)
	crafted := fkStretchedModulus(s)
	ret := fkSplit(t, b.subSig(t, b.primaryPair(), enc[0].pair.pub, fkSigSpec{Typ: 0x28, Flags: 0}))[0]
	back := fkPacket{2, fkSerializeSig(t, b.backSig(t, sig[0], fkSigAt(1000)))}
	back = fkSplit(t, back.Body)[0]
	reused := map[string]fkPacket{
		"the real binding of another subkey":      ps[4],
		"the real binding of the signing subkey":  ps[6],
		"the real self-signature of a user ID":    ps[2],
		"a real revocation of another subkey":     ret,
		"a real back-signature of another subkey": back,
		"the genuine binding of this subkey":      fkBinding(t, b, s.body[:s.pubLen]),
	}
	var attacks []fkAttack
	for name, sg := range reused {
		attacks = append(attacks, fkAttack{
			name:   name,
			file:   fkJoin(ps[0], ps[1], ps[2], fkPacket{7, crafted}, sg),
			secret: [][]byte{s.area()[2:]},
		})
		// the same two signatures in front of the subkey as well
		attacks = append(attacks, fkAttack{
			name:   name + ", twice",
			file:   fkJoin(ps[0], ps[1], ps[2], fkPacket{7, crafted}, sg, sg),
			secret: [][]byte{s.area()[2:]},
		})
	}
	fkRunAttacks(t, b, attacks)
	fkLogTable(t)
}

// A secret subkey packet that is relabelled as a public one, and bytes put in packets that the reader
// copies without reading them.
func TestForeignRelabelledAndHiddenSecrets(t *testing.T) {
	fkRunAttacks(t, fkNamed(t, "ed25519"), fkRelabelledAttacks(t))
	fkLogTable(t)
}

func fkRelabelledAttacks(t testing.TB) []fkAttack {
	b := fkNamed(t, "ed25519")
	enc, _, _ := fkDonors(t)
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	w := fkWriter{b}
	var attacks []fkAttack

	// a secret subkey packet with the tag of a public subkey, its secret area still in the body
	for _, usage := range []byte{0, 254} {
		s := fkRSASub(t, 65537, usage)
		sec := [][]byte{s.area()[2:]}
		relabel := func(name string, body []byte) {
			attacks = append(attacks, fkAttack{
				name:   fmt.Sprintf("a secret subkey with the public tag, %s, usage %d", name, usage),
				file:   fkJoin(append(slicesClone(head), fkPacket{14, body}, fkBinding(t, b, s.body[:s.pubLen]))...),
				secret: sec,
			})
		}
		relabel("as it is", s.body)
		for _, k := range []int{len(s.area()), len(s.area()) - 1, 20} {
			relabel(fmt.Sprintf("the last field stretched over %d bytes", k), s.stretch(s.last, k))
		}
		unknown := bytes.Clone(s.body)
		unknown[5] = 99 // an algorithm that is not known: a public packet of it is taken whole
		relabel("an unknown algorithm", unknown)
	}
	// the same for an ECDH subkey and a stub with a serial
	for name, s := range map[string]fkSubSecret{
		"ECDH":    fkRealSub(t, "ECDH", enc[5].pub, enc[5].sec, 0, 6, 33, true),
		"a stub":  {body: append(bytes.Clone(enc[5].pub.Body), fkStubRegion(255, 2, fkSerial)...), pubLen: len(enc[5].pub.Body)},
		"a dummy": {body: append(bytes.Clone(enc[5].pub.Body), fkStubRegion(254, 1, nil)...), pubLen: len(enc[5].pub.Body)},
	} {
		unknown := bytes.Clone(s.body)
		unknown[5] = 99
		for label, body := range map[string][]byte{"as it is": s.body, "an unknown algorithm": unknown} {
			attacks = append(attacks, fkAttack{
				name:   fmt.Sprintf("%s with the public tag, %s", name, label),
				file:   fkJoin(append(slicesClone(head), fkPacket{14, body})...),
				secret: [][]byte{s.body[s.pubLen+2:]},
				serial: name == "a stub",
			})
		}
	}

	// bytes hidden in packets that the reader copies and does not read: the secret key packet of the
	// primary, in a certification by another key (unhashed area), in a user attribute, and in a valid
	// self-signature of the primary (unhashed area)
	for _, prot := range []fkProt{{}, {Pass: fkPass}} {
		primary := fkSplit(t, b.file(t, prot))
		sec := primary[0].Body
		var secrets [][]byte
		if prot.Pass == "" {
			secrets = b.secrets(t).Primary
		} else {
			secrets = [][]byte{sec[len(b.pubBody(t)):]}
		}
		hidden := fkSubpacket(100, false, sec...)
		other := fkThird(t, b)
		// the certification of another key with the secret in its unhashed area: the unhashed area is
		// the bytes after the hashed area in the body
		hl := int(other.Body[4])<<8 | int(other.Body[5])
		withUnhashed := func(body []byte, extra []byte) []byte {
			uh := int(body[6+hl])<<8 | int(body[6+hl+1])
			out := bytes.Clone(body[:6+hl])
			n := uh + len(extra)
			out = append(out, byte(n>>8), byte(n))
			out = append(out, body[6+hl+2:6+hl+2+uh]...)
			out = append(out, extra...)
			return append(out, body[6+hl+2+uh:]...)
		}
		sealed := fkPacket{2, withUnhashed(other.Body, hidden)}
		self := fkPacket{2, w.userSig(t, 0x13, w.areas(1000, fkSubpacket(27, false, 3)), hidden)}
		name := "unprotected"
		if prot.Pass != "" {
			name = "protected"
		}
		sigsOf := func(ps []fkCP) int {
			n := 0
			for _, p := range ps {
				if p.tag == 2 {
					n++
				}
			}
			return n
		}
		// The outcome of each, as of the reader that writes its certificate from what the primary signed.
		attacks = append(attacks,
			// READ: the certification of another key is counted and left out, with what it hid
			fkAttack{name: "a certification by another key with the secret in its unhashed area, primary " + name,
				file: fkJoin(head[0], head[1], head[2], sealed), secret: secrets,
				check: func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP) {
					if k.UserIDs[0].Certifications != 1 || sigsOf(ps) != 1 {
						t.Errorf("the certification of another key: %d counted, %d signatures in the certificate", k.UserIDs[0].Certifications, sigsOf(ps))
					}
				}},
			// READ: a user attribute that no signature of the primary covers is left out and counted
			fkAttack{name: "a user attribute with the secret, primary " + name,
				file: fkJoin(head[0], head[1], head[2], fkPacket{17, append([]byte{byte(len(sec) + 1), 1}, sec...)}), secret: secrets,
				check: func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP) {
					if k.UserAttributes != 1 || k.UserAttributesLeftOut != 1 || len(fkCertTagsOf(ps, 17)) != 0 {
						t.Errorf("the attribute: %d, %d left out, %d in the certificate", k.UserAttributes, k.UserAttributesLeftOut, len(fkCertTagsOf(ps, 17)))
					}
				}},
			// READ: the valid self-signature is kept, valid, with an unhashed area that the reader built
			fkAttack{name: "a self-signature of the primary with the secret in its unhashed area, primary " + name,
				file: fkJoin(head[0], head[1], self), secret: secrets,
				check: func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP) {
					u := k.UserIDs[0]
					if !u.Valid || len(u.Signatures) != 1 || u.Signatures[0].Status != openpgp.SignatureValid || sigsOf(ps) != 1 || len(fkCertUsers(ps)) != 1 {
						t.Errorf("the self-signature with the secret in its unhashed area: %+v", u)
					}
				}},
			// REFUSED (no valid self-signature) when the user ID with the secret as its text is the only one
			fkAttack{name: "a user ID whose text is the secret, alone, primary " + name,
				file: fkJoin(head[0], fkPacket{13, sec}, head[2]), secret: secrets},
			// READ: beside a good user ID the one with the secret has no valid self-signature and is left out
			fkAttack{name: "a user ID whose text is the secret, beside a good one, primary " + name,
				file: fkJoin(head[0], fkPacket{13, sec}, head[2], head[1], head[2]), secret: secrets,
				check: func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP) {
					if got := fkCertUsers(ps); len(got) != 1 || got[0] != fkUser {
						t.Errorf("the user IDs of the certificate: %q", got)
					}
				}},
		)
		// signature values that are not in the form: trailing bytes, a leading zero octet, an extra number.
		// Each is followed by the good self-signature, so that the file is read; the bad one is not in it.
		good := head[2].Body
		cut := len(good) - 68 // the two numbers of an Ed25519 signature: 2 x (2 + 32)
		bits := int(good[cut])<<8 | int(good[cut+1])
		bad := map[string][]byte{
			"trailing bytes after the value":               append(bytes.Clone(good), sec...),
			"a leading zero octet in a number":             slicesJoin(good[:cut+2], []byte{0}, good[cut+2:]),
			"a number whose bit count counts a zero octet": slicesJoin(good[:cut], fkHdr(bits+8), []byte{0}, good[cut+2:]),
			"an extra number after the two":                append(bytes.Clone(good), fkMPI(sec)...),
			"nothing after the signed fields":              good[:cut],
		}
		for label, body := range bad {
			attacks = append(attacks, fkAttack{name: label + ", primary " + name, file: fkJoin(head[0], head[1], fkPacket{2, body}, head[2]), secret: secrets,
				check: func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP) {
					if sigsOf(ps) != 1 || len(k.UserIDs[0].Signatures) != 2 || k.UserIDs[0].Signatures[0].Status.Counts() {
						t.Errorf("a signature whose value is not in the form counts or is written: %+v", k.UserIDs[0].Signatures)
					}
				}})
		}
		// the same valid self-signature, 300 times: one is written, the rest are dropped and counted
		many := []fkPacket{head[0], head[1]}
		for i := 0; i < 300; i++ {
			many = append(many, head[2])
		}
		attacks = append(attacks, fkAttack{name: "the same valid self-signature 300 times, primary " + name, file: fkJoin(many...), secret: secrets,
			check: func(t *testing.T, k *openpgp.ForeignKey, ps []fkCP) {
				if sigsOf(ps) != 1 || k.DuplicatesDropped != 299 {
					t.Errorf("%d signatures written, %d duplicates dropped, want 1 and 299", sigsOf(ps), k.DuplicatesDropped)
				}
			}})
	}
	return attacks
}

// The ordinary secret subkeys, with every binding that the rule of the reader admits and refuses.
func TestForeignSecretSubkeyBindings(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, sig, _ := fkDonors(t)
	w := fkWriter{b}
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	flags := fkSubpacket(27, false, 0x0C)
	bind := func(d fkDonorKey, hashed []byte, hashID byte, h func() hash.Hash) fkPacket {
		return fkPacket{2, w.sign(t, "sub", 0x18, hashed, nil, hashID, h, d.pub.Body)}
	}
	file := func(d fkDonorKey, form fkSubForm, sigs ...fkPacket) []byte {
		return fkJoin(append(append(slicesClone(head), d.packet(t, form)), sigs...)...)
	}
	good := bind(enc[0], w.areas(1000, flags), 8, sha256.New)

	t.Run("a valid binding", func(t *testing.T) {
		k := fkRead(t, file(enc[0], fkAsSecret, good))
		s := k.Subkeys[0]
		if s.Form != openpgp.SubkeyWithSecret || !s.Bound || len(fkCertTags(t, k, 14)) != 1 {
			t.Errorf("%+v", s)
		}
	})
	t.Run("a valid but expired binding", func(t *testing.T) {
		exp := bind(enc[0], w.areas(1000, flags, fkSubpacket(9, false, fkU32(60)...), fkSubpacket(3, false, fkU32(60)...)), 8, sha256.New)
		k := fkRead(t, file(enc[0], fkAsSecret, exp))
		s := k.Subkeys[0]
		if !s.Bound || !s.Expires.Equal(s.Created.Add(60e9)) || len(fkCertTags(t, k, 14)) != 1 {
			t.Errorf("the expiry is not in the view: %+v", s)
		}
	})
	t.Run("a valid binding and a revocation", func(t *testing.T) {
		rev := fkPacket{2, w.sign(t, "sub", 0x28, w.areas(1100, fkReasonSub(2)), nil, 8, sha256.New, enc[0].pub.Body)}
		k := fkRead(t, file(enc[0], fkAsSecret, good, rev))
		if s := k.Subkeys[0]; !s.Bound || !s.Revoked || len(fkCertTags(t, k, 14)) != 1 {
			t.Errorf("%+v", s)
		}
	})
	t.Run("a signing subkey with a binding and no back-signature", func(t *testing.T) {
		nb := bind(sig[0], w.areas(1000, fkSubpacket(27, false, 0x02)), 8, sha256.New)
		k := fkRead(t, file(sig[0], fkAsSecret, nb))
		// an incomplete binding is not written: the subkey is left out, reported, with its fingerprint
		if s := k.Subkeys[0]; s.Bound || s.InCertificate || !s.IncompleteBinding || s.Fingerprint != hexOf(sig[0].pair.pub.Fingerprint) || len(fkCertTags(t, k, 14)) != 0 {
			t.Errorf("a signing subkey with no back-signature: %+v", s)
		}
		_ = fkCertProperty(t, "a signing subkey with no back-signature", k)
	})
	t.Run("a binding with SHA-1", func(t *testing.T) {
		weak := bind(enc[0], w.areas(1000, flags), 2, sha1.New)
		k := fkRead(t, file(enc[0], fkAsSecret, weak))
		if s := k.Subkeys[0]; !s.Bound || !s.WeakHash || len(fkCertTags(t, k, 14)) != 1 {
			t.Errorf("%+v", s)
		}
	})
	t.Run("a stub with a binding, and no serial anywhere", func(t *testing.T) {
		k := fkRead(t, file(enc[0], fkAsCard, good))
		if s := k.Subkeys[0]; s.Form != openpgp.SubkeyStub || !s.Bound || len(fkCertTags(t, k, 14)) != 1 {
			t.Errorf("%+v", s)
		}
		for _, hay := range append(fkStrings(k), k.Certificate()) {
			for _, form := range fkHexForms(fkSerial) {
				if bytes.Contains(hay, form) {
					t.Fatal("the serial number is in what the reader returns")
				}
			}
		}
	})
	t.Run("a public subkey with no binding", func(t *testing.T) {
		// the certificate holds only what a signature of the primary confirms: a subkey with none is left
		// out and reported, with no fingerprint
		k := fkRead(t, file(enc[0], fkAsPublic))
		if s := k.Subkeys[0]; s.Form != openpgp.SubkeyPublic || s.Bound || s.InCertificate || s.Fingerprint != "" || len(fkCertTags(t, k, 14)) != 0 {
			t.Errorf("%+v", s)
		}
		_ = fkCertProperty(t, "a public subkey with no binding", k)
	})

	// the refusals: the file is refused or, when it is read, the subkey is not in the certificate
	md5 := bind(enc[0], w.areas(1000, flags), 1, sha256.New)
	badSig := fkPacket{2, bytes.Clone(good.Body)}
	badSig.Body[len(badSig.Body)-1] ^= 1
	for _, c := range []struct {
		name string
		sigs []fkPacket
	}{
		{"no binding", nil},
		{"only an MD5 binding", []fkPacket{md5}},
		{"a binding that does not verify", []fkPacket{badSig}},
	} {
		for _, form := range []fkSubForm{fkAsSecret, fkAsOtherPass, fkAsCard, fkAsDummy} {
			t.Run(c.name+fmt.Sprintf(", form %d", form), func(t *testing.T) {
				k, err := openpgp.ReadForeignKey(file(enc[0], form, c.sigs...))
				if err != nil {
					if k != nil || !errors.Is(err, openpgp.ErrForeignKey) {
						t.Fatalf("%v", err)
					}
					t.Logf("refused with %s", fkKindName(err))
					return
				}
				if n := len(fkCertTags(t, k, 14)); n != 0 {
					t.Errorf("a secret subkey with %s is in the certificate", c.name)
				}
			})
		}
	}
}

// fkCertTagsOf lists the bodies of the packets of a tag in a walked certificate.
func fkCertTagsOf(ps []fkCP, tag byte) [][]byte {
	var out [][]byte
	for _, p := range ps {
		if p.tag == tag {
			out = append(out, p.body)
		}
	}
	return out
}

// fkCertTags lists the bodies of the packets of a tag in the certificate of a key.
func fkCertTags(t testing.TB, k *openpgp.ForeignKey, tag byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range splitPackets(t, k.Certificate()) {
		if p.Tag == tag {
			out = append(out, p.Body)
		}
	}
	return out
}

// Sign and Wipe from many goroutines: every Sign returns a signature that verifies or ErrSecretWiped.
func TestForeignSignWhileWiping(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		rounds := 20
		if b.name == "rsa4096" {
			rounds = 3
		}
		for r := 0; r < rounds; r++ {
			k := fkRead(t, b.file(t, fkProt{}))
			s, err := k.OpenSecret(nil)
			if err != nil {
				t.Fatal(err)
			}
			signer := s.Signer()
			pub := fkCertPublic(t, k.Certificate())
			var wg sync.WaitGroup
			errs := make(chan error, 64)
			start := make(chan struct{})
			for i := 0; i < 6; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for j := 0; j < 4; j++ {
						msg, sig, err := fkSignOnce(b, signer)
						switch {
						case errors.Is(err, openpgp.ErrSecretWiped):
							if sig != nil {
								errs <- errors.New("a signature with ErrSecretWiped")
							}
						case err != nil:
							errs <- err
						case !fkVerifyOnce(pub, msg, sig):
							errs <- errors.New("a signature that does not verify")
						}
					}
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				s.Wipe()
			}()
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, openpgp.ErrSecretWiped) {
				t.Errorf("after the wipe: %v", err)
			}
		}
	})
}

// strong and weak signatures: the fields come from the newest signature that counts, whatever its hash (the
// person's last choice), and WeakHash says that they come from a weak one.
func TestForeignStrongBeforeWeakFields(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	user := func(h byte, hf func() hash.Hash, at int, flags byte, rest ...[]byte) []byte {
		return w.sign(t, "user", 0x13, w.areas(at, append([][]byte{fkSubpacket(27, false, flags)}, rest...)...), nil, h, hf, []byte(fkUser))
	}
	sub := func(h byte, hf func() hash.Hash, at int, flags byte) []byte {
		return w.sign(t, "sub", 0x18, w.areas(at, fkSubpacket(27, false, flags)), nil, h, hf, enc[3].pub.Body)
	}
	cases := []struct {
		name         string
		sigs         [][]byte
		created      int
		flags        byte
		weak         bool
		subSigs      [][]byte
		boundAt      int
		subFlags     byte
		subWeakFlags bool
	}{
		{"a strong one older than a weak one", [][]byte{user(8, sha256.New, 1000, 3), user(2, sha1.New, 1100, 1)}, 1100, 1, true,
			[][]byte{sub(8, sha256.New, 1000, 0x0C), sub(2, sha1.New, 1100, 0x04)}, 1100, 0x04, true},
		{"a weak one older than a strong one", [][]byte{user(2, sha1.New, 1000, 1), user(8, sha256.New, 1100, 3)}, 1100, 3, false,
			[][]byte{sub(2, sha1.New, 1000, 0x04), sub(8, sha256.New, 1100, 0x0C)}, 1100, 0x0C, false},
		{"only weak ones", [][]byte{user(2, sha1.New, 1000, 1), user(2, sha1.New, 1100, 3)}, 1100, 3, true,
			[][]byte{sub(2, sha1.New, 1000, 0x04), sub(2, sha1.New, 1100, 0x08)}, 1100, 0x08, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := []fkPacket{}
			head := fkTemplateHead(t, b.file(t, fkProt{}))
			ps = append(ps, head[0], head[1])
			for _, s := range c.sigs {
				ps = append(ps, fkPacket{2, s})
			}
			ps = append(ps, enc[3].pub)
			for _, s := range c.subSigs {
				ps = append(ps, fkPacket{2, s})
			}
			k := fkRead(t, fkJoin(ps...))
			u := k.UserIDs[0]
			if !u.Valid || !u.Created.Equal(fkAt(c.created)) || u.KeyFlags != c.flags || u.WeakHash != c.weak {
				t.Errorf("user ID: created %v flags %d weak %v, want %v %d %v", u.Created, u.KeyFlags, u.WeakHash, fkAt(c.created), c.flags, c.weak)
			}
			s := k.Subkeys[0]
			if !s.Bound || !s.BoundAt.Equal(fkAt(c.boundAt)) || s.Flags != c.subFlags || s.WeakHash != c.subWeakFlags {
				t.Errorf("subkey: bound at %v flags %d weak %v, want %v %d %v", s.BoundAt, s.Flags, s.WeakHash, fkAt(c.boundAt), c.subFlags, c.subWeakFlags)
			}
		})
	}
	// a soft revocation is compared with the newest self-signature of either kind
	rev := w.sign(t, "user", 0x30, w.areas(1050, fkReasonSub(32)), nil, 8, sha256.New, []byte(fkUser))
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	k := fkRead(t, fkJoin(head[0], head[1], fkPacket{2, user(8, sha256.New, 1000, 3)}, fkPacket{2, user(2, sha1.New, 1100, 1)}, fkPacket{2, rev}))
	if k.UserIDs[0].Revoked {
		t.Error("a soft revocation older than a weak self-signature revokes")
	}
}

// fkSignOnce signs a fixed message as the algorithm of the template does, and fkVerifyOnce verifies it with
// the public key that go-crypto reads from the certificate.
func fkSignOnce(b *fkBase, s crypto.Signer) (msg, sig []byte, err error) {
	d := sha256.Sum256([]byte("many goroutines"))
	switch b.name {
	case "ed25519":
		msg = d[:]
		sig, err = s.Sign(rand.Reader, msg, crypto.Hash(0))
	case "p384":
		d := sha512.Sum384([]byte("many goroutines"))
		msg = d[:]
		sig, err = s.Sign(rand.Reader, msg, crypto.SHA384)
	default:
		msg = d[:]
		sig, err = s.Sign(rand.Reader, msg, crypto.SHA256)
	}
	return msg, sig, err
}

func fkVerifyOnce(pk *gpacket.PublicKey, msg, sig []byte) bool {
	switch pub := pk.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, msg, sig) == nil
	case *eddsa.PublicKey:
		return ed25519.Verify(ed25519.PublicKey(pub.X), msg, sig)
	case *gecdsa.PublicKey:
		raw := append([]byte{4}, pub.X.FillBytes(make([]byte, 48))...)
		raw = append(raw, pub.Y.FillBytes(make([]byte, 48))...)
		std, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw)
		return err == nil && ecdsa.VerifyASN1(std, msg, sig)
	}
	return false
}

func slicesJoin(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
