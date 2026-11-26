package openpgp_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sort"
	"testing"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The refusals of ReadForeignCertificate, one change at a time in a good certificate. Every refusal is an
// ErrForeignKey with no key; the kind says why. A change that leaves another certificate that the reader
// would write itself (a signature of a component taken out when another stays, a packet cut at the end of
// a signature) is accepted, and the certificate that comes back is then the input.

type qaCase struct {
	name string
	cert []byte
	// kinds are the kinds that the refusal may be: any one of them. Empty means any ErrForeignKey.
	kinds []error
	// mayAccept is true when the change leaves a certificate that the reader would write.
	mayAccept bool
}

// qaComponent is the index of the component of a packet: the primary and its key-level signatures are 0, and
// each user ID, user attribute or subkey starts a new one.
func qaComponents(ps []fkPacket) []int {
	out := make([]int, len(ps))
	c := 0
	for i, p := range ps {
		if i > 0 && (p.Tag == 13 || p.Tag == 17 || p.Tag == 14) {
			c++
		}
		out[i] = c
	}
	return out
}

func qaJoin(parts ...[]fkPacket) []byte {
	var all []fkPacket
	for _, p := range parts {
		all = append(all, p...)
	}
	return fkJoin(all...)
}

func qaIns(ps []fkPacket, at int, extra ...fkPacket) []fkPacket {
	out := slices.Clone(ps[:at])
	out = append(out, extra...)
	return append(out, ps[at:]...)
}

func qaDel(ps []fkPacket, at int) []fkPacket {
	return append(slices.Clone(ps[:at]), ps[at+1:]...)
}

func qaSwap(ps []fkPacket, i, j int) []fkPacket {
	out := slices.Clone(ps)
	out[i], out[j] = out[j], out[i]
	return out
}

// qaWithUnhashed adds a subpacket to the end of the unhashed area of a signature body, which no signature covers.
func qaWithUnhashed(body []byte, sp []byte) []byte {
	hl := int(body[4])<<8 | int(body[5])
	ul := int(body[6+hl])<<8 | int(body[7+hl])
	n := ul + len(sp)
	out := bytes.Clone(body[:6+hl])
	out = append(out, byte(n>>8), byte(n))
	out = append(out, body[8+hl:8+hl+ul]...)
	out = append(out, sp...)
	return append(out, body[8+hl+ul:]...)
}

// qaCases are the changes of a certificate. other is a key that is not the primary, with a certification of
// the user ID by it.
func qaCases(t testing.TB, b *fkBase, ps []fkPacket, stride int) []qaCase {
	t.Helper()
	comp := qaComponents(ps)
	var cases []qaCase
	add := func(name string, cert []byte, mayAccept bool, kinds ...error) {
		cases = append(cases, qaCase{name, cert, kinds, mayAccept})
	}
	sigs := []int{}
	for i, p := range ps {
		if p.Tag == 2 {
			sigs = append(sigs, i)
		}
	}
	countIn := map[int]int{}
	for _, i := range sigs {
		countIn[comp[i]]++
	}
	sameComponentSigs := func(i, j int) bool { return ps[i].Tag == 2 && ps[j].Tag == 2 && comp[i] == comp[j] }

	// two packets swapped: the neighbours, and the packets two apart
	for i := 0; i+1 < len(ps); i++ {
		add(fmt.Sprintf("packets %d and %d swapped", i, i+1), fkJoin(qaSwap(ps, i, i+1)...), sameComponentSigs(i, i+1))
	}
	for i := 0; i+2 < len(ps); i++ {
		add(fmt.Sprintf("packets %d and %d swapped", i, i+2), fkJoin(qaSwap(ps, i, i+2)...), sameComponentSigs(i, i+2))
	}
	// a packet that the reader does not write, in front of each packet and at the end
	for _, p := range []fkPacket{{12, []byte{0, 1, 2}}, {10, []byte("PGP")}, {21, []byte{1, 2, 3}}, {11, []byte("literal")}} {
		for i := 0; i <= len(ps); i++ {
			add(fmt.Sprintf("packet of tag %d before packet %d", p.Tag, i), fkJoin(qaIns(ps, i, p)...), false)
		}
	}
	// a header that is not the shortest, and an old-format header, for each packet
	for i, p := range ps {
		long := slices.Clone(ps)
		out := slices.Concat(fkJoin(ps[:i]...), wrapLong(p.Tag, p.Body), fkJoin(ps[i+1:]...))
		_ = long
		add(fmt.Sprintf("packet %d with a five-octet length", i), out, false, openpgp.ErrAdoptedCertificate)
		old := slices.Concat(fkJoin(ps[:i]...), oldHeader(p.Tag, p.Body), fkJoin(ps[i+1:]...))
		add(fmt.Sprintf("packet %d with an old-format header", i), old, false, openpgp.ErrAdoptedCertificate)
	}
	// an unhashed subpacket that the reader does not write, in each signature
	for _, i := range sigs {
		for _, sp := range [][]byte{
			fkSubpacket(26, false, []byte("https://example.org/policy")...),
			fkSubpacket(16, false, 1, 2, 3, 4, 5, 6, 7, 8),
			fkSubpacket(20, false, make([]byte, 12)...),
			fkSubpacket(99, true, 1),
		} {
			sg := slices.Clone(ps)
			sg[i] = fkPacket{2, qaWithUnhashed(ps[i].Body, sp)}
			// an unknown critical subpacket stops the signature from counting, even in the unhashed area
			add(fmt.Sprintf("signature %d with an unhashed subpacket of type %d", i, sp[1]&0x7F), fkJoin(sg...), false, openpgp.ErrAdoptedCertificate, openpgp.ErrForeignSelfSignature)
		}
	}
	// a signature twice, next to itself and at the end of its component
	for _, i := range sigs {
		add(fmt.Sprintf("signature %d twice", i), fkJoin(qaIns(ps, i+1, ps[i])...), false, openpgp.ErrAdoptedCertificate)
	}
	// a signature taken out: a component that is left with none, or with another one
	for _, i := range sigs {
		alone := countIn[comp[i]] == 1
		var kinds []error
		if alone {
			kinds = []error{openpgp.ErrAdoptedCertificate, openpgp.ErrForeignSelfSignature}
		}
		add(fmt.Sprintf("signature %d taken out (%d in its component)", i, countIn[comp[i]]), fkJoin(qaDel(ps, i)...), !alone, kinds...)
	}
	// one bit of a signature changed
	step := 0
	for _, i := range sigs {
		body := ps[i].Body
		for off := 0; off < len(body); off++ {
			for bit := 0; bit < 8; bit++ {
				step++
				if step%stride != 0 {
					continue
				}
				mod := slices.Clone(ps)
				nb := bytes.Clone(body)
				nb[off] ^= 1 << bit
				mod[i] = fkPacket{2, nb}
				add(fmt.Sprintf("signature %d byte %d bit %d changed", i, off, bit), fkJoin(mod...), false)
			}
		}
	}
	// a user ID with no signature: after the last component of user IDs, and after a subkey
	lastUser, firstSub := -1, len(ps)
	for i, p := range ps {
		if p.Tag == 13 || p.Tag == 17 {
			lastUser = i
		}
		if p.Tag == 14 && firstSub == len(ps) {
			firstSub = i
		}
	}
	bare := fkPacket{13, []byte("Nobody <nobody@example.org>")}
	add("a user ID with no signature before the subkeys", fkJoin(qaIns(ps, firstSub, bare)...), false, openpgp.ErrAdoptedCertificate)
	add("a user ID with no signature right after the primary", fkJoin(qaIns(ps, 1, bare)...), false, openpgp.ErrAdoptedCertificate)
	if firstSub < len(ps) {
		add("a user ID with no signature after a subkey", fkJoin(qaIns(ps, len(ps), bare)...), false, openpgp.ErrForeignForm)
	}
	add("a user ID repeated with no signature", fkJoin(qaIns(ps, lastUser+1, ps[lastUser])...), false)
	// a certification of the user ID by another key, and a revocation of the key by another key
	_, _, other := fkDonors(t)
	foreign := fkSplit(t, b.certSig(t, other, b.ent.PrimaryKey, fkUser, fkSigSpec{Typ: gpacket.SigTypeGenericCert}))
	for i, p := range ps {
		if p.Tag == 13 && string(p.Body) == fkUser {
			add("a certification of the user ID by another key", fkJoin(qaIns(ps, i+2, foreign...)...), false, openpgp.ErrAdoptedCertificate)
			add("a certification of the user ID by another key, first", fkJoin(qaIns(ps, i+1, foreign...)...), false, openpgp.ErrAdoptedCertificate)
		}
	}
	rev := fkSplit(t, b.keySig(t, other, b.ent.PrimaryKey, fkSigSpec{Typ: gpacket.SigTypeKeyRevocation}))
	add("a revocation of the key by another key", fkJoin(qaIns(ps, 1, rev...)...), false, openpgp.ErrAdoptedCertificate)
	// the secret packets of the export in place of the public ones
	export := fkSplit(t, b.plain)
	sec := slices.Clone(ps)
	sec[0] = export[0]
	add("the secret key packet in place of the public one", fkJoin(sec...), false, openpgp.ErrAdoptedCertificate)
	for i, p := range ps {
		if p.Tag != 14 {
			continue
		}
		for _, e := range export {
			if e.Tag == 7 && bytes.HasPrefix(e.Body, p.Body) {
				sub := slices.Clone(ps)
				sub[i] = e
				add(fmt.Sprintf("the secret subkey packet in place of subkey %d", i), fkJoin(sub...), false, openpgp.ErrAdoptedCertificate)
			}
		}
	}
	// a second primary
	add("a second primary at the end", fkJoin(append(slices.Clone(ps), ps[0])...), false, openpgp.ErrForeignPrimaries)
	add("a second primary after the first", fkJoin(qaIns(ps, 1, ps[0])...), false, openpgp.ErrForeignPrimaries)
	add("the certificate twice", slices.Concat(fkJoin(ps...), fkJoin(ps...)), false, openpgp.ErrForeignPrimaries)
	add("the secret key packet as a second primary", fkJoin(append(slices.Clone(ps), export[0])...), false)
	// trailing bytes
	whole := fkJoin(ps...)
	for _, tail := range [][]byte{{0}, {0xC0}, {0xC2, 0x05}, bytes.Repeat([]byte{0xAA}, 100), {0xC0 | 12, 0}} {
		add(fmt.Sprintf("%d bytes after the certificate: %x", len(tail), tail[:min(len(tail), 4)]), append(bytes.Clone(whole), tail...), false)
	}
	add("bytes before the certificate", append([]byte{0}, whole...), false)
	// nothing, and one byte
	add("an empty input", nil, false, openpgp.ErrForeignForm)
	add("an input of one byte", []byte{0xC6}, false, openpgp.ErrForeignForm)
	return cases
}

// qaRun reads a case: a refusal with no key, of a kind that is allowed, with a text that is safe; or, where
// the change leaves a certificate that the reader would write, that certificate.
func qaRun(t *testing.T, b *fkBase, c qaCase, kinds map[string]int) {
	t.Helper()
	k, err := openpgp.ReadForeignCertificate(c.cert)
	if err == nil {
		if !c.mayAccept {
			t.Errorf("%s: the certificate was read, want a refusal", c.name)
			return
		}
		if k == nil || !bytes.Equal(k.Certificate(), c.cert) {
			t.Errorf("%s: a certificate that is accepted is not the input", c.name)
		}
		kinds["accepted"]++
		return
	}
	if k != nil {
		t.Errorf("%s: a key is returned with the error %v", c.name, err)
	}
	if !errors.Is(err, openpgp.ErrForeignKey) {
		t.Errorf("%s: %v is not an ErrForeignKey", c.name, err)
	}
	if len(c.kinds) > 0 {
		ok := false
		for _, kind := range c.kinds {
			ok = ok || errors.Is(err, kind)
		}
		if !ok {
			t.Errorf("%s: %v is none of the kinds %v", c.name, err, c.kinds)
		}
	}
	kinds[qaKind(err)]++
	fkCheckText(t, c.name, err, b)
}

// qaKind names the narrowest kind of a refusal of the reader.
func qaKind(err error) string {
	for _, k := range []struct {
		name string
		kind error
	}{
		{"ErrAdoptedCertificate", openpgp.ErrAdoptedCertificate}, {"ErrForeignSelfSignature", openpgp.ErrForeignSelfSignature},
		{"ErrForeignLimit", openpgp.ErrForeignLimit}, {"ErrForeignPrimaries", openpgp.ErrForeignPrimaries},
		{"ErrForeignPacket", openpgp.ErrForeignPacket}, {"ErrForeignNoSecret", openpgp.ErrForeignNoSecret},
		{"ErrForeignAlgorithm", openpgp.ErrForeignAlgorithm}, {"ErrForeignVersion", openpgp.ErrForeignVersion},
		{"ErrForeignArmour", openpgp.ErrForeignArmour}, {"ErrForeignForm", openpgp.ErrForeignForm},
	} {
		if errors.Is(err, k.kind) {
			return k.name
		}
	}
	return "ErrForeignKey"
}

func qaReport(t *testing.T, what string, kinds map[string]int) {
	var names []string
	for k := range kinds {
		names = append(names, fmt.Sprintf("%s=%d", k, kinds[k]))
	}
	sort.Strings(names)
	t.Logf("%s: %v", what, names)
}

func TestQAReadForeignCertificateRefusalTable(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		plain := fkSplit(t, fkRead(t, b.plain).Certificate())
		stride := 1
		switch b.name {
		case "rsa4096":
			stride = 5
		case "p384":
			stride = 3
		}
		kinds := map[string]int{}
		cases := qaCases(t, b, plain, stride)
		for _, c := range cases {
			qaRun(t, b, c, kinds)
		}
		qaReport(t, b.name+" (the key as go-crypto makes it)", kinds)
		if b.name == "rsa4096" {
			return
		}
		// the same changes in a certificate with several user IDs, an attribute, revoked and SHA-1 ones, and
		// subkeys of every kind
		rich := fkSplit(t, fkRead(t, fkRichOf(t, b, false, true).file).Certificate())
		kinds = map[string]int{}
		cases = qaCases(t, b, rich, 400)
		for _, c := range cases {
			qaRun(t, b, c, kinds)
		}
		qaReport(t, b.name+" (the rich certificate)", kinds)
	})
}

// A certificate cut short is refused, except where it is cut after a whole packet and what is left is a
// certificate that the reader writes: then it is accepted and is the prefix, and the snapshot is that of a key
// that has less in it.
func TestQAReadForeignCertificateTruncations(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		sources := map[string][]byte{"plain": fkRead(t, b.plain).Certificate()}
		if b.name != "rsa4096" {
			sources["rich"] = fkRead(t, fkRichOf(t, b, false, true).file).Certificate()
		}
		for name, cert := range sources {
			ps := fkSplit(t, cert)
			boundary := map[int]bool{}
			off := 0
			for _, p := range ps {
				off += len(wrap(p.Tag, p.Body))
				boundary[off] = true
			}
			step := 1
			if name == "rich" {
				step = 3
			}
			accepted, refused := 0, 0
			for n := 0; n < len(cert); n++ {
				if step > 1 && n%step != 0 && !boundary[n] && !boundary[n+1] && !boundary[n-1] {
					continue
				}
				k, err := openpgp.ReadForeignCertificate(cert[:n])
				if err == nil {
					if !boundary[n] {
						t.Errorf("%s: a certificate cut at %d, in the middle of a packet, was read", name, n)
					} else if !bytes.Equal(k.Certificate(), cert[:n]) {
						t.Errorf("%s: a certificate cut at %d is read as another certificate", name, n)
					}
					accepted++
					continue
				}
				refused++
				if k != nil || !errors.Is(err, openpgp.ErrForeignKey) {
					t.Errorf("%s: cut at %d: %v with a key %v", name, n, err, k != nil)
				}
				if !boundary[n] && !errors.Is(err, openpgp.ErrForeignForm) {
					t.Errorf("%s: cut at %d, in the middle of a packet: %v is not an ErrForeignForm", name, n, err)
				}
				fkCheckText(t, fmt.Sprintf("%s cut at %d", name, n), err, b)
			}
			t.Logf("%s %s: %d bytes, %d cuts refused, %d accepted (at the end of a packet)", b.name, name, len(cert), refused, accepted)
			if accepted == 0 {
				t.Errorf("%s: no cut at the end of a packet is a certificate: the signature of the user ID is cut off with nothing left", name)
			}
		}
	})
}

// The order of two whole blocks, or of two signatures of one component, is the order of the input: the reader
// writes what it reads in the order it reads it, so a certificate with the blocks the other way round is a
// fixpoint too. This pins that, with what the snapshot makes of it.
func TestQAReadForeignCertificatePermutedBlocksAreKept(t *testing.T) {
	b := fkNamed(t, "ed25519")
	rich := fkSplit(t, fkRead(t, fkRichOf(t, b, false, true).file).Certificate())
	var users []int // index of each user ID packet
	for i, p := range rich {
		if p.Tag == 13 {
			users = append(users, i)
		}
	}
	if len(users) < 3 {
		t.Fatalf("the rich certificate has %d user IDs", len(users))
	}
	// the blocks of the first two user IDs swapped
	a, c := users[0], users[1]
	d := users[2]
	swapped := slices.Concat(rich[:a], rich[c:d], rich[a:c], rich[d:])
	k0 := fkRead(t, fkRichOf(t, b, false, true).file)
	k, err := openpgp.ReadForeignCertificate(fkJoin(swapped...))
	if err != nil {
		t.Fatalf("the blocks of two user IDs swapped: %v", err)
	}
	if !bytes.Equal(k.Certificate(), fkJoin(swapped...)) {
		t.Error("not the input")
	}
	if got, want := openpgp.SnapshotUsers(k)[0].Text, openpgp.SnapshotUsers(k0)[1].Text; got != want {
		t.Errorf("the first user ID of the snapshot is %q, want the second of the original, %q", got, want)
	}
	t.Logf("the order of the user ID blocks of an accepted certificate is the input's: a permutation of blocks is a fixpoint")
}

// The wrong door: an export to the reader of certificates, a certificate to the reader of exports, the secret of a
// key that was read from a certificate.
func TestQAReadForeignCertificateWrongDoor(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		export := fkRead(t, b.plain)
		cert := export.Certificate()
		for name, in := range map[string][]byte{
			"an export":                      b.plain,
			"a protected export":             b.file(t, fkProt{Pass: fkPass}),
			"an armoured export":             fkArmourKey(t, b.plain),
			"an armoured certificate":        fkArmour(t, cert, "PGP PUBLIC KEY BLOCK", nil),
			"the rich export":                fkRichOf(t, b, false, true).file,
			"a certificate and then secrets": append(bytes.Clone(cert), b.plain...),
		} {
			if k, err := openpgp.ReadForeignCertificate(in); k != nil || err == nil {
				t.Errorf("%s: read by ReadForeignCertificate: %v", name, err)
			} else {
				if !errors.Is(err, openpgp.ErrForeignKey) {
					t.Errorf("%s: %v is not an ErrForeignKey", name, err)
				}
				fkCheckText(t, name, err, b)
			}
		}
		// the export is refused by name: it holds a secret key packet
		if _, err := openpgp.ReadForeignCertificate(b.plain); !errors.Is(err, openpgp.ErrAdoptedCertificate) {
			t.Errorf("an export: %v", err)
		}
		// a certificate is no export
		for name, in := range map[string][]byte{"a certificate": cert, "an armoured certificate": fkArmour(t, cert, "PGP PUBLIC KEY BLOCK", nil), "an armoured certificate as a private block": fkArmourKey(t, cert)} {
			k, err := openpgp.ReadForeignKey(in)
			if k != nil || err == nil || !errors.Is(err, openpgp.ErrForeignKey) {
				t.Errorf("%s: read by ReadForeignKey: %v", name, err)
				continue
			}
			fkCheckText(t, name, err, b)
		}
		if _, err := openpgp.ReadForeignKey(cert); !errors.Is(err, openpgp.ErrForeignNoSecret) {
			t.Errorf("a certificate to ReadForeignKey: %v", err)
		}
		// the secret of a key read from a certificate: a named refusal, for every passphrase, before and after a wipe
		k, err := openpgp.ReadForeignCertificate(cert)
		if err != nil {
			t.Fatal(err)
		}
		for _, pass := range [][]byte{nil, []byte(fkPass), bytes.Repeat([]byte("x"), openpgp.MaxForeignPassphraseBytes+1)} {
			s, err := k.OpenSecret(pass)
			if s != nil || !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrForeignKey) {
				t.Errorf("OpenSecret(%d bytes) of a certificate: %v, %v", len(pass), s, err)
			}
			fkCheckText(t, "OpenSecret", err, b)
		}
		k.Wipe()
		k.Wipe()
		if s, err := k.OpenSecret(nil); s != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("OpenSecret after a wipe: %v, %v", s, err)
		}
		if !bytes.Equal(k.Certificate(), cert) {
			t.Error("a wipe changed the certificate")
		}
		// the key of a certificate still makes an issuer with the secret from the export
		sec, err := export.OpenSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer sec.Wipe()
		k2, _ := openpgp.ReadForeignCertificate(cert)
		if _, err := openpgp.NewAdoptedIssuer(k2, sec.Signer()); err != nil {
			t.Errorf("the issuer of a key read from a certificate: %v", err)
		}
	})
}
