package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// These tests read the reader of an answer (docs/reference/hand-off-contract.md, "OpenPGP subkey",
// "What comes back" and "What the requester checks before it installs"). Each expectation is what
// the page says. The inputs are the vector files, the output of BindSubkey, and bindings that the
// tests write by hand with their own signer (see binding_kit_test.go).

// lastSecond is the last second that a time field of OpenPGP holds (the year 2106).
const lastSecond = 1<<32 - 1

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// The fingerprints that the vector set gives to its three test primaries: A and B are on the root
// list, Z is not.
const (
	fingerprintA = "6df387de63525c9dc0ec1174bd138d2c4889b79b"
	fingerprintB = "c4288657012230588b51fa66e0831b9c6e084f39"
	fingerprintZ = "2015fa9a72973797c70fc6388b163000f8338ed9"
)

// boundVectors is what the page says about each OpenPGP answer of the vector set. issuer is the
// primary that bound the subkey ("a", "b" or "z"); shape is set when the signature verifies and the
// subpackets are not the set of the page.
var boundVectors = []struct {
	id         string
	issuer     string
	capability string
	ends       string // the end of the subkey, RFC 3339
	shape      bool
}{
	{"pgp-piv-valid", "a", "sign", "2027-12-15T12:00:00Z", false},
	{"pgp-kms-valid", "a", "sign", "2027-12-15T12:00:00Z", false},
	{"pgp-openpgp-card-valid", "a", "sign", "2027-12-15T12:00:00Z", false},
	{"pgp-software-valid", "a", "sign", "2027-12-15T12:00:00Z", false},
	{"pgp-response-other-primary", "b", "sign", "2027-12-15T12:00:00Z", false},
	{"pgp-response-no-backsig", "a", "", "", true},
	{"pgp-response-wrong-subkey", "a", "sign", "2027-12-15T12:00:00Z", false},
	{"pgp-response-wrong-primary", "z", "sign", "2027-12-15T12:00:00Z", false},
	{"pgp-response-short-expiry", "a", "sign", "2027-01-14T12:00:00Z", false},
	{"pgp-openpgp-card-authenticate", "a", "authenticate", "2027-12-15T12:00:00Z", false},
	{"pgp-response-authenticate-bound-for-signing", "a", "sign", "2027-12-15T12:00:00Z", false},
}

var issuerFingerprints = map[string]string{"a": fingerprintA, "b": fingerprintB, "z": fingerprintZ}

func boundFile(t testing.TB, id string) []byte {
	t.Helper()
	return vector(t, "responses", id+".bound.pgp")
}

// manifestResponses is the list of answers of the vector set.
func manifestResponses(t testing.TB) []struct{ ID, Type, Request string } {
	t.Helper()
	var m struct {
		Responses []struct{ ID, Type, Request string }
	}
	if err := json.Unmarshal(vector(t, "manifest.json"), &m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	return m.Responses
}

// An independent check of a key's end: the creation time in the key packet plus the key expiration
// time of the signature, read by the tests' own packet reader.
func endOfSubkey(t testing.TB, subPacket, bindingPkt []byte) time.Time {
	t.Helper()
	sp := splitPackets(t, subPacket)[0]
	createdAt := binary.BigEndian.Uint32(sp.Body[1:5])
	sig := parseSig(t, bodyOf(t, bindingPkt))
	life := binary.BigEndian.Uint32(find(t, sig.Hashed, 9).Data)
	return time.Unix(int64(createdAt)+int64(life), 0).UTC()
}

func TestBoundVectorsListEveryOpenPGPAnswerOfTheManifest(t *testing.T) {
	want := map[string]bool{}
	for _, v := range boundVectors {
		want[v.id] = true
	}
	n := 0
	for _, r := range manifestResponses(t) {
		if r.Type != "openpgp-subkey" {
			continue
		}
		n++
		if !want[r.ID] {
			t.Errorf("the manifest has the OpenPGP answer %s, which this test does not know", r.ID)
		}
		delete(want, r.ID)
	}
	if n == 0 {
		t.Fatal("the manifest has no OpenPGP answer")
	}
	for id := range want {
		t.Errorf("the test lists %s, which the manifest does not have", id)
	}
}

func TestTheBoundVectorsHaveTheIssuersOfTheirPrimaries(t *testing.T) {
	for label, want := range issuerFingerprints {
		if got := primaryOf(t, label).Fingerprint(); got != want {
			t.Errorf("the primary %s has the fingerprint %s, want %s", label, got, want)
		}
	}
}

func TestEveryBoundVectorIsSplitAndReadByTheReaders(t *testing.T) {
	for _, v := range boundVectors {
		t.Run(v.id, func(t *testing.T) {
			file := boundFile(t, v.id)
			subPkt, bindingPkt, err := openpgp.SplitBoundFile(file)
			if err != nil {
				t.Fatalf("SplitBoundFile: %v", err)
			}
			ps := splitPackets(t, file)
			if !bytes.Equal(subPkt, ps[0].Raw) || !bytes.Equal(bindingPkt, ps[1].Raw) {
				t.Error("the two packets are not the two packets of the file, as they are")
			}
			issuer, err := openpgp.BindingIssuer(bindingPkt)
			if err != nil || issuer != issuerFingerprints[v.issuer] {
				t.Errorf("BindingIssuer = %q, %v; want %s", issuer, err, issuerFingerprints[v.issuer])
			}
			sk, err := openpgp.ReadSubkey(subPkt)
			if err != nil {
				t.Fatalf("ReadSubkey: %v", err)
			}
			primary := primaryOf(t, v.issuer)
			b, err := openpgp.VerifyBinding(bindingPkt, primary, sk)
			if v.shape {
				assertFaultResult(t, v.id+" with its primary", b, err, openpgp.ErrBindingShape)
			} else {
				if err != nil || b == nil {
					t.Fatalf("VerifyBinding with the primary %s = %v, %v", v.issuer, b, err)
				}
				if got := b.Capability(); got != v.capability {
					t.Errorf("Capability = %q, want %q", got, v.capability)
				}
				if got := b.Ends(); got.Format(time.RFC3339) != v.ends {
					t.Errorf("Ends = %s, want %s", got.Format(time.RFC3339), v.ends)
				}
				if got := endOfSubkey(t, subPkt, bindingPkt); !b.Ends().Equal(got) {
					t.Errorf("Ends = %v, but the key packet and the key expiration time say %v", b.Ends(), got)
				}
				if !b.Created().Equal(ceremony) {
					t.Errorf("Created = %v, want the ceremony time %v", b.Created(), ceremony)
				}
				if got := b.IssuerFingerprint(); got != issuerFingerprints[v.issuer] {
					t.Errorf("IssuerFingerprint = %s, want %s", got, issuerFingerprints[v.issuer])
				}
			}
			// Another primary: the issuer is not the primary's, whatever the subpackets are.
			for label := range issuerFingerprints {
				if label == v.issuer {
					continue
				}
				b, err := openpgp.VerifyBinding(bindingPkt, primaryOf(t, label), sk)
				assertFaultResult(t, v.id+" with the primary "+label, b, err, openpgp.ErrBinding)
			}
			// A primary with the same key and another creation time has another fingerprint.
			pub, _ := vectorPrimary(t, v.issuer)
			late, err := openpgp.NewPrimaryKey(pub, created.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			b, err = openpgp.VerifyBinding(bindingPkt, late, sk)
			assertFaultResult(t, v.id+" with the same key a second later", b, err, openpgp.ErrBinding)
		})
	}
}

func TestTheBindingOfAWrongSubkeyIsNotTheBindingOfTheRequestsSubkey(t *testing.T) {
	_, bindingPkt, err := openpgp.SplitBoundFile(boundFile(t, "pgp-response-wrong-subkey"))
	if err != nil {
		t.Fatal(err)
	}
	reqSub, _, err := openpgp.SplitSubkeyFile(subkeyFile(t, "pgp-response-request"), 2)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := openpgp.ReadSubkey(reqSub)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openpgp.VerifyBinding(bindingPkt, primaryOf(t, "a"), sk)
	assertFaultResult(t, "the binding of another subkey", b, err, openpgp.ErrBinding)
	// The right binding of the same request verifies, as the control.
	_, other, err := openpgp.SplitBoundFile(boundFile(t, "pgp-response-other-primary"))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := openpgp.VerifyBinding(other, primaryOf(t, "b"), sk); err != nil || b == nil {
		t.Errorf("the answer of the request itself does not verify: %v", err)
	}
}

func TestEmbedsIsTheRequestsOwnBackSignatureForThePrimaryThatBound(t *testing.T) {
	for _, v := range boundVectors {
		if v.shape || v.id == "pgp-response-wrong-subkey" || v.id == "pgp-response-wrong-primary" {
			continue
		}
		t.Run(v.id, func(t *testing.T) {
			var request string
			for _, r := range manifestResponses(t) {
				if r.ID == v.id {
					request = r.Request
				}
			}
			_, sigs, err := openpgp.SplitSubkeyFile(subkeyFile(t, request), 2)
			if err != nil || len(sigs) != 2 {
				t.Fatalf("the request %s: %d signatures, %v; want two", request, len(sigs), err)
			}
			subPkt, bindingPkt, err := openpgp.SplitBoundFile(boundFile(t, v.id))
			if err != nil {
				t.Fatal(err)
			}
			sk, err := openpgp.ReadSubkey(subPkt)
			if err != nil {
				t.Fatal(err)
			}
			b, err := openpgp.VerifyBinding(bindingPkt, primaryOf(t, v.issuer), sk)
			if err != nil {
				t.Fatal(err)
			}
			own, other := sigs[0], sigs[1]
			if v.issuer == "b" {
				own, other = sigs[1], sigs[0]
			}
			if !b.Embeds(own) {
				t.Error("the embedded signature is not the request's back-signature for the primary that bound")
			}
			if b.Embeds(other) {
				t.Error("the embedded signature is the back-signature for the other primary")
			}
		})
	}
}

func TestEmbedsComparesTheBodyOfOneWholeSignaturePacket(t *testing.T) {
	k := newBindKit(t)
	b := k.assertAccepted(t, "the binding of the page", k.build(t, nil))
	if b == nil {
		return
	}
	back := k.sub.BackSig
	oldForm := oldHeader(tagSignature, k.sub.BackBody)
	if !b.Embeds(back) {
		t.Error("the back-signature, as the request has it, is not embedded")
	}
	if !b.Embeds(oldForm) {
		t.Error("the same body with an old-format header is not the same signature")
	}
	if !b.Embeds(wrapLong(tagSignature, k.sub.BackBody)) {
		t.Error("the same body with a five-byte length is not the same signature")
	}
	flipped := bytes.Clone(back)
	flipped[len(flipped)-1] ^= 1
	longer := append(bytes.Clone(back), 0)
	for name, in := range map[string][]byte{
		"nil":                   nil,
		"empty":                 {},
		"one byte":              {back[0]},
		"the header only":       back[:2],
		"the body, no header":   k.sub.BackBody,
		"a cut packet":          back[:len(back)-1],
		"a flipped bit":         flipped,
		"a byte after":          longer,
		"two copies":            append(bytes.Clone(back), back...),
		"another tag":           wrap(tagSubkey, k.sub.BackBody),
		"the subkey packet":     k.sub.Packet,
		"a partial length":      append([]byte{0xE0}, back[1:]...),
		"an empty signature":    wrap(tagSignature, nil),
		"another back-sig":      newBindKit(t).sub.BackSig,
		"the binding itself":    k.build(t, nil),
		"an indeterminate form": append([]byte{0x80 | tagSignature<<2 | 3}, k.sub.BackBody...),
	} {
		if b.Embeds(in) {
			t.Errorf("Embeds is true for %s", name)
		}
	}
}

// Every binding that BindSubkey writes is a binding that the requester accepts, with the values
// that were asked for. This is the one reader of the page for the writer and the reader.
func TestEveryBindingThatBindSubkeyWritesIsAccepted(t *testing.T) {
	for _, capability := range []string{"sign", "authenticate"} {
		for _, sc := range []struct {
			name      string
			subAt     time.Time
			expires   func(subAt time.Time) time.Time
			longForms bool
		}{
			{"13 months", ceremony.Add(-2 * time.Hour), func(time.Time) time.Time { return ceremony.AddDate(1, 1, 0) }, false},
			{"one second after the ceremony", ceremony.Add(-2 * time.Hour), func(time.Time) time.Time { return ceremony.Add(time.Second) }, false},
			{"a subkey made at the ceremony", ceremony, func(time.Time) time.Time { return ceremony.AddDate(0, 2, 0) }, false},
			{"the last second that a time field holds", ceremony.Add(-time.Hour), func(time.Time) time.Time { return time.Unix(4294967295, 0).UTC() }, false},
			{"a subkey packet with a five-byte length", ceremony.Add(-2 * time.Hour), func(time.Time) time.Time { return ceremony.AddDate(1, 1, 0) }, true},
		} {
			t.Run(capability+", "+sc.name, func(t *testing.T) {
				s := newSigner(t)
				m := newSubkey(t, &s.key.PublicKey, created, sc.subAt)
				pkt := m.Packet
				if sc.longForms {
					pkt = wrapLong(tagSubkey, m.body())
				}
				p := openpgp.BindParams{Primary: s.params(), Subkey: pkt, BackSig: m.BackSig, Capability: capability, ExpiresAt: sc.expires(sc.subAt)}
				out, err := openpgp.BindSubkey(rand.Reader, p)
				if err != nil {
					t.Fatalf("BindSubkey: %v", err)
				}
				assertBindingMatches(t, out, p)
			})
		}
	}
}

// assertBindingMatches reads what BindSubkey wrote with the reader of the answer and checks that it
// holds what was asked for. It also asks go-crypto and the tests' own verifier. The tests of the
// builder call it through bind.
func assertBindingMatches(t testing.TB, out []byte, p openpgp.BindParams) {
	t.Helper()
	subPkt, bindingPkt, err := openpgp.SplitBoundFile(out)
	if err != nil {
		t.Errorf("SplitBoundFile of what BindSubkey wrote: %v", err)
		return
	}
	if !bytes.Equal(subPkt, p.Subkey) {
		t.Error("the first packet of the answer is not the subkey packet of the request, byte for byte")
	}
	pub, ok := p.Primary.Key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Error("the signer has no ECDSA key")
		return
	}
	primary, err := openpgp.NewPrimaryKey(pub, p.Primary.CreationTime)
	if err != nil {
		t.Errorf("NewPrimaryKey: %v", err)
		return
	}
	sk, err := openpgp.ReadSubkey(subPkt)
	if err != nil {
		t.Errorf("ReadSubkey: %v", err)
		return
	}
	if got, err := openpgp.BindingIssuer(bindingPkt); err != nil || got != primary.Fingerprint() {
		t.Errorf("BindingIssuer = %q, %v; want the fingerprint of the primary %s", got, err, primary.Fingerprint())
	}
	b, err := openpgp.VerifyBinding(bindingPkt, primary, sk)
	if err != nil || b == nil {
		t.Errorf("VerifyBinding refuses what BindSubkey wrote: %v", err)
		return
	}
	if b.Capability() != p.Capability {
		t.Errorf("Capability = %q, want %q", b.Capability(), p.Capability)
	}
	if !b.Ends().Equal(p.ExpiresAt) {
		t.Errorf("Ends = %v, want %v", b.Ends(), p.ExpiresAt)
	}
	if !b.Created().Equal(p.Primary.CeremonyTime) {
		t.Errorf("Created = %v, want the ceremony time %v", b.Created(), p.Primary.CeremonyTime)
	}
	if b.IssuerFingerprint() != primary.Fingerprint() {
		t.Errorf("IssuerFingerprint = %s, want %s", b.IssuerFingerprint(), primary.Fingerprint())
	}
	if !b.Embeds(p.BackSig) {
		t.Error("the embedded signature is not the back-signature of the request")
	}
	body := bodyOf(t, bindingPkt)
	if !softSignatureValid(body, pub, sk.PublicKey(), p.Primary.CreationTime.Unix(), sk.Created().Unix()) {
		t.Error("the tests' own verifier does not accept the binding that the reader accepted")
	}
	if !goCryptoAccepts(t, pub, sk.PublicKey(), p.Primary.CreationTime.Unix(), sk.Created().Unix(), bindingPkt) {
		t.Error("go-crypto does not accept the binding that the reader accepted")
	}
}

func TestTheSubpacketsMayComeInAnyOrderAndInAnyLengthFormOfTheStandard(t *testing.T) {
	k := newBindKit(t)
	reverse := func(sp *sigSpec) {
		for i, j := 0, len(sp.Hashed)-1; i < j; i, j = i+1, j-1 {
			sp.Hashed[i], sp.Hashed[j] = sp.Hashed[j], sp.Hashed[i]
		}
		sp.Unhashed[0], sp.Unhashed[1] = sp.Unhashed[1], sp.Unhashed[0]
	}
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"the order of the page", nil},
		{"the reverse order", reverse},
		{"the unhashed area first-to-last swapped only", func(sp *sigSpec) { sp.Unhashed[0], sp.Unhashed[1] = sp.Unhashed[1], sp.Unhashed[0] }},
		{"five-byte lengths in both areas", func(sp *sigSpec) { sp.LongLengths = true }},
		{"an old-format packet header", func(sp *sigSpec) { sp.OldHeader = true }},
		{"the shortest expiry", func(sp *sigSpec) { sp.Hashed[2].Data = u32(1) }},
		{"the longest expiry that ends within a time field", func(sp *sigSpec) { sp.Hashed[2].Data = u32(uint32(lastSecond - subAt.Unix())) }},
		{"the authentication flag", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x20} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := k.assertAccepted(t, c.name, k.build(t, c.tweak))
			if b == nil {
				return
			}
			if !b.Embeds(k.sub.BackSig) {
				t.Error("the embedded signature is not found")
			}
			if b.IssuerFingerprint() != k.primary.Fingerprint() {
				t.Errorf("IssuerFingerprint = %s", b.IssuerFingerprint())
			}
		})
	}
}

func TestTheEndOfTheSubkeyIsItsCreationTimePlusTheKeyExpirationTimeInUTC(t *testing.T) {
	k := newBindKit(t)
	for _, secs := range []uint32{1, 59, 3600, 86400 * 400, 0x7FFFFFFF, uint32(lastSecond - subAt.Unix())} {
		b := k.assertAccepted(t, "an expiry", k.build(t, func(sp *sigSpec) { sp.Hashed[2].Data = u32(secs) }))
		if b == nil {
			continue
		}
		want := subAt.Add(time.Duration(secs) * time.Second)
		if !b.Ends().Equal(want) {
			t.Errorf("an expiry of %d seconds: Ends = %v, want %v", secs, b.Ends(), want)
		}
		if b.Ends().Location() != time.UTC || b.Created().Location() != time.UTC {
			t.Errorf("Ends is in %v and Created in %v, want UTC", b.Ends().Location(), b.Created().Location())
		}
	}
	// The expiry counts from the subkey's creation, not from the binding's.
	b := k.assertAccepted(t, "the page's binding", k.build(t, nil))
	if b != nil && !b.Ends().Equal(subAt.Add(time.Duration(k.life)*time.Second)) {
		t.Errorf("Ends = %v, not the creation time of the subkey plus %d seconds", b.Ends(), k.life)
	}
}

func TestTheBindingIsOfTheSubkeyAndThePrimaryItWasMadeOver(t *testing.T) {
	k := newBindKit(t)
	pkt := k.build(t, nil)
	k.assertAccepted(t, "the right pair", pkt)
	other := newBindKit(t)
	for _, c := range []struct {
		name string
		pri  *openpgp.PrimaryKey
		sub  *openpgp.Subkey
	}{
		{"another subkey", k.primary, other.subKey},
		{"another primary", other.primary, k.subKey},
		{"a primary with the same key made at another time", func() *openpgp.PrimaryKey {
			p, err := openpgp.NewPrimaryKey(&k.key.PublicKey, created.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			return p
		}(), k.subKey},
	} {
		b, err := openpgp.VerifyBinding(pkt, c.pri, c.sub)
		assertFaultResult(t, c.name, b, err, openpgp.ErrBinding)
	}
	// The same key packet with another creation time is another subkey: the signature covers the time.
	later := subkeyMaterial{Key: k.sub.Key, Created: subAt.Add(time.Second)}
	later.Packet = wrap(tagSubkey, later.body())
	sk, err := openpgp.ReadSubkey(later.Packet)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openpgp.VerifyBinding(pkt, k.primary, sk)
	assertFaultResult(t, "the subkey with the key of the binding and a later creation time", b, err, openpgp.ErrBinding)
	// The data of the signature is the primary and then the subkey: the other order is no binding.
	swapped := k.build(t, func(sp *sigSpec) { sp.Data[0], sp.Data[1] = sp.Data[1], sp.Data[0] })
	k.assertFault(t, "the subkey and then the primary", swapped, openpgp.ErrBinding)
	// A signature by another key, with every subpacket right.
	k.assertFault(t, "a signature by another key", k.build(t, func(sp *sigSpec) { sp.Key = genKey(t) }), openpgp.ErrBinding)
	// A signature over the primary and a subkey of another key.
	k.assertFault(t, "a signature over another subkey", k.build(t, func(sp *sigSpec) {
		sp.Data[1] = hashPrefix(&other.sub.Key.PublicKey, subAt)
	}), openpgp.ErrBinding)
	// A signature made with another type of data in front: a certification of a user ID.
	k.assertFault(t, "a signature over the primary alone", k.build(t, func(sp *sigSpec) { sp.Data = sp.Data[:1] }), openpgp.ErrBinding)
}

func TestVerifyBindingChangesNoByteOfItsInputAndKeepsNoSliceOfIt(t *testing.T) {
	k := newBindKit(t)
	pkt := k.build(t, nil)
	before := bytes.Clone(pkt)
	b := k.assertAccepted(t, "the page's binding", pkt)
	if !bytes.Equal(pkt, before) {
		t.Error("VerifyBinding changed the bytes of its input")
	}
	if b == nil {
		return
	}
	// What the Binding holds is its own: clearing the input changes nothing in it.
	clear(pkt)
	if !b.Embeds(k.sub.BackSig) {
		t.Error("the Binding holds the embedded signature of the input, not a copy")
	}
	if b.Capability() != "sign" || b.IssuerFingerprint() != k.primary.Fingerprint() {
		t.Errorf("the Binding changed with its input: %q, %s", b.Capability(), b.IssuerFingerprint())
	}
}

func TestANilOrZeroKeyIsAParameterFaultAndNotAnAnswerFault(t *testing.T) {
	k := newBindKit(t)
	pkt := k.build(t, nil)
	for _, c := range []struct {
		name string
		pkt  []byte
		pri  *openpgp.PrimaryKey
		sub  *openpgp.Subkey
	}{
		{"a nil primary", pkt, nil, k.subKey},
		{"a zero primary", pkt, &openpgp.PrimaryKey{}, k.subKey},
		{"a nil subkey", pkt, k.primary, nil},
		{"a zero subkey", pkt, k.primary, &openpgp.Subkey{}},
		{"nothing", nil, nil, nil},
		{"no binding and no key", []byte{}, &openpgp.PrimaryKey{}, &openpgp.Subkey{}},
		{"a garbage binding and a nil primary", []byte{1, 2, 3}, nil, k.subKey},
	} {
		b, err := openpgp.VerifyBinding(c.pkt, c.pri, c.sub)
		if b != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("%s: VerifyBinding = %v, %v; want ErrParams and no binding", c.name, b, err)
		}
		if errors.Is(err, openpgp.ErrAnswer) {
			t.Errorf("%s: the fault of a parameter is an ErrAnswer", c.name)
		}
	}
	// Keys that are right and no binding, or none that is whole: a fault of the answer.
	for name, in := range map[string][]byte{"nil": nil, "empty": {}, "one byte": {0xC2}, "zeros": make([]byte, 400)} {
		k.assertFault(t, name, in, openpgp.ErrBinding)
	}
}

func TestANilOrZeroBindingHoldsNothing(t *testing.T) {
	for name, b := range map[string]*openpgp.Binding{"nil": nil, "zero": {}} {
		if b.Created() != (time.Time{}) || !b.Created().IsZero() {
			t.Errorf("%s: Created = %v", name, b.Created())
		}
		if b.Ends() != (time.Time{}) || !b.Ends().IsZero() {
			t.Errorf("%s: Ends = %v", name, b.Ends())
		}
		if got := b.IssuerFingerprint(); got != "" {
			t.Errorf("%s: IssuerFingerprint = %q", name, got)
		}
		if got := b.Capability(); got != "" {
			t.Errorf("%s: Capability = %q", name, got)
		}
		k := newBindKit(t)
		for _, in := range [][]byte{nil, {}, k.sub.BackSig, k.sub.BackBody, wrap(tagSignature, nil)} {
			if b.Embeds(in) {
				t.Errorf("%s: Embeds(%d bytes) is true", name, len(in))
			}
		}
	}
}

func TestTheKindsOfTheFaultsOfAnAnswer(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		is   []error
		not  []error
	}{
		{"ErrAnswer", openpgp.ErrAnswer, []error{openpgp.ErrAnswer}, []error{openpgp.ErrBoundFile, openpgp.ErrBinding, openpgp.ErrBindingShape, openpgp.ErrRequest, openpgp.ErrParams}},
		{"ErrBoundFile", openpgp.ErrBoundFile, []error{openpgp.ErrBoundFile, openpgp.ErrAnswer}, []error{openpgp.ErrBinding, openpgp.ErrBindingShape, openpgp.ErrRequest, openpgp.ErrForm}},
		{"ErrBinding", openpgp.ErrBinding, []error{openpgp.ErrBinding, openpgp.ErrAnswer}, []error{openpgp.ErrBoundFile, openpgp.ErrBindingShape, openpgp.ErrRequest, openpgp.ErrBackSignature}},
		{"ErrBindingShape", openpgp.ErrBindingShape, []error{openpgp.ErrBindingShape, openpgp.ErrAnswer}, []error{openpgp.ErrBoundFile, openpgp.ErrBinding, openpgp.ErrRequest, openpgp.ErrBackSignature}},
	} {
		for _, want := range c.is {
			if !errors.Is(c.err, want) {
				t.Errorf("%s is not %v", c.name, want)
			}
		}
		for _, no := range c.not {
			if errors.Is(c.err, no) {
				t.Errorf("%s is %v", c.name, no)
			}
		}
		if c.err.Error() == "" {
			t.Errorf("%s has no text", c.name)
		}
	}
	// The kinds of the request are not kinds of an answer.
	for _, e := range []error{openpgp.ErrRequest, openpgp.ErrForm, openpgp.ErrAlgorithm, openpgp.ErrBackSignature, openpgp.ErrSignature, openpgp.ErrParams} {
		if errors.Is(e, openpgp.ErrAnswer) {
			t.Errorf("%v is an ErrAnswer", e)
		}
	}
}

func TestBindingIssuerReadsTheIssuerOfOneSignaturePacketAndVerifiesNothing(t *testing.T) {
	k := newBindKit(t)
	good := k.build(t, nil)
	want := k.primary.Fingerprint()
	if got, err := openpgp.BindingIssuer(good); err != nil || got != want || !fingerprintPattern.MatchString(got) {
		t.Fatalf("BindingIssuer = %q, %v; want %s in lower case", got, err, want)
	}
	// It verifies nothing: a signature that does not verify, or one of another type, still names its issuer.
	broken := bytes.Clone(good)
	broken[len(broken)-1] ^= 1
	for name, in := range map[string][]byte{
		"a damaged signature":        broken,
		"a signature of type 0x19":   k.build(t, func(sp *sigSpec) { sp.Type = 0x19 }),
		"a signature by another key": k.build(t, func(sp *sigSpec) { sp.Key = genKey(t) }),
		"a shape fault":              k.build(t, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1}}) }),
		"an old-format header":       k.build(t, func(sp *sigSpec) { sp.OldHeader = true }),
		"five-byte lengths":          k.build(t, func(sp *sigSpec) { sp.LongLengths = true }),
	} {
		if got, err := openpgp.BindingIssuer(in); err != nil || got != want {
			t.Errorf("%s: BindingIssuer = %q, %v; want %s", name, got, err, want)
		}
	}
	fp := append([]byte{4}, k.fp...)
	for name, in := range map[string][]byte{
		"nothing":              nil,
		"empty":                {},
		"the whole bound file": append(bytes.Clone(k.sub.Packet), good...),
		"a subkey packet":      k.sub.Packet,
		"a packet of tag 14 with the body of the binding": wrap(tagSubkey, bodyOf(t, good)),
		"the body without a header":                       bodyOf(t, good),
		"a byte after the packet":                         append(bytes.Clone(good), 0),
		"a cut packet":                                    good[:len(good)-1],
		"no issuer fingerprint":                           k.build(t, func(sp *sigSpec) { sp.Hashed = sp.Hashed[:3] }),
		"two issuer fingerprints":                         k.build(t, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[3]) }),
		"two different issuers": k.build(t, func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 33, Data: append([]byte{4}, newBindKit(t).fp...)})
		}),
		"the issuer in the unhashed area only": k.build(t, func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[3])
			sp.Hashed = sp.Hashed[:3]
		}),
		"an issuer of version 5":      k.build(t, func(sp *sigSpec) { sp.Hashed[3].Data = append([]byte{5}, make([]byte, 32)...) }),
		"an issuer of version 6":      k.build(t, func(sp *sigSpec) { sp.Hashed[3].Data = append([]byte{6}, make([]byte, 32)...) }),
		"an issuer of version 3":      k.build(t, func(sp *sigSpec) { sp.Hashed[3].Data[0] = 3 }),
		"an issuer of version 0":      k.build(t, func(sp *sigSpec) { sp.Hashed[3].Data[0] = 0 }),
		"an issuer of 20 bytes":       k.build(t, func(sp *sigSpec) { sp.Hashed[3].Data = fp[:20] }),
		"an issuer of 22 bytes":       k.build(t, func(sp *sigSpec) { sp.Hashed[3].Data = append(bytes.Clone(fp), 0) }),
		"an empty issuer":             k.build(t, func(sp *sigSpec) { sp.Hashed[3].Data = nil }),
		"a version 3 signature":       func() []byte { b := bodyOf(t, good); b[0] = 3; return withBody(b) }(),
		"a version 5 signature":       func() []byte { b := bodyOf(t, good); b[0] = 5; return withBody(b) }(),
		"a version 0 signature":       func() []byte { b := bodyOf(t, good); b[0] = 0; return withBody(b) }(),
		"a hashed area that runs out": func() []byte { b := bodyOf(t, good); b[4], b[5] = 0xFF, 0xFF; return withBody(b) }(),
		"an unhashed area that runs out": func() []byte {
			b := bodyOf(t, good)
			l := layoutOf(b)
			binary.BigEndian.PutUint16(b[l.hashedAt+l.hashedLen:], 0xFFFF)
			return withBody(b)
		}(),
		"33 subpackets in the hashed area": k.build(t, func(sp *sigSpec) {
			for len(sp.Hashed) < 33 {
				sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1}})
			}
		}),
		"33 subpackets in the unhashed area": k.build(t, func(sp *sigSpec) {
			for len(sp.Unhashed) < 33 {
				sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: []byte{1}})
			}
		}),
		"a partial length": append([]byte{0xC2, 0xE0}, good[2:]...),
		"a partial length followed by a five-byte length": append(append([]byte{0xC2, 0xE0}, u32(uint32(len(bodyOf(t, good))))...), bodyOf(t, good)...),
		"an indeterminate length":                         append([]byte{0x80 | tagSignature<<2 | 3}, bodyOf(t, good)...),
	} {
		got, err := openpgp.BindingIssuer(in)
		if got != "" || !errors.Is(err, openpgp.ErrBinding) || !errors.Is(err, openpgp.ErrAnswer) {
			t.Errorf("%s: BindingIssuer = %q, %v; want ErrBinding and no text", name, got, err)
		} else {
			checkErrorText(t, name, err)
		}
	}
}

func TestBindingIssuerIsTheLowerCaseFingerprintOfTheVectors(t *testing.T) {
	for _, v := range boundVectors {
		_, bindingPkt, err := openpgp.SplitBoundFile(boundFile(t, v.id))
		if err != nil {
			t.Fatal(err)
		}
		got, err := openpgp.BindingIssuer(bindingPkt)
		if err != nil || !fingerprintPattern.MatchString(got) {
			t.Errorf("%s: BindingIssuer = %q, %v; want 40 lower-case digits", v.id, got, err)
		}
	}
}

// A binding is read by many goroutines at once, with the same keys: the keys are not changed by a
// reading. The goroutines start behind one closed channel.
func TestManyReadersOfOneBindingAtOnceAgree(t *testing.T) {
	k := newBindKit(t)
	good := k.build(t, nil)
	shape := k.build(t, func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x03} })
	broken := bytes.Clone(good)
	broken[len(broken)-1] ^= 1
	const readers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]string, readers)
	for i := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var out string
			for _, in := range [][]byte{good, shape, broken} {
				b, err := k.verify(in)
				switch {
				case err == nil && b != nil && b.Capability() == "sign" && b.Embeds(k.sub.BackSig):
					out += "A"
				case errors.Is(err, openpgp.ErrBindingShape) && b == nil:
					out += "S"
				case errors.Is(err, openpgp.ErrBinding) && b == nil:
					out += "B"
				default:
					out += "?"
				}
			}
			results[i] = out
		}()
	}
	close(start)
	wg.Wait()
	for i, r := range results {
		if r != "ASB" {
			t.Errorf("reader %d saw %q, want ASB", i, r)
		}
	}
}
