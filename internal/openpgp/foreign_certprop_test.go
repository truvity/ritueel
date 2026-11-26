package openpgp_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The property that Certificate() has, whatever the file was. It is written with a packet walker of
// these tests and the verification of go-crypto, and it is held for every file that the reader accepts:
// the packets are of five kinds, in the order of a certificate, written in the shortest new-format
// header, every signature verifies with the primary over the component it follows, the unhashed area of
// every signature holds only what the reader builds, nothing follows the last packet, and no run of any
// secret that the file held is in it.

// fkCP is one packet of a certificate as the walker of the tests reads it.
type fkCP struct {
	tag  byte
	body []byte
}

// fkWalkCertificate reads a certificate: whole packets in the new format with the shortest length, to
// the end of the bytes.
func fkWalkCertificate(cert []byte) ([]fkCP, error) {
	var out []fkCP
	for len(cert) > 0 {
		if len(cert) < 2 || cert[0]&0xC0 != 0xC0 {
			return nil, fmt.Errorf("a packet that is not new-format at byte %d", len(cert))
		}
		tag := cert[0] & 0x3F
		var n, hl int
		switch l := int(cert[1]); {
		case l < 192:
			n, hl = l, 2
		case l < 224:
			if len(cert) < 3 {
				return nil, fmt.Errorf("cut in a length")
			}
			n, hl = (l-192)<<8+int(cert[2])+192, 3
		case l == 255:
			if len(cert) < 6 {
				return nil, fmt.Errorf("cut in a length")
			}
			n, hl = int(cert[2])<<24|int(cert[3])<<16|int(cert[4])<<8|int(cert[5]), 6
		default:
			return nil, fmt.Errorf("a partial length")
		}
		if hl+n > len(cert) {
			return nil, fmt.Errorf("a packet that runs past the end")
		}
		body := cert[hl : hl+n]
		if !bytes.Equal(cert[:hl+n], wrap(tag, body)) {
			return nil, fmt.Errorf("a packet of tag %d whose header is not the shortest", tag)
		}
		out = append(out, fkCP{tag, body})
		cert = cert[hl+n:]
	}
	return out, nil
}

// fkSubpacketsOf reads a subpacket area: type, critical bit and data.
type fkSP struct {
	typ  byte
	crit bool
	data []byte
}

func fkReadSubpackets(area []byte) ([]fkSP, bool) {
	var out []fkSP
	for len(area) > 0 {
		var n, hl int
		switch l := int(area[0]); {
		case l < 192:
			n, hl = l, 1
		case l < 255:
			if len(area) < 2 {
				return nil, false
			}
			n, hl = (l-192)<<8+int(area[1])+192, 2
		default:
			if len(area) < 5 {
				return nil, false
			}
			n, hl = int(area[1])<<24|int(area[2])<<16|int(area[3])<<8|int(area[4]), 5
		}
		if n < 1 || hl+n > len(area) {
			return nil, false
		}
		out = append(out, fkSP{area[hl] & 0x7F, area[hl]&0x80 != 0, area[hl+1 : hl+n]})
		area = area[hl+n:]
	}
	return out, true
}

// fkSigAreasOf splits a version 4 signature body: its type, its hashed area, its unhashed area.
func fkSigAreasOf(body []byte) (typ byte, hashed, unhashed []byte, ok bool) {
	if len(body) < 6 || body[0] != 4 {
		return 0, nil, nil, false
	}
	hl := int(body[4])<<8 | int(body[5])
	if len(body) < 6+hl+2 {
		return 0, nil, nil, false
	}
	ul := int(body[6+hl])<<8 | int(body[7+hl])
	if len(body) < 8+hl+ul+2 {
		return 0, nil, nil, false
	}
	return body[1], body[6 : 6+hl], body[8+hl : 8+hl+ul], true
}

// fkCheckUnhashed holds the unhashed area of a signature to the three things that the reader builds:
// the issuer key ID, the issuer fingerprint and, on a binding, one embedded signature whose own unhashed
// area holds issuers only.
func fkCheckUnhashed(body []byte, depth int) error {
	typ, _, un, ok := fkSigAreasOf(body)
	if !ok {
		return fmt.Errorf("a signature that does not read")
	}
	sps, ok := fkReadSubpackets(un)
	if !ok {
		return fmt.Errorf("an unhashed area that does not read")
	}
	embedded := 0
	for _, sp := range sps {
		switch sp.typ {
		case 16, 33:
		case 32:
			embedded++
			if depth > 0 || typ != 0x18 {
				return fmt.Errorf("an embedded signature where none belongs")
			}
			if err := fkCheckUnhashed(sp.data, depth+1); err != nil {
				return fmt.Errorf("the embedded signature: %w", err)
			}
		default:
			return fmt.Errorf("a subpacket of type %d in an unhashed area", sp.typ)
		}
	}
	if embedded > 1 {
		return fmt.Errorf("%d embedded signatures", embedded)
	}
	return nil
}

// fkVerifyAttribute verifies a signature over a user attribute packet with the primary.
func fkVerifyAttribute(pk *gpacket.PublicKey, body []byte, sig *gpacket.Signature) error {
	h, err := sig.PrepareVerify()
	if err != nil {
		return err
	}
	if err := pk.SerializeForHash(h); err != nil {
		return err
	}
	h.Write([]byte{0xD1, byte(len(body) >> 24), byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	return pk.VerifySignature(h, sig)
}

// fkCertProperty holds a key that the reader returned to the property of the certificate. secrets are the
// byte strings of the file that no run of eight may be found in. It returns the packets of the
// certificate.
func fkCertProperty(t testing.TB, what string, k *openpgp.ForeignKey, secrets ...[]byte) []fkCP {
	t.Helper()
	cert := k.Certificate()
	ps, err := fkWalkCertificate(cert)
	if err != nil {
		t.Fatalf("%s: the certificate does not walk: %v", what, err)
	}
	if len(ps) == 0 || ps[0].tag != 6 {
		t.Fatalf("%s: the certificate does not start with a public key", what)
	}
	primary, err := fkPublicOf(ps[0].tag, ps[0].body)
	if err != nil {
		t.Fatalf("%s: the primary: %v", what, err)
	}
	if hexOf(primary.Fingerprint) != k.Primary.Fingerprint {
		t.Fatalf("%s: the primary of the certificate is not the primary of the key", what)
	}
	// the order and the verification: component is what the signatures that follow are over
	const (
		atKey = iota
		atUser
		atAttr
		atSub
	)
	at := atKey
	var userText, attrBody []byte
	var sub *gpacket.PublicKey
	sawSub := false
	for i, p := range ps[1:] {
		switch p.tag {
		case 13, 17:
			if sawSub {
				t.Fatalf("%s: packet %d: a user ID or attribute after a subkey", what, i+1)
			}
			if p.tag == 13 {
				at, userText = atUser, p.body
			} else {
				at, attrBody = atAttr, p.body
			}
		case 14:
			sawSub = true
			at = atSub
			if sub, err = fkPublicOf(14, p.body); err != nil {
				t.Fatalf("%s: packet %d: a subkey that does not read: %v", what, i+1, err)
			}
		case 2:
			if err := fkCheckUnhashed(p.body, 0); err != nil {
				t.Fatalf("%s: packet %d: %v", what, i+1, err)
			}
			g, err := gpacket.Read(bytes.NewReader(wrap(2, p.body)))
			if err != nil {
				t.Fatalf("%s: packet %d: go-crypto does not read the signature: %v", what, i+1, err)
			}
			sig, ok := g.(*gpacket.Signature)
			if !ok {
				t.Fatalf("%s: packet %d: not a signature", what, i+1)
			}
			var verr error
			typ := byte(sig.SigType)
			switch {
			case at == atKey && typ == 0x1F:
				verr = primary.VerifyDirectKeySignature(sig)
			case at == atKey && typ == 0x20:
				verr = primary.VerifyRevocationSignature(sig)
			case at == atUser && ((typ >= 0x10 && typ <= 0x13) || typ == 0x30):
				verr = primary.VerifyUserIdSignature(string(userText), primary, sig)
			case at == atAttr && ((typ >= 0x10 && typ <= 0x13) || typ == 0x30):
				verr = fkVerifyAttribute(primary, attrBody, sig)
			case at == atSub && (typ == 0x18 || typ == 0x28):
				verr = primary.VerifySubkeyRevocationSignature(sig, sub)
				if verr == nil && sig.EmbeddedSignature != nil && typ == 0x18 {
					verr = primary.VerifyKeySignature(sub, sig)
				}
			default:
				verr = fmt.Errorf("a signature of type %#x does not belong here (component %d)", typ, at)
			}
			if verr != nil {
				t.Fatalf("%s: packet %d (type %#x): %v", what, i+1, typ, verr)
			}
		default:
			t.Fatalf("%s: packet %d has the tag %d, which a certificate does not hold", what, i+1, p.tag)
		}
	}
	if len(ps) > 1 && ps[len(ps)-1].tag != 2 && ps[len(ps)-1].tag != 14 && ps[len(ps)-1].tag != 13 && ps[len(ps)-1].tag != 17 {
		t.Fatalf("%s: the last packet", what)
	}
	// the library's key-ring reader reads the certificate, as the same key, with exactly the subkeys that the
	// view says are in it (the same subkey twice in the file is one in the certificate)
	ents, err := pgp.ReadKeyRing(bytes.NewReader(cert))
	if err != nil || len(ents) != 1 {
		t.Fatalf("%s: go-crypto does not read the certificate as a key ring: %v (%d keys)", what, err, len(ents))
	}
	if hexOf(ents[0].PrimaryKey.Fingerprint) != k.Primary.Fingerprint {
		t.Fatalf("%s: the key ring has another primary", what)
	}
	var wantSubs []string
	for _, s := range k.Subkeys {
		if s.InCertificate && !slices.Contains(wantSubs, s.Fingerprint) {
			wantSubs = append(wantSubs, s.Fingerprint)
		}
	}
	var gotSubs []string
	for _, s := range ents[0].Subkeys {
		gotSubs = append(gotSubs, hexOf(s.PublicKey.Fingerprint))
	}
	if !slices.Equal(gotSubs, wantSubs) {
		t.Fatalf("%s: the key ring has the subkeys %v, the view says %v are in the certificate", what, gotSubs, wantSubs)
	}
	// no run of a secret, no serial
	if where, bad := fkLeaks(cert, secrets...); bad {
		t.Fatalf("%s: the certificate holds a run of a secret (%s)", what, where)
	}
	for _, form := range fkHexForms(fkSerial) {
		if bytes.Contains(cert, form) {
			t.Fatalf("%s: the certificate holds the serial number of a stub", what)
		}
	}
	return ps
}

// fkPublicOf reads a public key packet of the given tag with go-crypto.
func fkPublicOf(tag byte, body []byte) (*gpacket.PublicKey, error) {
	p, err := gpacket.Read(bytes.NewReader(wrap(tag, body)))
	if err != nil {
		return nil, err
	}
	pk, ok := p.(*gpacket.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a public key")
	}
	return pk, nil
}

// fkCertSubkeys lists the fingerprints of the subkeys of a certificate, in order.
func fkCertSubkeys(ps []fkCP) []string {
	var out []string
	for _, p := range ps {
		if p.tag == 14 {
			if pk, err := fkPublicOf(14, p.body); err == nil {
				out = append(out, hexOf(pk.Fingerprint))
			}
		}
	}
	return out
}

// fkCertUsers lists the texts of the user IDs of a certificate, in order.
func fkCertUsers(ps []fkCP) []string {
	var out []string
	for _, p := range ps {
		if p.tag == 13 {
			out = append(out, string(p.body))
		}
	}
	return out
}
