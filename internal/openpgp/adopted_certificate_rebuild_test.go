package openpgp_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The certificate of every key of the kit that the reader accepts is built from what the file signed and from
// nothing else, and is the certificate that a writer of the tests makes from the same packets. No byte is
// stored: the writer here is written from the standard (RFC 9580, section 5.2.3.7 for the subpackets) and reads
// only the certificate and the file.

// qaSigParts slices a signature body without judging it: the fields up to the end of the hashed area, the hashed
// area, the unhashed area, and what follows it (the hash tag and the numbers).
func qaSigParts(body []byte) (fields, hashed, unhashed, rest []byte, ok bool) {
	if len(body) < 8 || body[0] != 4 {
		return nil, nil, nil, nil, false
	}
	hl := int(binary.BigEndian.Uint16(body[4:]))
	if len(body) < 8+hl {
		return nil, nil, nil, nil, false
	}
	ul := int(binary.BigEndian.Uint16(body[6+hl:]))
	if len(body) < 8+hl+ul {
		return nil, nil, nil, nil, false
	}
	return body[:6+hl], body[6 : 6+hl], body[8+hl : 8+hl+ul], body[8+hl+ul:], true
}

// qaSubpacket writes a subpacket with the length in the form of the standard: one octet below 192, two below
// 8384, else five.
func qaSubpacket(typ byte, data []byte) []byte {
	n := len(data) + 1
	var out []byte
	switch {
	case n < 192:
		out = []byte{byte(n)}
	case n < 8384:
		out = []byte{byte((n-192)>>8) + 192, byte(n - 192)}
	default:
		out = binary.BigEndian.AppendUint32([]byte{255}, uint32(n))
	}
	return append(append(out, typ), data...)
}

func TestQACertificateIsBuiltFromWhatTheFileSignedByAnotherWriter(t *testing.T) {
	checked, sigs := 0, 0
	for _, f := range qaExports(t) {
		k, err := openpgp.ReadForeignKey(f.file)
		if err != nil {
			continue
		}
		checked++
		cert := k.Certificate()
		cps := fkSplit(t, cert)
		fp := openpgpFP(k)
		// the packets of the file
		file := fkDecoded(f.file)
		fps := fkSplit(t, file)
		type key struct{ fields, rest string }
		fileSigs := map[key]bool{}
		for _, p := range fps {
			if p.Tag != 2 {
				continue
			}
			if fl, _, _, rest, ok := qaSigParts(p.Body); ok {
				fileSigs[key{string(fl), string(rest)}] = true
			}
		}
		var rebuilt []byte
		for i, p := range cps {
			switch p.Tag {
			case 6:
				if i != 0 || !bytes.HasPrefix(fps[0].Body, p.Body) {
					t.Errorf("%s: the primary of the certificate is not the public part of the primary of the file", f.name)
				}
				rebuilt = append(rebuilt, wrap(6, p.Body)...)
			case 13, 17:
				found := false
				for _, q := range fps {
					found = found || (q.Tag == p.Tag && bytes.Equal(q.Body, p.Body))
				}
				if !found {
					t.Errorf("%s: a user ID or attribute of the certificate is not in the file", f.name)
				}
				rebuilt = append(rebuilt, wrap(p.Tag, p.Body)...)
			case 14:
				found := false
				for _, q := range fps {
					found = found || ((q.Tag == 14 || q.Tag == 7) && bytes.HasPrefix(q.Body, p.Body))
				}
				if !found {
					t.Errorf("%s: a subkey of the certificate is not the public part of one of the file", f.name)
				}
				rebuilt = append(rebuilt, wrap(14, p.Body)...)
			case 2:
				sigs++
				fl, hashed, un, rest, ok := qaSigParts(p.Body)
				if !ok {
					t.Fatalf("%s: a signature of the certificate does not slice", f.name)
				}
				if !fileSigs[key{string(fl), string(rest)}] {
					t.Errorf("%s: signature %d of the certificate has fields and numbers that no signature of the file has", f.name, i)
				}
				// the unhashed area that the standard and the reader's rule give: the issuer key ID, the issuer
				// fingerprint when the hashed area has none, and the embedded back-signature when there was one
				subs := qaSubs(t, hashed)
				hasFP := false
				for _, s := range subs {
					hasFP = hasFP || s.Typ == 33
				}
				var embedded []byte
				for _, s := range qaSubs(t, un) {
					if s.Typ == 32 {
						embedded = s.Data
					}
				}
				want := qaSubpacket(16, fp[12:])
				if !hasFP {
					want = append(want, qaSubpacket(33, append([]byte{4}, fp...))...)
				}
				if embedded != nil {
					want = append(want, qaSubpacket(32, embedded)...)
				}
				body := append(bytes.Clone(fl), byte(len(want)>>8), byte(len(want)))
				body = append(append(body, want...), rest...)
				rebuilt = append(rebuilt, wrap(2, body)...)
			default:
				t.Errorf("%s: a packet of tag %d in the certificate", f.name, p.Tag)
			}
		}
		if !bytes.Equal(rebuilt, cert) {
			t.Errorf("%s: the certificate is not the one that another writer makes from its parts (%d and %d bytes)", f.name, len(cert), len(rebuilt))
		}
		// and the certificate is a fixpoint of the reader
		if kc, err := qaReadCert(cert); err != nil || !bytes.Equal(kc.Certificate(), cert) {
			t.Errorf("%s: %v", f.name, err)
		}
	}
	t.Logf("%d keys, %d signatures rebuilt", checked, sigs)
	if checked < 150 || sigs < 400 {
		t.Errorf("only %d keys and %d signatures", checked, sigs)
	}
}

// openpgpFP is the fingerprint of the primary of a key, from its view, as bytes.
func openpgpFP(k *openpgp.ForeignKey) []byte {
	out := make([]byte, 0, 20)
	s := k.Primary.Fingerprint
	for i := 0; i+1 < len(s); i += 2 {
		out = append(out, hexVal(s[i])<<4|hexVal(s[i+1]))
	}
	return out
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 0
}
