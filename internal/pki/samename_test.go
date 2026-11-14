package pki_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// SameName is OpenSSL's comparison of two names, exported. The ground is OpenSSL's own subject hash (the hash of the canonical
// form of a name), asked for a certificate made with the raw name; the code is held to it on every pair of the table, in
// both orders, and on every pair of all the names of the table.
func TestSameNameAgainstOpenSSLsNameHash(t *testing.T) {
	rows := sameNameRows()
	hashes := map[string]string{}
	var names [][]byte
	hashOf := func(name []byte) string {
		if h, ok := hashes[string(name)]; ok {
			return h
		}
		h := opensslNameHash(t, name)
		hashes[string(name)] = h
		names = append(names, name)
		return h
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			want := hashOf(r.issuer) == hashOf(r.subj)
			if want != r.same {
				t.Fatalf("OpenSSL says %v, the table says %v", want, r.same)
			}
			for _, pair := range [][2][]byte{{r.issuer, r.subj}, {r.subj, r.issuer}} {
				got, err := pki.SameName(pair[0], pair[1])
				if err != nil {
					t.Fatalf("a name that the table gives is refused: %v", err)
				}
				if got != want {
					t.Errorf("SameName(%x, %x) = %v, OpenSSL says %v", pair[0], pair[1], got, want)
				}
			}
			if got, err := pki.SameName(r.issuer, r.issuer); err != nil || !got {
				t.Errorf("a name is not the same as itself: %v, %v", got, err)
			}
		})
	}
	t.Run("every pair of the names of the table, in both orders", func(t *testing.T) {
		equal, different := 0, 0
		for _, a := range names {
			for _, b := range names {
				want := hashes[string(a)] == hashes[string(b)]
				got, err := pki.SameName(a, b)
				if err != nil {
					t.Fatalf("%v", err)
				}
				if got != want {
					t.Errorf("SameName(%x, %x) = %v, OpenSSL says %v", a, b, got, want)
				}
				if want {
					equal++
				} else {
					different++
				}
			}
		}
		t.Logf("%d names, %d ordered pairs: %d the same to OpenSSL, %d different; no difference", len(names), len(names)*len(names), equal, different)
		if len(names) < 30 || equal < 200 || different < 800 {
			t.Errorf("the table is too small: %d names, %d same, %d different", len(names), equal, different)
		}
	})
}

// Bytes that are no name: an error that wraps ErrParams, no comparison, whichever of the two is bad.
func TestSameNameOfBytesThatAreNoName(t *testing.T) {
	good := cnName(tUTF8, "acme root")
	cn := atv(oidAttrCN, str(tUTF8, "x"))
	rows := []struct {
		name string
		raw  []byte
	}{
		{"nothing", nil},
		{"an empty slice", []byte{}},
		{"an empty sequence", []byte{0x30, 0x00}},
		{"an empty relative name", []byte{0x30, 0x02, 0x31, 0x00}},
		{"a byte after a name", append(append([]byte(nil), good...), 0)},
		{"a name twice", append(append([]byte(nil), good...), good...)},
		{"a name cut short", good[:len(good)-1]},
		{"a set instead of a sequence", append([]byte{0x31}, good[1:]...)},
		{"an octet string", tlv(0x04, good)},
		{"an integer", []byte{0x02, 0x01, 0x05}},
		{"text", []byte("CN=acme root")},
		{"a sequence of indefinite length", append(append([]byte{0x30, 0x80}, good[2:]...), 0, 0)},
		{"an attribute with a value that is an integer", nameOf(rdn(atv(oidAttrCN, tlv(0x02, []byte{1}))))},
		{"an attribute with three elements", nameOf(rdn(tlv(0x30, mustOID([]int{2, 5, 4, 3}), tlv(tUTF8, []byte("x")), tlv(tUTF8, []byte("y")))))},
		{"an attribute that is not a sequence", nameOf(tlv(0x31, tlv(0x04, []byte("x"))))},
		{"an attribute whose type is not an object identifier", nameOf(rdn(tlv(0x30, tlv(0x02, []byte{1}), tlv(tUTF8, []byte("x")))))},
		{"a relative name that is not in DER order", nameOf(rdnAsGiven(atv(oidAttrO, str(tUTF8, "x")), cn))},
		{"a common name of 65 characters", cnName(tUTF8, strings.Repeat("a", 65))},
		{"a country of three characters", nameOf(rdn(atv(oidAttrC, str(tPrintable, "NLD"))))},
		{"a BMPString", nameOf(rdn(atv(oidAttrCN, tlv(0x1e, []byte{0, 'a'}))))},
		{"a name that is a request", goodRequest(t).DER()},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			for _, pair := range [][2][]byte{{r.raw, good}, {good, r.raw}, {r.raw, r.raw}} {
				got, err := pki.SameName(pair[0], pair[1])
				refused(t, err, pki.ErrParams)
				if got {
					t.Error("a comparison was made")
				}
			}
		})
	}
}
