package openpgp_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// F. The named limits: each is read at its value and refused one past it, and the text names the
// constant. The packets that fill a file are trust packets and marker packets, which the reader skips,
// and signatures of another key, which it counts and does not parse.

// fkPad writes trust packets, old or new format, that are exactly n bytes together. n is 0 or at
// least 2.
func fkPad(t testing.TB, n int) []byte {
	t.Helper()
	var out []byte
	for n > 0 {
		chunk := min(n, 6+openpgp.MaxForeignPacketBytes)
		if n-chunk == 1 {
			chunk--
		}
		if chunk < 2 {
			t.Fatalf("cannot pad %d bytes", n)
		}
		switch {
		case chunk-2 < 256:
			out = append(out, 0x80|12<<2, byte(chunk-2))
			out = append(out, make([]byte, chunk-2)...)
		case chunk-3 < 65536:
			out = append(out, 0x80|12<<2|1, byte((chunk-3)>>8), byte(chunk-3))
			out = append(out, make([]byte, chunk-3)...)
		default:
			body := make([]byte, chunk-6)
			out = append(out, wrapLong(12, body)...)
		}
		n -= chunk
	}
	return out
}

// fkThird is a certification of the user ID by another key, whole: the reader counts it.
func fkThird(t testing.TB, b *fkBase) fkPacket {
	t.Helper()
	_, _, other := fkDonors(t)
	return fkSplit(t, b.certSig(t, other, b.ent.PrimaryKey, fkUser, fkSigSpec{Typ: gpacket.SigTypeGenericCert}))[0]
}

// fkLimitAcceptsAndRefuses reads the file at the limit and the file one past it.
func fkLimitAcceptsAndRefuses(t *testing.T, name, constant string, b *fkBase, atLimit, pastLimit []byte, check func(t *testing.T, k *openpgp.ForeignKey)) {
	t.Helper()
	k, err := openpgp.ReadForeignKey(atLimit)
	if err != nil {
		t.Errorf("%s: at the limit: %v", name, err)
	} else if check != nil {
		check(t, k)
	}
	err = fkRefused(t, name+" past the limit", pastLimit, b, openpgp.ErrForeignLimit)
	if err != nil && !strings.Contains(err.Error(), constant) {
		t.Errorf("%s: the text %q does not name %s", name, err, constant)
	}
}

func TestForeignLimits(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, _, _ := fkDonors(t)
	plain := b.file(t, fkProt{})
	ps := fkSplit(t, plain)
	third := fkThird(t, b)
	extras := func(n int, tag byte, body func(i int) []byte) []fkPacket {
		var out []fkPacket
		for i := 0; i < n; i++ {
			out = append(out, fkPacket{tag, body(i)})
		}
		return out
	}
	// the packets are: 0 primary, 1 user ID, 2 its self-signature, 3 and 4 the encryption subkey with its
	// binding, 5 and 6 the signing subkey with its binding.
	with := func(at int, add ...fkPacket) []byte {
		out := append([]fkPacket{}, ps[:at]...)
		out = append(out, add...)
		return fkJoin(append(out, ps[at:]...)...)
	}

	t.Run("MaxForeignKeyBytes", func(t *testing.T) {
		at := append(bytes.Clone(plain), fkPad(t, openpgp.MaxForeignKeyBytes-len(plain))...)
		past := append(bytes.Clone(plain), fkPad(t, openpgp.MaxForeignKeyBytes+1-len(plain))...)
		if len(at) != openpgp.MaxForeignKeyBytes || len(past) != openpgp.MaxForeignKeyBytes+1 {
			t.Fatalf("the files are %d and %d bytes", len(at), len(past))
		}
		fkLimitAcceptsAndRefuses(t, "binary", "MaxForeignKeyBytes", b, at, past, func(t *testing.T, k *openpgp.ForeignKey) {
			if len(k.Certificate()) == 0 || len(k.Certificate()) > 4096 {
				t.Errorf("the certificate is %d bytes: the padding is in it", len(k.Certificate()))
			}
		})
		// the limit is checked before the armour is read, and before anything else
		head := []byte("-----BEGIN " + fkPrivateBlock() + "-----\n\n")
		armoured := append(bytes.Clone(head), bytes.Repeat([]byte("A"), openpgp.MaxForeignKeyBytes+1-len(head))...)
		err := fkRefused(t, "armoured past the limit", armoured, b, openpgp.ErrForeignLimit)
		if err != nil && !strings.Contains(err.Error(), "MaxForeignKeyBytes") {
			t.Errorf("the text does not name the limit: %v", err)
		}
		// a file of garbage past the limit is a limit and not a form
		_ = fkRefused(t, "garbage past the limit", make([]byte, openpgp.MaxForeignKeyBytes+1), b, openpgp.ErrForeignLimit)
	})

	t.Run("MaxForeignPacketBytes", func(t *testing.T) {
		trust := func(n int) []byte { return append(bytes.Clone(plain), wrapLong(12, make([]byte, n))...) }
		fkLimitAcceptsAndRefuses(t, "a trust packet", "MaxForeignPacketBytes", b,
			trust(openpgp.MaxForeignPacketBytes), trust(openpgp.MaxForeignPacketBytes+1), nil)
		// a packet that is kept, a user attribute of the largest size, is read, and its size is counted
		kept := with(3, fkPacket{17, make([]byte, openpgp.MaxForeignPacketBytes)})
		k, err := openpgp.ReadForeignKey(kept)
		if err != nil || k.UserAttributes != 1 || k.UserAttributeBytes != openpgp.MaxForeignPacketBytes {
			t.Errorf("a user attribute of MaxForeignPacketBytes: %v", err)
		}
	})

	t.Run("MaxForeignPackets", func(t *testing.T) {
		markers := func(n int) []byte { return bytes.Repeat([]byte{0xCA, 0}, n) }
		atN := openpgp.MaxForeignPackets - len(ps)
		at := append(bytes.Clone(plain), markers(atN)...)
		past := append(bytes.Clone(plain), markers(atN+1)...)
		fkLimitAcceptsAndRefuses(t, "markers", "MaxForeignPackets", b, at, past, nil)
		// the trust and marker packets count even when they stand first
		first := append(markers(openpgp.MaxForeignPackets-len(ps)), plain...)
		if _, err := openpgp.ReadForeignKey(first); err != nil {
			t.Errorf("markers first, at the limit: %v", err)
		}
		_, err := openpgp.ReadForeignKey(append(markers(1), first...))
		if !strings.Contains(fmt.Sprint(err), "MaxForeignPackets") {
			t.Errorf("markers first, past the limit: %v", err)
		}
	})

	t.Run("MaxForeignUserIDs", func(t *testing.T) {
		uids := func(n int) []fkPacket {
			return extras(n, 13, func(i int) []byte { return []byte(fmt.Sprintf("extra %d <extra%d@example.org>", i, i)) })
		}
		fkLimitAcceptsAndRefuses(t, "user IDs", "MaxForeignUserIDs", b,
			with(3, uids(openpgp.MaxForeignUserIDs-1)...), with(3, uids(openpgp.MaxForeignUserIDs)...),
			func(t *testing.T, k *openpgp.ForeignKey) {
				if len(k.UserIDs) != openpgp.MaxForeignUserIDs {
					t.Errorf("%d user IDs", len(k.UserIDs))
				}
			})
		attrs := func(n int) []fkPacket {
			return extras(n, 17, func(i int) []byte { return append([]byte{3, 1}, byte(i), byte(i)) })
		}
		fkLimitAcceptsAndRefuses(t, "user attributes", "MaxForeignUserIDs", b,
			with(3, attrs(openpgp.MaxForeignUserIDs)...), with(3, attrs(openpgp.MaxForeignUserIDs+1)...),
			func(t *testing.T, k *openpgp.ForeignKey) {
				if k.UserAttributes != openpgp.MaxForeignUserIDs {
					t.Errorf("%d user attributes", k.UserAttributes)
				}
			})
		// the two are counted apart: 32 of each is read
		both := with(3, append(uids(openpgp.MaxForeignUserIDs-1), attrs(openpgp.MaxForeignUserIDs)...)...)
		if _, err := openpgp.ReadForeignKey(both); err != nil {
			t.Errorf("32 user IDs and 32 user attributes: %v", err)
		}
	})

	t.Run("MaxForeignSubkeys", func(t *testing.T) {
		subs := func(n int) []fkPacket {
			out := make([]fkPacket, n)
			for i := range out {
				out[i] = enc[i%len(enc)].pub
			}
			return out
		}
		at := fkJoin(append(append([]fkPacket{}, ps[:3]...), subs(openpgp.MaxForeignSubkeys)...)...)
		past := fkJoin(append(append([]fkPacket{}, ps[:3]...), subs(openpgp.MaxForeignSubkeys+1)...)...)
		fkLimitAcceptsAndRefuses(t, "subkeys", "MaxForeignSubkeys", b, at, past, func(t *testing.T, k *openpgp.ForeignKey) {
			if len(k.Subkeys) != openpgp.MaxForeignSubkeys {
				t.Errorf("%d subkeys", len(k.Subkeys))
			}
		})
	})

	t.Run("MaxForeignSignatures", func(t *testing.T) {
		thirds := func(n int) []fkPacket { return extras(n, 2, func(int) []byte { return third.Body }) }
		attr := fkAttribute(t, 10)
		cases := []struct {
			name  string
			build func(n int) []byte
			check func(t *testing.T, k *openpgp.ForeignKey)
		}{
			{"on the key", func(n int) []byte { return with(1, thirds(n)...) }, func(t *testing.T, k *openpgp.ForeignKey) {
				if k.OtherKeySignatures != openpgp.MaxForeignSignatures {
					t.Errorf("%d signatures of other keys on the key", k.OtherKeySignatures)
				}
			}},
			{"on a user ID, with its self-signature", func(n int) []byte { return with(3, thirds(n-1)...) }, func(t *testing.T, k *openpgp.ForeignKey) {
				if k.UserIDs[0].Certifications != openpgp.MaxForeignSignatures-1 {
					t.Errorf("%d certifications", k.UserIDs[0].Certifications)
				}
			}},
			{"on a user attribute", func(n int) []byte { return with(3, append([]fkPacket{attr}, thirds(n)...)...) }, nil},
			{"on a subkey, with its binding", func(n int) []byte { return with(5, thirds(n-1)...) }, func(t *testing.T, k *openpgp.ForeignKey) {
				if k.Subkeys[0].OtherSignatures != openpgp.MaxForeignSignatures-1 {
					t.Errorf("%d signatures of other keys on the subkey", k.Subkeys[0].OtherSignatures)
				}
			}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				fkLimitAcceptsAndRefuses(t, c.name, "MaxForeignSignatures", b,
					c.build(openpgp.MaxForeignSignatures), c.build(openpgp.MaxForeignSignatures+1), c.check)
			})
		}
	})
}

// The limit of the passphrase is MaxForeignPassphraseBytes, tested with the passphrase (B). The
// constants have the values of the doc comment.
func TestForeignLimitValues(t *testing.T) {
	for name, c := range map[string][2]int{
		"MaxForeignKeyBytes":          {openpgp.MaxForeignKeyBytes, 8 << 20},
		"MaxForeignPackets":           {openpgp.MaxForeignPackets, 10000},
		"MaxForeignUserIDs":           {openpgp.MaxForeignUserIDs, 32},
		"MaxForeignSubkeys":           {openpgp.MaxForeignSubkeys, 64},
		"MaxForeignSignatures":        {openpgp.MaxForeignSignatures, 1024},
		"MaxForeignPacketBytes":       {openpgp.MaxForeignPacketBytes, 1 << 20},
		"MaxForeignPassphraseBytes":   {openpgp.MaxForeignPassphraseBytes, 4096},
		"MaxForeignUserIDBytes":       {openpgp.MaxForeignUserIDBytes, 2048},
		"MaxForeignClaimedSignatures": {openpgp.MaxForeignClaimedSignatures, 2048},
	} {
		if c[0] != c[1] {
			t.Errorf("%s is %d, the doc comment says %d", name, c[0], c[1])
		}
	}
}
