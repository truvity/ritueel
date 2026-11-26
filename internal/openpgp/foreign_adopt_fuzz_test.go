package openpgp_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// FuzzOpenSecretPacket: whatever the input is, the reader does not panic (the reader recovers a panic
// and says so in its text, which is a failure here); it returns a key or a refusal and never both; a
// refusal is an ErrForeignKey whose text is plain and holds no run of the input; and a packet that it
// accepts is canonical (the shortest header, the numbers in their shortest form, the right checksum),
// so that writing it again from what it says gives the same bytes, and the key that it returns has the
// public key that the packet says, signs, and is the key that go-crypto reads, where go-crypto reads it.
func FuzzOpenSecretPacket(f *testing.F) {
	for _, b := range fkBases(f) {
		_, pkt := fkLone(f, b, "")
		f.Add(pkt)
		p, err := alParse(pkt)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(pkt[:len(pkt)-1])
		f.Add(append(bytes.Clone(pkt), 0))
		f.Add(wrap(6, pkt[alHeaderLen(pkt):]))
		f.Add(wrap(5, p.body(0, 0)))
		f.Add(wrap(5, p.body(254, -1)))
		bad := bytes.Clone(pkt)
		bad[alHeaderLen(pkt)+5] ^= 0x10
		f.Add(bad)
		other := p.clone()
		other.Sec[len(other.Sec)-1] = fkMPI(flipLast(other.values()[len(other.Sec)-1]))
		f.Add(other.packet())
	}
	f.Add([]byte(nil))
	f.Add([]byte{0xC5, 0x00})
	f.Add([]byte{0x94, 0x03, 4, 0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		secret, pub, err := openpgp.OpenSecretPacket(in)
		if err != nil {
			if secret != nil || pub.Fingerprint != "" || pub.PublicBody != nil {
				t.Fatalf("something is returned with the error %v", err)
			}
			if !errors.Is(err, openpgp.ErrForeignKey) {
				t.Fatalf("%v is not an ErrForeignKey", err)
			}
			text := err.Error()
			if strings.Contains(text, "could not be read") {
				t.Fatalf("the reader recovered a panic: %v", err)
			}
			if len(text) > 500 {
				t.Fatalf("the text is %d bytes long", len(text))
			}
			for _, c := range []byte(text) {
				if c < 0x20 || c > 0x7E {
					t.Fatalf("the text holds the byte %#x: %q", c, text)
				}
			}
			for i := 0; i+10 <= len(in) && i < 4096; i++ {
				if strings.Contains(text, string(in[i:i+10])) {
					t.Fatalf("the text holds a run of the input at %d: %q", i, text)
				}
			}
			return
		}
		defer secret.Wipe()
		p, perr := alParse(in)
		if perr != nil {
			t.Fatalf("a packet that is not canonical is read: %v", perr)
		}
		if !bytes.Equal(p.packet(), in) {
			t.Fatalf("the packet that it says is not the packet that was read")
		}
		if len(in) > openpgp.MaxAdoptedPacketBytes {
			t.Fatalf("a packet of %d bytes is read", len(in))
		}
		if !bytes.Equal(pub.PublicBody, p.pubBody()) || pub.Fingerprint != alFingerprint(p.pubBody()) || pub.Algorithm.ID != p.alg() {
			t.Fatalf("the facts that it says are not those of the packet")
		}
		want := alPublicOf(t, p)
		if !publicEqual(secret.Signer().Public(), want) {
			t.Fatalf("the public key of the signer is not the public key of the packet")
		}
		alSignAndVerify(t, secret.Signer(), want)
		if read, err := gpacket.Read(bytes.NewReader(in)); err == nil {
			if sk, ok := read.(*gpacket.PrivateKey); ok && !fkSamePublic(secret.Signer(), &sk.PublicKey) {
				t.Fatalf("go-crypto reads another public key")
			}
		}
	})
}
