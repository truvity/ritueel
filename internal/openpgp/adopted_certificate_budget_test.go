package openpgp_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The limits of the reader hold for a certificate, and they are held before the work that they bound: a
// certificate that passes one is refused without a signature being verified or a byte hashed. The cases
// are made so that doing the work first would cost seconds, and the refusal is timed.

// qaPhoto is a user attribute packet of the largest size that the reader takes (one image subpacket).
func qaPhoto(t testing.TB, fill byte) fkPacket {
	t.Helper()
	n := openpgp.MaxForeignPacketBytes - 6
	body := append([]byte{0xFF, byte((n + 1) >> 24), byte((n + 1) >> 16), byte((n + 1) >> 8), byte(n + 1), 1}, bytes.Repeat([]byte{fill}, n)...)
	return fkPacket{17, body}
}

func TestQAReadForeignCertificateHoldsItsLimitsBeforeTheWork(t *testing.T) {
	b := fkNamed(t, "ed25519")
	ps := fkSplit(t, fkRead(t, b.plain).Certificate())
	head, sig := ps[:3], ps[2]
	const quick = 3 * time.Second // verifying or hashing what the limit bounds would take longer on any machine

	refuse := func(what, constant string, cert []byte) {
		t.Helper()
		start := time.Now()
		k, err := qaReadCert(cert)
		took := time.Since(start)
		if k != nil || err == nil {
			t.Errorf("%s: the certificate was read (%v)", what, err)
			return
		}
		if !errors.Is(err, openpgp.ErrForeignLimit) || !errors.Is(err, openpgp.ErrForeignKey) {
			t.Errorf("%s: %v is not an ErrForeignLimit", what, err)
		}
		if !strings.Contains(err.Error(), constant) {
			t.Errorf("%s: the text %q does not name %s", what, err, constant)
		}
		fkCheckText(t, what, err, b)
		t.Logf("%s: refused in %v", what, took.Round(time.Microsecond))
		if took > quick {
			t.Errorf("%s: refused after %v: the limit was not held before the work", what, took)
		}
	}

	// the size, before anything is read
	refuse("more bytes than MaxForeignKeyBytes", "MaxForeignKeyBytes", make([]byte, openpgp.MaxForeignKeyBytes+1))
	// the packets: signatures that are all good, more than the limit
	many := append(fkJoin(head[:2]...), bytes.Repeat(fkJoin(sig), openpgp.MaxForeignPackets)...)
	refuse("more packets than MaxForeignPackets", "MaxForeignPackets", many)
	// a packet longer than the limit
	over := fkJoin(head[0], fkPacket{17, make([]byte, openpgp.MaxForeignPacketBytes+1)})
	refuse("a packet longer than MaxForeignPacketBytes", "MaxForeignPacketBytes", over)
	// more user IDs and more attributes than the limit
	var ids, attrs []byte
	ids = append(ids, fkJoin(head[0])...)
	attrs = append(attrs, fkJoin(head[0])...)
	for i := 0; i <= openpgp.MaxForeignUserIDs; i++ {
		ids = append(ids, fkJoin(fkPacket{13, []byte{byte('A' + i)}}, sig)...)
		attrs = append(attrs, fkJoin(fkPacket{17, []byte{1, 1, 1}}, sig)...)
	}
	refuse("more user IDs than MaxForeignUserIDs", "MaxForeignUserIDs", ids)
	refuse("more attributes than MaxForeignUserIDs", "MaxForeignUserIDs", attrs)
	// a user ID packet longer than the limit
	refuse("a user ID longer than MaxForeignUserIDBytes", "MaxForeignUserIDBytes", fkJoin(head[0], fkPacket{13, make([]byte, openpgp.MaxForeignUserIDBytes+1)}))
	// more subkeys than the limit
	enc, _, _ := fkDonors(t)
	subs := fkJoin(head...)
	for i := 0; i <= openpgp.MaxForeignSubkeys; i++ {
		body := bytes.Clone(enc[0].pub.Body)
		body[4] = byte(i)
		subs = append(subs, fkJoin(fkPacket{14, body}, sig)...)
	}
	refuse("more subkeys than MaxForeignSubkeys", "MaxForeignSubkeys", subs)
	// more signatures on one component than the limit: a photograph of the largest size with 1025 signatures on it,
	// which would hash two gigabytes if they were checked
	photo := qaPhoto(t, 7)
	same := fkJoin(head[0], photo)
	same = append(same, bytes.Repeat(fkJoin(sig), openpgp.MaxForeignSignatures+1)...)
	refuse("more signatures than MaxForeignSignatures on one photograph", "MaxForeignSignatures", same)
	// more signatures that the primary answers for than the limit, none on one component more than 1024: three photographs of
	// the largest size, 700 signatures on each, which would hash four gigabytes if they were checked
	claimed := fkJoin(head[0])
	for i := 0; i < 3; i++ {
		claimed = append(claimed, fkJoin(qaPhoto(t, byte(i)))...)
		claimed = append(claimed, bytes.Repeat(fkJoin(sig), 700)...)
	}
	refuse("more signatures than MaxForeignClaimedSignatures over photographs", "MaxForeignClaimedSignatures", claimed)
}

// The worst case that the limits allow, read as a certificate: distinct signatures on one photograph of the
// largest size up to the budget of hashing, and distinct bindings up to the budget of verifications. Both
// certificates are accepted, since every signature is good and none is a duplicate; one signature more
// is refused by name. The times are logged.
func TestQAReadForeignCertificateWorstCaseInsideTheLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("hashes about half a gigabyte")
	}
	b := fkNamed(t, "ed25519")
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	photo := qaPhoto(t, 9)

	// the budget of hashing: each check hashes the photograph twice, so 255 distinct signatures are just under
	// 512 MiB and 256 are over it
	hashed := func(n int) []byte {
		ps := []fkPacket{head[0], head[1], head[2], photo}
		for i := 0; i < n; i++ {
			ps = append(ps, fkPacket{2, fkAttrSig(t, b, photo.Body, 1000+i)})
		}
		return fkJoin(ps...)
	}
	file := hashed(255)
	start := time.Now()
	k, err := openpgp.ReadForeignKey(file)
	exportTook := time.Since(start)
	if err != nil {
		t.Fatalf("255 distinct signatures on a photograph, read as an export: %v", err)
	}
	if k.DuplicatesDropped != 0 || k.UserAttributes != 1 {
		t.Fatalf("duplicates %d, attributes %d", k.DuplicatesDropped, k.UserAttributes)
	}
	cert := k.Certificate()
	start = time.Now()
	kc, err := qaReadCert(cert)
	certTook := time.Since(start)
	if err != nil {
		t.Fatalf("255 distinct signatures on a photograph, read as a certificate: %v", err)
	}
	if !bytes.Equal(kc.Certificate(), cert) || !qaSnapshotEqual(k, kc) {
		t.Error("the certificate is not read as it stands")
	}
	t.Logf("WORST CASE hashing: a certificate of %d bytes with one photograph and 255 distinct signatures: export %v, certificate %v", len(cert), exportTook.Round(time.Millisecond), certTook.Round(time.Millisecond))
	if certTook > 30*time.Second {
		t.Errorf("the worst case of hashing took %v", certTook)
	}
	over := hashed(256)
	_, err = openpgp.ReadForeignKey(over)
	if !errors.Is(err, openpgp.ErrForeignLimit) || !strings.Contains(err.Error(), "MaxForeignHashedBytes") {
		t.Errorf("256 distinct signatures on a photograph, as an export: %v", err)
	}
	// the certificate form of the same: the signatures of the export are those of the certificate when they count
	// but the export is what is refused first; a certificate of 256 distinct signatures is made by hand
	ps := fkSplit(t, cert)
	ps = append(ps, fkPacket{2, fkAttrSig(t, b, photo.Body, 1000+255)})
	start = time.Now()
	kc, err = qaReadCert(fkJoin(ps...))
	if kc != nil || !errors.Is(err, openpgp.ErrForeignLimit) || !strings.Contains(err.Error(), "MaxForeignHashedBytes") {
		t.Errorf("256 distinct signatures on a photograph, as a certificate: %v", err)
	}
	t.Logf("256 distinct signatures, as a certificate: refused by name in %v", time.Since(start).Round(time.Millisecond))

	// the budget of verifications: 1365 distinct bindings of two subkeys cost 4096, one more is over. The
	// primary of each of two algorithms makes them: a verification of a P-384 signature is the slowest.
	enc, _, _ := fkDonors(t)
	for _, name := range []string{"ed25519", "p384"} {
		pb := fkNamed(t, name)
		phead := fkTemplateHead(t, pb.file(t, fkProt{}))
		bindOf := func(i int, d fkDonorKey) fkPacket {
			return fkPacket{2, fkSplit(t, pb.subSig(t, pb.primaryPair(), d.pair.pub, fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding, Flags: 0x0C, At: fkSigAt(1000 + i)}))[0].Body}
		}
		n := 1365
		ps := []fkPacket{phead[0], phead[1], phead[2], enc[0].pub}
		for i := 0; i < n; i++ {
			if i == (n+1)/2 {
				ps = append(ps, enc[1].pub)
			}
			d := enc[0]
			if i >= (n+1)/2 {
				d = enc[1]
			}
			ps = append(ps, bindOf(i, d))
		}
		k, err = openpgp.ReadForeignKey(fkJoin(ps...))
		if err != nil {
			t.Fatalf("%s: 1365 bindings: %v", name, err)
		}
		cert = k.Certificate()
		start = time.Now()
		kc, err = qaReadCert(cert)
		bindTook := time.Since(start)
		if err != nil {
			t.Fatalf("%s: 1365 bindings, read as a certificate: %v", name, err)
		}
		if !bytes.Equal(kc.Certificate(), cert) || !qaSnapshotEqual(k, kc) {
			t.Errorf("%s: the certificate of 1365 bindings is not read as it stands", name)
		}
		t.Logf("WORST CASE verifying with %s: a certificate of %d bytes with 1365 distinct bindings (4096 verifications): %v", name, len(cert), bindTook.Round(time.Millisecond))
		cps := fkSplit(t, cert)
		cps = append(cps, bindOf(n+7, enc[1]))
		kc, err = qaReadCert(fkJoin(cps...))
		if kc != nil || !errors.Is(err, openpgp.ErrForeignLimit) || !strings.Contains(err.Error(), "MaxForeignVerifications") {
			t.Errorf("%s: 1366 bindings, as a certificate: %v", name, err)
		}
		if ents, err := pgp.ReadKeyRing(bytes.NewReader(cert)); err != nil || len(ents) != 1 {
			t.Errorf("%s: go-crypto does not read the certificate of the bindings: %v", name, err)
		}
	}
}
