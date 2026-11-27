package openpgp_test

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // a SHA-1 signature is what some of the files hold: the reader counts it
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"ritueel.id/ritueel/internal/openpgp"
)

// The certificate of every export that the kit can make and the reader accepts is read again by
// ReadForeignCertificate as it stands, and gives the snapshot of the export.

// qaExport is a file of the kit.
type qaExport struct {
	name string
	b    *fkBase
	file []byte
}

// qaExports are the files of the kit: the base keys, the rich file of each base and the files that leave
// one subkey out, the files of the writer of signatures (SHA-1, several signatures, revocations, key-level
// signatures of every kind), the user IDs of odd texts, the subkeys of every algorithm and form, with their
// length fields stretched, and the attacks of the reviewers. Some of them the reader refuses, which is
// not the business of this test.
func qaExports(t testing.TB) []qaExport {
	t.Helper()
	var out []qaExport
	add := func(b *fkBase, name string, file []byte) {
		out = append(out, qaExport{b.name + ": " + name, b, file})
	}
	for _, b := range fkBases(t) {
		for n, f := range fkSnapshotCases(t, b) {
			add(b, n, f)
		}
		for _, p := range []fkProt{{Pass: fkPass, Cipher: 7}, {Pass: fkPass, Count: 1024}} {
			add(b, "protected another way", b.file(t, p))
		}
		skip := []string{"valid", "revoked", "twobind", "backsig"}
		if b.name == "rsa4096" {
			skip = skip[:1]
		}
		for _, s := range skip {
			add(b, "rich without "+s, fkBuildRich(t, b, fkProt{}, false, s).file)
			add(b, "rich clean without "+s, fkBuildRich(t, b, fkProt{}, true, s).file)
		}
	}
	ed := fkNamed(t, "ed25519")
	w := fkWriter{ed}
	life := func(days uint32) []byte { return fkSubpacket(9, true, fkU32(days*86400)...) }
	flags := func(f byte) []byte { return fkSubpacket(27, false, f) }
	sha1At := func(kind string, typ byte, at int, extra ...[]byte) []byte {
		target := []byte(fkUser)
		if kind != "user" {
			target = nil
		}
		return w.sign(t, kind, typ, w.areas(at, extra...), nil, 2, sha1.New, target)
	}
	user := func(at int, extra ...[]byte) []byte { return w.userSig(t, 0x13, w.areas(at, extra...), nil) }
	direct := func(at int, extra ...[]byte) []byte { return w.keySig(t, 0x1F, w.areas(at, extra...), nil) }
	parts := map[string]fkParts{
		"two self-signatures at different times": {userSigs: [][]byte{user(1100, flags(3))}},
		"two self-signatures in the same second": {userSigs: [][]byte{user(0, flags(3))}},
		"a SHA-1 self-signature alone":           {noSelf: true, userSigs: [][]byte{sha1At("user", 0x13, 1000, flags(1))}},
		"a SHA-1 self-signature after a strong":  {userSigs: [][]byte{sha1At("user", 0x13, 2000, flags(3), life(5))}},
		"a SHA-1 self-signature before a strong": {userSigs: [][]byte{sha1At("user", 0x13, 100, flags(3))}},
		"one dated far in the future":            {userSigs: [][]byte{user(900000000, flags(3), life(7))}},
		"a direct-key signature with an expiry":  {keySigs: [][]byte{direct(1200, life(30), flags(1))}},
		"a direct-key signature and two more":    {keySigs: [][]byte{direct(1200, life(30)), direct(1300), direct(1300, life(9))}},
		"a SHA-1 direct-key signature":           {keySigs: [][]byte{sha1At("key", 0x1F, 1200, life(30))}},
		"a hard key revocation": {keySigs: [][]byte{
			w.keySig(t, 0x20, w.areas(1500, fkReasonSub(2)), nil)}},
		"a soft key revocation": {keySigs: [][]byte{
			w.keySig(t, 0x20, w.areas(1500, fkReasonSub(3)), nil)}},
		"a key revocation without a reason": {keySigs: [][]byte{
			w.keySig(t, 0x20, w.areas(1500), nil)}},
		"a user ID revocation": {userSigs: [][]byte{
			w.userSig(t, 0x30, w.areas(1100, fkReasonSub(32)), nil)}},
		"a user ID revocation, then a renewal": {userSigs: [][]byte{
			w.userSig(t, 0x30, w.areas(1100, fkReasonSub(32)), nil), user(1200, flags(3))}},
		"every preference subpacket": {userSigs: [][]byte{user(1100, flags(3),
			fkSubpacket(11, false, 9, 8, 7), fkSubpacket(21, false, 10, 9, 8), fkSubpacket(22, false, 2, 1),
			fkSubpacket(23, false, 0x80), fkSubpacket(30, false, 1), fkSubpacket(39, false, 2, 9, 2, 7),
			fkSubpacket(26, false, []byte("https://example.org/policy")...), fkSubpacket(25, false, 1))}},
		"a binding and a revocation of the subkey": {subSigs: [][]byte{
			w.subSig(t, 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil),
			w.subSig(t, 0x28, w.areas(1100, fkReasonSub(3)), nil)}},
		"a binding with a SHA-1 hash": {noBind: false, subSigs: [][]byte{
			w.sign(t, "sub", 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil, 2, sha1.New, mustDonor(t))}},
	}
	for name, p := range parts {
		add(ed, name, w.file(t, p))
	}
	// user IDs of odd texts: the reader takes the bytes that the primary signed
	head := fkTemplateHead(t, ed.file(t, fkProt{}))
	for name, text := range map[string]string{
		"a user ID with a comment":             "Quokka Tester (the second one) <quokka@example.org>",
		"a user ID with no address":            "Quokka Tester",
		"a user ID with letters outside ASCII": "Zo\u00eb M\u00fcller-\u0141ukasiewicz <zoe@example.org>",
		"a user ID with a line break":          "Quokka\nTester",
		"a user ID with a NUL":                 "Quokka\x00Tester",
		"a user ID that is not UTF-8":          "Quokka \xff\xfe Tester",
		"a user ID of one byte":                "q",
		"a user ID of the longest length":      strings.Repeat("q", openpgp.MaxForeignUserIDBytes),
		"a user ID that is empty":              "",
		"a user ID with an escape":             "Quokka\x1b[31m Tester",
	} {
		sig := fkPacket{2, w.sign(t, "user", 0x13, w.areas(1000, flags(3)), nil, 8, sha256.New, []byte(text))}
		add(ed, name, fkJoin(head[0], fkPacket{13, []byte(text)}, sig))
		two := fkJoin(head[0], head[1], head[2], fkPacket{13, []byte(text)}, sig)
		add(ed, name+", beside the user ID of the template", two)
	}
	// the subkeys of every algorithm and form, with their length fields stretched
	for i, c := range qaCraftedFiles(t) {
		add(ed, "crafted subkey "+fkItoa(i), c)
	}
	for _, a := range append(fkReviewerAttacks(t), fkRelabelledAttacks(t)...) {
		add(ed, "attack "+a.name, a.file)
	}
	return out
}

// qaCraftedFiles are the files of the secret subkeys in every form that the fuzz seeds hold (fkCraftedSeeds
// takes a *testing.F).
func qaCraftedFiles(t testing.TB) [][]byte {
	b := fkNamed(t, "ed25519")
	enc, sig, _ := fkDonors(t)
	var out [][]byte
	for _, usage := range []byte{0, 254, 255} {
		for _, s := range []fkSubSecret{
			fkRSASub(t, 3, usage), fkRSASub(t, 257, usage), fkRSASub(t, 65537, usage),
			fkFakeSub(t, 17, usage), fkFakeSub(t, 16, usage),
			fkRealSub(t, "ECDH", enc[0].pub, enc[0].sec, usage, 6, 33, true),
			fkRealSub(t, "EdDSA", sig[0].pub, sig[0].sec, usage, 6, 33, false),
		} {
			out = append(out, s.bound(t, b, s.body))
			for _, k := range []int{1, 3, 8} {
				out = append(out, s.bound(t, b, s.stretch(s.last, k)))
			}
		}
	}
	return out
}

// mustDonor is the public subkey body that fkWriter.subSig signs over (the fourth encryption donor).
func mustDonor(t testing.TB) []byte {
	enc, _, _ := fkDonors(t)
	return enc[3].pub.Body
}

// qaReadCert reads a certificate against its own digest, which is what a caller that holds the right digest does.
func qaReadCert(cert []byte) (*openpgp.ForeignKey, error) {
	return openpgp.ReadForeignCertificate(cert, fkDigestOf(cert))
}

// qaSnapshotEqual compares two snapshots with the exported views of the tests.
func qaSnapshotEqual(a, b *openpgp.ForeignKey) bool {
	return reflect.DeepEqual(openpgp.SnapshotOf(a), openpgp.SnapshotOf(b))
}

func TestQACertificateOfEveryAcceptedExportIsAccepted(t *testing.T) {
	files := qaExports(t)
	accepted, refused := 0, 0
	seen := map[string]bool{}
	for _, f := range files {
		k, err := openpgp.ReadForeignKey(f.file)
		if err != nil {
			refused++
			continue
		}
		accepted++
		if strings.Contains(f.name, "a user ID") {
			t.Logf("read as an export: %s", f.name)
		}
		cert := k.Certificate()
		if seen[string(cert)] {
			continue
		}
		seen[string(cert)] = true
		what := f.name
		in := bytes.Clone(cert)
		kc, err := qaReadCert(in)
		if err != nil {
			t.Errorf("%s: the certificate of the export is refused: %v", what, err)
			continue
		}
		// a copy: what the caller does to its input afterwards changes nothing
		clear(in)
		if !bytes.Equal(kc.Certificate(), cert) {
			t.Errorf("%s: the certificate that was read is not the input", what)
		}
		if !qaSnapshotEqual(k, kc) {
			t.Errorf("%s: the snapshot of the certificate is not the snapshot of the export:\n%+v\n%+v", what, openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc))
		}
		// and again: a fixpoint of a fixpoint
		kc2, err := qaReadCert(kc.Certificate())
		if err != nil || !bytes.Equal(kc2.Certificate(), cert) || !qaSnapshotEqual(kc, kc2) {
			t.Errorf("%s: the certificate is not read again as itself: %v", what, err)
		}
		// the view of the key agrees with the export's on what a certificate holds
		if kc.Primary.Fingerprint != k.Primary.Fingerprint || kc.Primary.Revoked != k.Primary.Revoked || !kc.Primary.Created.Equal(k.Primary.Created) {
			t.Errorf("%s: the primary of the certificate: %+v, the export's %+v", what, kc.Primary, k.Primary)
		}
		wantUsers, gotUsers := validUsers(k), kc.UserIDs
		if len(gotUsers) != len(wantUsers) {
			t.Errorf("%s: %d user IDs in the view of the certificate, %d valid ones in the export", what, len(gotUsers), len(wantUsers))
		} else {
			for i, u := range gotUsers {
				w := wantUsers[i]
				if u.Text != w.Text || u.Valid != w.Valid || u.Revoked != w.Revoked || u.WeakHash != w.WeakHash || u.KeyFlags != w.KeyFlags ||
					u.Primary != w.Primary || !u.KeyExpires.Equal(w.KeyExpires) || !u.Created.Equal(w.Created) {
					t.Errorf("%s: user ID %d of the certificate: %+v, the export's: %+v", what, i, u, w)
				}
			}
		}
		var wantSubs []openpgp.ForeignSubkey
		for _, s := range k.Subkeys {
			if s.InCertificate {
				wantSubs = append(wantSubs, s)
			}
		}
		var gotSubs []openpgp.ForeignSubkey
		for _, s := range kc.Subkeys {
			if s.InCertificate {
				gotSubs = append(gotSubs, s)
			}
		}
		if len(gotSubs) != len(wantSubs) {
			t.Errorf("%s: %d subkeys in the certificate, %d in the export's", what, len(gotSubs), len(wantSubs))
		}
		// go-crypto reads it as one entity of the same fingerprint
		ents, err := pgp.ReadKeyRing(bytes.NewReader(cert))
		if err != nil || len(ents) != 1 || hexOf(ents[0].PrimaryKey.Fingerprint) != k.Primary.Fingerprint {
			t.Errorf("%s: go-crypto does not read the certificate as one entity of the key: %v", what, err)
		}
		// it holds no secret
		if s, err := kc.OpenSecret(nil); s != nil || err == nil {
			t.Errorf("%s: OpenSecret of a certificate: %v", what, err)
		}
	}
	t.Logf("%d files of the kit: %d read as exports (%d certificates that differ), %d refused", len(files), accepted, len(seen), refused)
	if accepted < 120 || len(seen) < 60 {
		t.Errorf("only %d files are read and %d certificates differ: the corpus is smaller than it was", accepted, len(seen))
	}
}

// validUsers are the user IDs of an export that go into its certificate, once each, in order.
func validUsers(k *openpgp.ForeignKey) []openpgp.ForeignUserID {
	var out []openpgp.ForeignUserID
	seen := map[string]bool{}
	for _, u := range k.UserIDs {
		if u.Valid && !seen[u.Text] {
			seen[u.Text] = true
			out = append(out, u)
		}
	}
	return out
}
