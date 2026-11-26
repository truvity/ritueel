package openpgp_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// D. The public certificate holds no secret material. For every key of the tests the certificate is
// read with go-crypto, searched for every secret number and every secret region of the file, compared
// packet by packet with the packets of the file that are not secret, and found to be a copy.
// C. The three forms of a subkey, and what the reader never needs of the secret of one.

// fkCertCase is one file with what it holds.
type fkCertCase struct {
	name string
	b    *fkBase
	file []byte
	// fingerprints are those of the primary and then of each subkey, in the order of the file.
	fingerprints [][]byte
	// users are the texts of the user IDs in the order of the file.
	users []string
	// numbers and regions are the secrets of the file, which no byte run of eight may leave.
	numbers, regions [][]byte
	// clean is true when go-crypto reads the file as a key ring too.
	clean bool
}

// knownPublic lists the public parts of every key packet of the tests, so that a secret key packet
// can be cut into its public and its secret part without the code under test.
func fkKnownPublic(t testing.TB, b *fkBase) [][]byte {
	t.Helper()
	known := [][]byte{b.pubBody(t)}
	for _, s := range b.ent.Subkeys {
		var buf bytes.Buffer
		if err := s.PublicKey.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		known = append(known, fkSplit(t, buf.Bytes())[0].Body)
	}
	enc, sig, _ := fkDonors(t)
	for _, d := range append(slices.Clone(enc), sig...) {
		known = append(known, d.pub.Body)
	}
	return known
}

// fkTemplateCase is the case of a file that the template writes.
func fkTemplateCase(t testing.TB, b *fkBase, name string, file []byte) fkCertCase {
	t.Helper()
	c := fkCertCase{name: name, b: b, file: file, users: []string{fkUser}, clean: true}
	c.fingerprints = append(c.fingerprints, b.ent.PrimaryKey.Fingerprint)
	for _, s := range b.ent.Subkeys {
		c.fingerprints = append(c.fingerprints, s.PublicKey.Fingerprint)
	}
	sec := b.secrets(t)
	c.numbers = sec.all()
	// every secret region that a protected file holds, by its place in the packets
	pub := b.pubBody(t)
	known := fkKnownPublic(t, b)
	for _, p := range fkSplit(t, file) {
		switch p.Tag {
		case 5:
			if r := p.Body[len(pub):]; r[0] != 0 {
				c.regions = append(c.regions, bytes.Clone(r))
			}
		case 7:
			for _, k := range known {
				if bytes.HasPrefix(p.Body, k) && len(p.Body) > len(k) && p.Body[len(k)] != 0 {
					c.regions = append(c.regions, bytes.Clone(p.Body[len(k):]))
				}
			}
		}
	}
	return c
}

// fkRichCase is the case of a rich file.
func fkRichCase(t testing.TB, r *fkRich, name string, clean bool) fkCertCase {
	t.Helper()
	c := fkCertCase{name: name, b: r.b, file: r.file, numbers: r.numbers, regions: r.regions, clean: clean}
	c.fingerprints = append(c.fingerprints, r.b.ent.PrimaryKey.Fingerprint)
	subs := make([][]byte, len(r.sub))
	for n, i := range r.sub {
		subs[i] = r.donor[n].pair.pub.Fingerprint
	}
	c.fingerprints = append(c.fingerprints, subs...)
	users := make([]string, len(r.uid))
	for n, i := range r.uid {
		users[i] = r.uidText[n]
	}
	c.users = users
	return c
}

// fkCheckCertificate holds the certificate of a key to the property of the certificate (fkCertProperty), and
// to what the view says it holds: the primary, the user IDs with a valid self-signature and the subkeys
// with a valid binding, in the order of the file, and no other. Where go-crypto reads the file as a key
// ring, it reads the certificate as the same key.
func fkCheckCertificate(t *testing.T, c fkCertCase, k *openpgp.ForeignKey) {
	t.Helper()
	cert := k.Certificate()
	if len(cert) == 0 {
		t.Fatalf("%s: no certificate", c.name)
	}
	secrets := append(slices.Clone(c.numbers), c.regions...)
	ps := fkCertProperty(t, c.name, k, secrets...)
	for _, pass := range []string{fkPass, fkPassOther} {
		if bytes.Contains(cert, []byte(pass)) {
			t.Errorf("%s: the certificate holds a passphrase", c.name)
		}
	}

	// the subkeys with a binding, and the user IDs with a self-signature, and no others
	var wantSubs []string
	for i, s := range k.Subkeys {
		switch {
		case s.InCertificate:
			if s.Fingerprint != hex.EncodeToString(c.fingerprints[1+i]) {
				t.Errorf("%s: subkey %d: the fingerprint %s, want %x", c.name, i, s.Fingerprint, c.fingerprints[1+i])
			}
			wantSubs = append(wantSubs, s.Fingerprint)
		case s.IncompleteBinding:
			// its public bytes were confirmed by a binding that verifies: the view keeps the fingerprint
			if s.Fingerprint != hex.EncodeToString(c.fingerprints[1+i]) {
				t.Errorf("%s: subkey %d has an incomplete binding and the fingerprint %q", c.name, i, s.Fingerprint)
			}
		case s.Fingerprint != "" || s.KeyID != "":
			t.Errorf("%s: subkey %d is left out and has the fingerprint %q", c.name, i, s.Fingerprint)
		}
	}
	if got := fkCertSubkeys(ps); !slices.Equal(got, wantSubs) {
		t.Errorf("%s: the subkeys of the certificate are %v, want those of the view that are in it: %v", c.name, got, wantSubs)
	}
	var wantUsers []string
	for _, u := range k.UserIDs {
		if u.Valid {
			wantUsers = append(wantUsers, u.Text)
		}
	}
	if got := fkCertUsers(ps); !slices.Equal(got, wantUsers) {
		t.Errorf("%s: user IDs %q, want those with a valid self-signature %q", c.name, got, wantUsers)
	}
	if k.Primary.Fingerprint != hex.EncodeToString(c.fingerprints[0]) {
		t.Errorf("%s: the fingerprint of the key is not that of the file", c.name)
	}

	// the file and the certificate as key rings, where go-crypto reads the file
	if c.clean {
		in := fkRingSummary(t, c.name+" file", c.file)
		out := fkRingSummary(t, c.name+" certificate", cert)
		if in.primary != out.primary || !slices.Equal(in.subs, out.subs) || len(in.users) != len(out.users) {
			t.Errorf("%s: go-crypto reads the file as %+v and the certificate as %+v", c.name, in, out)
		}
		for name := range in.users {
			if _, ok := out.users[name]; !ok {
				t.Errorf("%s: go-crypto does not find the user ID %q in the certificate", c.name, name)
			}
		}
	}

	// a copy
	first := bytes.Clone(cert)
	for i := range cert {
		cert[i] ^= 0xFF
	}
	if second := k.Certificate(); !bytes.Equal(second, first) {
		t.Errorf("%s: a change of the returned certificate changed the next one", c.name)
	}
}

// fkRing is what a key ring shows of a key, for a comparison.
type fkRing struct {
	primary string
	subs    []string
	users   map[string]int // the user ID and the number of its signatures
	revoked int
}

func fkRingSummary(t testing.TB, what string, data []byte) fkRing {
	t.Helper()
	ents, err := pgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil || len(ents) != 1 {
		t.Fatalf("%s: go-crypto does not read it: %v (%d keys)", what, err, len(ents))
	}
	e := ents[0]
	r := fkRing{primary: hex.EncodeToString(e.PrimaryKey.Fingerprint), users: map[string]int{}, revoked: len(e.Revocations)}
	for _, s := range e.Subkeys {
		r.subs = append(r.subs, hex.EncodeToString(s.PublicKey.Fingerprint))
	}
	for name, id := range e.Identities {
		r.users[name] = len(id.Signatures)
	}
	return r
}

func TestForeignCertificateOfTemplateFiles(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, v := range fkVariants() {
			file := b.file(t, v.prot)
			if v.hand != nil {
				file = v.hand(t, b)
			}
			t.Run(v.name, func(t *testing.T) {
				c := fkTemplateCase(t, b, v.name, file)
				k := fkRead(t, file)
				fkCheckCertificate(t, c, k)
				// the armoured file gives the same certificate
				ka := fkRead(t, fkArmourKey(t, file))
				if !bytes.Equal(ka.Certificate(), k.Certificate()) {
					t.Error("the armoured file gives another certificate")
				}
			})
		}
	})
}

func TestForeignCertificateOfRichFiles(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, protected := range []bool{false, true} {
			for _, clean := range []bool{true, false} {
				name := "unprotected"
				if protected {
					name = "protected"
				}
				if clean {
					name += "/clean"
				} else {
					name += "/all shapes"
				}
				t.Run(name, func(t *testing.T) {
					r := fkRichOf(t, b, protected, clean)
					c := fkRichCase(t, r, name, clean)
					fkCheckCertificate(t, c, fkRead(t, r.file))
				})
			}
		}
	})
}

// The certificate is written by the reader, so it is the same bytes for every header form of the file,
// for the armoured file, and for a file with trust and marker packets in it.
func TestForeignCertificateIsTheSameForEveryHeaderForm(t *testing.T) {
	b := fkNamed(t, "ed25519")
	r := fkRichOf(t, b, true, true)
	base := fkRead(t, r.file).Certificate()
	for _, form := range []string{"old1", "old2", "old4", "new5", "new2"} {
		file := fkRepackAll(t, r.file, form)
		k := fkRead(t, file)
		c := fkRichCase(t, r, form, true)
		c.file = file
		fkCheckCertificate(t, c, k)
		if !bytes.Equal(k.Certificate(), base) {
			t.Errorf("%s: the certificate is not the certificate of the new-format file", form)
		}
		if !bytes.Equal(fkRead(t, fkArmourKey(t, file)).Certificate(), base) {
			t.Errorf("%s: the armoured file gives another certificate", form)
		}
	}
}

// fkRepackAll writes every packet of a file in a header form where its length fits it. A tag over 15
// has no old-format header and keeps its own.
func fkRepackAll(t testing.TB, file []byte, form string) []byte {
	t.Helper()
	var out []byte
	for _, p := range splitPackets(t, file) {
		if pkt, ok := packetIn(form, p.Tag, p.Body); ok && (p.Tag < 16 || form[:3] == "new") {
			out = append(out, pkt...)
		} else {
			out = append(out, p.Raw...)
		}
	}
	return out
}

// C. The three forms of a subkey.

func TestForeignSubkeyForms(t *testing.T) {
	enc, _, _ := fkDonors(t)
	forms := []struct {
		name string
		form fkSubForm
	}{
		{"public", fkAsPublic},
		{"stub, dummy, usage 255", fkAsDummy},
		{"stub, card with a serial number, usage 255", fkAsCard},
		{"stub, card with a serial number, usage 254", fkAsCard254},
		{"with a secret, unprotected", fkAsSecret},
		{"with a secret, protected by another passphrase", fkAsOtherPass},
		{"protected, with ciphertext of random bytes", fkAsGarbage},
	}
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, protected := range []bool{false, true} {
			prot := fkProt{}
			if protected {
				prot = fkProt{Pass: fkPass}
			}
			want := fkReadGoCrypto(t, b.file(t, prot), prot.Pass)
			head := fkTemplateHead(t, b.file(t, prot))
			for _, f := range forms {
				name := f.name
				if protected {
					name += ", protected primary"
				}
				t.Run(name, func(t *testing.T) {
					d := enc[0]
					binding := fkSplit(t, b.subSig(t, b.primaryPair(), d.pair.pub, fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding, Flags: 0x0C}))[0]
					sub := d.packet(t, f.form)
					file := fkJoin(append(slices.Clone(head), sub, binding)...)
					k := fkRead(t, file)
					if len(k.Subkeys) != 1 {
						t.Fatalf("%d subkeys, want 1", len(k.Subkeys))
					}
					s := k.Subkeys[0]
					if s.Form != f.form.wantForm() {
						t.Errorf("form %v, want %v", s.Form, f.form.wantForm())
					}
					if s.Fingerprint != hex.EncodeToString(d.pair.pub.Fingerprint) || s.KeyID != s.Fingerprint[24:] {
						t.Errorf("fingerprint %s and key ID %s, want %x", s.Fingerprint, s.KeyID, d.pair.pub.Fingerprint)
					}
					if s.Algorithm != d.want || s.Algorithm.String() != "ECDH Curve25519" {
						t.Errorf("algorithm %+v (%s), want %+v", s.Algorithm, s.Algorithm, d.want)
					}
					if !s.Created.Equal(fkEpoch.Add(3600 * 1e9)) {
						t.Errorf("created %v, want an hour after %v", s.Created, fkEpoch)
					}
					if !s.Bound || s.Revoked || s.Flags != 0x0C || len(s.Signatures) != 1 || s.Signatures[0].Status != openpgp.SignatureValid || s.OtherSignatures != 0 {
						t.Errorf("binding fields %+v", s)
					}
					if len(k.UserIDs) != 1 || !k.UserIDs[0].Valid {
						t.Errorf("the user ID is not read: %+v", k.UserIDs)
					}

					// the secret of the subkey is never needed: the primary opens with its own passphrase
					secret, err := k.OpenSecret([]byte(prot.Pass))
					if err != nil {
						t.Fatalf("OpenSecret with a subkey that is %s: %v", f.name, err)
					}
					fkAgrees(t, secret.Signer(), want)
					fkSignAndVerify(t, secret.Signer(), fkCertPublic(t, k.Certificate()))
					secret.Wipe()
					// and the other passphrase, which belongs to a subkey, does not open the primary
					if protected {
						if _, err := k.OpenSecret([]byte(fkPassOther)); err == nil {
							t.Error("the passphrase of a subkey opens the primary")
						}
					}

					// the certificate holds the public subkey packet of every form
					wantSub := wrap(14, d.pub.Body)
					if !bytes.Contains(k.Certificate(), wantSub) {
						t.Error("the certificate lacks the public subkey packet")
					}
					c := fkCertCase{name: name, b: b, file: file, clean: false,
						fingerprints: [][]byte{b.ent.PrimaryKey.Fingerprint, d.pair.pub.Fingerprint}, users: []string{fkUser}}
					c.numbers = append(slices.Clone(b.secrets(t).Primary), fkReadMPIs(t, d.sec.Body[len(d.pub.Body)+1:])...)
					if f.form != fkAsPublic {
						c.regions = [][]byte{sub.Body[len(d.pub.Body):]}
					}
					fkCheckCertificate(t, c, k)

					// no serial number anywhere: not in a field, not in the certificate
					for _, hay := range fkStrings(k) {
						for _, form := range fkHexForms(fkSerial) {
							if bytes.Contains(hay, form) {
								t.Fatalf("the serial number of a stub is in what the reader returns: %q", hay)
							}
						}
					}
				})
			}
		}
	})
}

// A secret subkey whose algorithm the reader cannot delimit is refused by name, and a public subkey of
// such an algorithm is read, with a binding that cannot be checked.
func TestForeignSubkeyOfUnknownAlgorithm(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, _, _ := fkDonors(t)
	file := b.file(t, fkProt{})
	ps := fkSplit(t, file)
	// the body of a subkey of the algorithm 99 with one number
	body := []byte{4, 0x65, 0x53, 0xF1, 0x00, 99, 0, 8, 0xAB}
	binding := ps[4] // the binding of the encryption subkey of the template: the issuer is the primary
	_ = enc

	secret := fkJoin(ps[0], ps[1], ps[2], fkPacket{7, append(bytes.Clone(body), 0, 0, 0)}, binding)
	err := fkRefused(t, "a secret subkey of an algorithm that is not delimited", secret, b, openpgp.ErrForeignAlgorithm)
	if err != nil && !bytes.Contains([]byte(err.Error()), []byte("99")) {
		t.Errorf("the text does not name the algorithm: %v", err)
	}

	public := fkJoin(ps[0], ps[1], ps[2], fkPacket{14, body}, binding)
	k := fkRead(t, public)
	if len(k.Subkeys) != 1 || k.Subkeys[0].Form != openpgp.SubkeyPublic || k.Subkeys[0].Algorithm.ID != 99 || k.Subkeys[0].Algorithm.String() != "algorithm 99" {
		t.Fatalf("subkeys %+v", k.Subkeys)
	}
	if k.Subkeys[0].Bound {
		t.Error("a binding of a key that cannot be read is counted")
	}
	if got := k.Subkeys[0].Signatures; len(got) != 1 || got[0].Status != openpgp.SignatureUnreadable {
		t.Errorf("signatures %+v, want one that is unreadable", got)
	}
}

// A subkey that is not a version 4 key is refused, public or secret.
func TestForeignSubkeyVersions(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, _, _ := fkDonors(t)
	ps := fkSplit(t, b.file(t, fkProt{}))
	for _, v := range []byte{3, 5, 6, 9} {
		for _, form := range []fkSubForm{fkAsPublic, fkAsSecret} {
			sub := enc[0].packet(t, form)
			body := bytes.Clone(sub.Body)
			body[0] = v
			file := fkJoin(ps[0], ps[1], ps[2], fkPacket{sub.Tag, body}, ps[4])
			if form == fkAsSecret {
				// a damaged secret key packet refuses the file
				_ = fkRefused(t, "a secret subkey of another version", file, b, openpgp.ErrForeignVersion)
				continue
			}
			// a public subkey packet that does not read is left out and reported, and is no reason to refuse
			k := fkRead(t, file)
			if len(k.Subkeys) != 1 || k.Subkeys[0].InCertificate || k.Subkeys[0].Fingerprint != "" {
				t.Errorf("a public subkey of version %d: %+v", v, k.Subkeys)
			}
			_ = fkCertProperty(t, "a public subkey of another version", k)
		}
	}
}

// The search for a leak finds a run of eight bytes of a number wherever it stands, and nothing else:
// the tests of the certificate and of the error texts rest on it.
func TestForeignLeakSearch(t *testing.T) {
	n := fkRandom(t, 40)
	n[0] |= 1
	other := fkRandom(t, 40)
	hay := append(append(bytes.Clone(other), n[13:21]...), other...)
	if _, bad := fkLeaks(hay, n); !bad {
		t.Error("a run of eight bytes of the number is not found")
	}
	if _, bad := fkLeaks(append(bytes.Clone(other), n[13:20]...), n); bad && !bytes.Contains(other, n[13:20]) {
		t.Error("a run of seven bytes is found")
	}
	if _, bad := fkLeaks(other, n); bad {
		t.Error("a leak is found in bytes that hold none")
	}
	short := []byte{1, 2, 3}
	if _, bad := fkLeaks([]byte{9, 1, 2, 3, 9}, short); !bad {
		t.Error("a short number is not found whole")
	}
	if _, bad := fkLeaks(nil, nil, []byte{}); bad {
		t.Error("an empty number is found")
	}
}
