package openpgp_test

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The shapes of a long-lived key: many user IDs and subkeys, signatures of every kind. They are made
// from a template by go-crypto's signing code, with the knobs of a signature set one by one, and from
// donor subkeys that are attached to any primary. No shape is written to a file.

// fkKeyPair is a key that signs: its public packet and its private key, unprotected.
type fkKeyPair struct {
	pub  *gpacket.PublicKey
	priv *gpacket.PrivateKey
}

// primaryPair is the key of a template that signs the self-signatures.
func (b *fkBase) primaryPair() fkKeyPair {
	return fkKeyPair{b.ent.PrimaryKey, b.ent.PrivateKey}
}

// fkSigSpec holds the knobs of a signature that the tests make.
type fkSigSpec struct {
	Typ     gpacket.SignatureType
	Hash    crypto.Hash // zero: SHA-256
	At      time.Time   // zero: fkEpoch plus fkSigOffset
	Life    uint32      // signature expiration time, seconds
	KeyLife uint32      // key expiration time, seconds
	Flags   byte        // first octet of the key flags
	Primary bool        // the primary user ID flag
	Reason  *gpacket.ReasonForRevocation
	// Critical adds a notation that is marked critical, which the reader does not understand.
	Critical bool
	// Back is the embedded back-signature of a binding.
	Back *gpacket.Signature
}

// fkSigAt is a time after the creation of the keys, at a distance in seconds.
func fkSigAt(secs int) time.Time { return fkEpoch.Add(time.Duration(secs) * time.Second) }

func (s fkSigSpec) signature(signer fkKeyPair) *gpacket.Signature {
	h := s.Hash
	if h == 0 {
		h = crypto.SHA256
	}
	at := s.At
	if at.IsZero() {
		at = fkSigAt(1000)
	}
	id := signer.pub.KeyId
	sg := &gpacket.Signature{
		Version:      4,
		SigType:      s.Typ,
		PubKeyAlgo:   signer.pub.PubKeyAlgo,
		Hash:         h,
		CreationTime: at,
		IssuerKeyId:  &id,
	}
	if s.Life != 0 {
		l := s.Life
		sg.SigLifetimeSecs = &l
	}
	if s.KeyLife != 0 {
		l := s.KeyLife
		sg.KeyLifetimeSecs = &l
	}
	if s.Flags != 0 {
		sg.FlagsValid = true
		sg.FlagCertify = s.Flags&gpacket.KeyFlagCertify != 0
		sg.FlagSign = s.Flags&gpacket.KeyFlagSign != 0
		sg.FlagEncryptCommunications = s.Flags&gpacket.KeyFlagEncryptCommunications != 0
		sg.FlagEncryptStorage = s.Flags&gpacket.KeyFlagEncryptStorage != 0
		sg.FlagAuthenticate = s.Flags&gpacket.KeyFlagAuthenticate != 0
	}
	if s.Primary {
		p := true
		sg.IsPrimaryId = &p
	}
	sg.RevocationReason = s.Reason
	if s.Reason != nil {
		sg.RevocationReasonText = "a test reason"
	}
	if s.Critical {
		sg.Notations = []*gpacket.Notation{{Name: "unknown@example.org", Value: []byte("v"), IsHumanReadable: true, IsCritical: true}}
	}
	sg.EmbeddedSignature = s.Back
	return sg
}

// fkSerialize writes a signature as a packet.
func fkSerializeSig(t testing.TB, sg *gpacket.Signature) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := sg.Serialize(&buf); err != nil {
		t.Fatalf("serialise a signature: %v", err)
	}
	return buf.Bytes()
}

// certSig is a certification (or its revocation) of a user ID of target by signer.
func (b *fkBase) certSig(t testing.TB, signer fkKeyPair, target *gpacket.PublicKey, uid string, s fkSigSpec) []byte {
	t.Helper()
	sg := s.signature(signer)
	if err := sg.SignUserId(uid, target, signer.priv, b.cfg); err != nil {
		t.Fatalf("sign a user ID: %v", err)
	}
	return fkSerializeSig(t, sg)
}

// keySig is a direct-key signature or a key revocation of target by signer.
func (b *fkBase) keySig(t testing.TB, signer fkKeyPair, target *gpacket.PublicKey, s fkSigSpec) []byte {
	t.Helper()
	sg := s.signature(signer)
	var err error
	switch s.Typ {
	case gpacket.SigTypeKeyRevocation:
		err = sg.RevokeKey(target, signer.priv, b.cfg)
	default:
		err = sg.SignDirectKeyBinding(target, signer.priv, b.cfg)
	}
	if err != nil {
		t.Fatalf("sign a key: %v", err)
	}
	return fkSerializeSig(t, sg)
}

// subSig is a binding or a revocation of a subkey by signer.
func (b *fkBase) subSig(t testing.TB, signer fkKeyPair, sub *gpacket.PublicKey, s fkSigSpec) []byte {
	t.Helper()
	sg := s.signature(signer)
	var err error
	switch s.Typ {
	case gpacket.SigTypeSubkeyRevocation:
		err = sg.RevokeSubkey(sub, signer.priv, b.cfg)
	default:
		err = sg.SignKey(sub, signer.priv, b.cfg)
	}
	if err != nil {
		t.Fatalf("sign a subkey: %v", err)
	}
	return fkSerializeSig(t, sg)
}

// backSig is the back-signature that a signing subkey makes over the primary.
func (b *fkBase) backSig(t testing.TB, sub fkDonorKey, at time.Time) *gpacket.Signature {
	t.Helper()
	id := sub.pair.pub.KeyId
	sg := &gpacket.Signature{
		Version:      4,
		SigType:      gpacket.SigTypePrimaryKeyBinding,
		PubKeyAlgo:   sub.pair.pub.PubKeyAlgo,
		Hash:         crypto.SHA256,
		CreationTime: at,
		IssuerKeyId:  &id,
	}
	if err := sg.CrossSignKey(sub.pair.pub, b.ent.PrimaryKey, sub.pair.priv, b.cfg); err != nil {
		t.Fatalf("sign a back-signature: %v", err)
	}
	return sg
}

// fkDonorKey is a subkey with its public and secret packets, ready to be attached to a primary.
type fkDonorKey struct {
	pair fkKeyPair
	// pub is the public subkey packet, sec the secret subkey packet, unprotected.
	pub, sec fkPacket
	want     openpgp.ForeignAlgorithm
}

var (
	fkDonorOnce sync.Once
	fkDonorEnc  []fkDonorKey
	fkDonorSig  []fkDonorKey
	fkCertifier fkKeyPair
	fkDonorErr  error
)

func fkDonorOf(sub pgp.Subkey, want openpgp.ForeignAlgorithm) (fkDonorKey, error) {
	var pubBuf, secBuf bytes.Buffer
	if err := sub.PublicKey.Serialize(&pubBuf); err != nil {
		return fkDonorKey{}, err
	}
	if err := sub.PrivateKey.Serialize(&secBuf); err != nil {
		return fkDonorKey{}, err
	}
	pub, err := fkSplitErr(pubBuf.Bytes())
	if err != nil {
		return fkDonorKey{}, err
	}
	sec, err := fkSplitErr(secBuf.Bytes())
	if err != nil {
		return fkDonorKey{}, err
	}
	if len(pub) != 1 || len(sec) != 1 {
		return fkDonorKey{}, fmt.Errorf("a subkey is not one packet")
	}
	return fkDonorKey{
		pair: fkKeyPair{sub.PublicKey, sub.PrivateKey},
		pub:  fkPacket{14, pub[0].Body},
		sec:  fkPacket{7, sec[0].Body},
		want: want,
	}, nil
}

// fkSplitErr is fkSplit for the setup of the donors, which has no test to fail.
func fkSplitErr(b []byte) ([]fkPacket, error) {
	var out []fkPacket
	for len(b) > 0 {
		if len(b) < 2 || b[0]&0x80 == 0 || b[0]&0x40 == 0 {
			return nil, fmt.Errorf("not a new-format packet")
		}
		tag := b[0] & 0x3F
		var n, hl int
		switch l := int(b[1]); {
		case l < 192:
			n, hl = l, 2
		case l < 224:
			n, hl = (l-192)<<8+int(b[2])+192, 3
		case l == 255:
			n, hl = int(b[2])<<24|int(b[3])<<16|int(b[4])<<8|int(b[5]), 6
		default:
			return nil, fmt.Errorf("a partial length")
		}
		if hl+n > len(b) {
			return nil, fmt.Errorf("a packet runs past the end")
		}
		out = append(out, fkPacket{tag, bytes.Clone(b[hl : hl+n])})
		b = b[hl+n:]
	}
	return out, nil
}

// fkDonors returns the donor subkeys, made once: ECDH subkeys for encryption, EdDSA subkeys for
// signing, and a key that certifies for others. They hang on one Ed25519 key that is never a primary
// in the tests, and they are created an hour after the primaries.
func fkDonors(t testing.TB) (enc, sig []fkDonorKey, certifier fkKeyPair) {
	t.Helper()
	fkDonorOnce.Do(func() {
		cfg := fkConfig(gpacket.PubKeyAlgoEdDSA, gpacket.Curve25519, 0)
		cfg.Time = func() time.Time { return fkEpoch.Add(time.Hour) }
		e, err := pgp.NewEntity("Donor Tester", "", "donor@example.org", cfg)
		if err != nil {
			fkDonorErr = err
			return
		}
		for i := 0; i < 15; i++ {
			if err := e.AddEncryptionSubkey(cfg); err != nil {
				fkDonorErr = err
				return
			}
		}
		for i := 0; i < 2; i++ {
			if err := e.AddSigningSubkey(cfg); err != nil {
				fkDonorErr = err
				return
			}
		}
		for i, s := range e.Subkeys {
			if i < 16 {
				d, err := fkDonorOf(s, openpgp.ForeignAlgorithm{ID: 18, Curve: "Curve25519"})
				if err != nil {
					fkDonorErr = err
					return
				}
				fkDonorEnc = append(fkDonorEnc, d)
			} else {
				d, err := fkDonorOf(s, openpgp.ForeignAlgorithm{ID: 22, Curve: "Ed25519"})
				if err != nil {
					fkDonorErr = err
					return
				}
				fkDonorSig = append(fkDonorSig, d)
			}
		}
		fkCertifier = fkKeyPair{e.PrimaryKey, e.PrivateKey}
	})
	if fkDonorErr != nil {
		t.Fatalf("make the donor subkeys: %v", fkDonorErr)
	}
	return fkDonorEnc, fkDonorSig, fkCertifier
}

// protectedSecret is the secret subkey packet of a donor, protected by a passphrase of go-crypto.
func (d fkDonorKey) protectedSecret(t testing.TB, pass string) fkPacket {
	t.Helper()
	p, err := gpacket.Read(bytes.NewReader(wrap(7, d.sec.Body)))
	if err != nil {
		t.Fatal(err)
	}
	k, ok := p.(*gpacket.PrivateKey)
	if !ok {
		t.Fatalf("a %T, want a private key", p)
	}
	if err := k.Encrypt([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := k.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	ps := fkSplit(t, buf.Bytes())
	return fkPacket{7, ps[0].Body}
}

// The three forms of a secret subkey that carry no secret or a secret that is not read.

// fkStubRegion is the GNU extension that says that the secret is not in the file. usage is 254 or 255,
// mode 1 is a dummy and mode 2 a card, which is followed by the length and the bytes of a serial.
func fkStubRegion(usage, mode byte, serial []byte) []byte {
	r := []byte{usage, 0, 101, 2, 'G', 'N', 'U', mode}
	if mode == 2 {
		r = append(r, byte(len(serial)))
		r = append(r, serial...)
	}
	return r
}

// fkSerial is a serial number that is easy to find: no key, error or field may hold it.
var fkSerial = []byte("TESTCARDSERIAL-0042")

// fkSubForm names how a donor subkey is put in a file.
type fkSubForm int

const (
	fkAsPublic fkSubForm = iota
	fkAsDummy
	fkAsCard
	fkAsCard254
	fkAsSecret
	fkAsOtherPass
	fkAsGarbage
)

// packet writes a donor subkey in a form.
func (d fkDonorKey) packet(t testing.TB, f fkSubForm) fkPacket {
	t.Helper()
	switch f {
	case fkAsPublic:
		return d.pub
	case fkAsDummy:
		return fkPacket{7, append(bytes.Clone(d.pub.Body), fkStubRegion(255, 1, nil)...)}
	case fkAsCard:
		return fkPacket{7, append(bytes.Clone(d.pub.Body), fkStubRegion(255, 2, fkSerial)...)}
	case fkAsCard254:
		return fkPacket{7, append(bytes.Clone(d.pub.Body), fkStubRegion(254, 2, fkSerial)...)}
	case fkAsSecret:
		return d.sec
	case fkAsOtherPass:
		return d.protectedSecret(t, fkPassOther)
	case fkAsGarbage:
		// a secret region of the length of the real one, with nothing in it that means anything
		n := len(d.sec.Body) - len(d.pub.Body)
		g := fkRandom(t, n)
		g[0] = 0 // not a stub: an unprotected secret with a wrong checksum
		return fkPacket{7, append(bytes.Clone(d.pub.Body), g...)}
	}
	t.Fatalf("no such form %d", f)
	return fkPacket{}
}

// wantForm is the form that the reader must report for a form of the file.
func (f fkSubForm) wantForm() openpgp.SubkeyForm {
	switch f {
	case fkAsPublic:
		return openpgp.SubkeyPublic
	case fkAsDummy, fkAsCard, fkAsCard254:
		return openpgp.SubkeyStub
	}
	return openpgp.SubkeyWithSecret
}

// fkTemplatePrimary is the packets of a template file up to and with the self-signature of its user
// ID: the primary, the user ID and its signature.
func fkTemplateHead(t testing.TB, file []byte) []fkPacket {
	t.Helper()
	ps := fkSplit(t, file)
	if len(ps) < 3 || ps[0].Tag != 5 || ps[1].Tag != 13 || ps[2].Tag != 2 {
		t.Fatalf("the template does not start with a primary, a user ID and a signature")
	}
	return ps[:3]
}

// fkAttribute is a user attribute packet with one image subpacket of n random bytes of content.
func fkAttribute(t testing.TB, n int) fkPacket {
	t.Helper()
	l := n + 1
	var enc []byte
	if l < 192 {
		enc = []byte{byte(l)}
	} else {
		enc = []byte{byte((l-192)>>8) + 192, byte(l - 192)}
	}
	body := append(slices.Clone(enc), 1)
	return fkPacket{17, append(body, fkRandom(t, n)...)}
}

// fkRich is a file with many shapes at once, and the names of its parts.
type fkRich struct {
	b    *fkBase
	file []byte
	// uid and sub map a short name to the index of the user ID or the subkey in the file.
	uid, sub map[string]int
	uidText  map[string]string
	donor    map[string]fkDonorKey
	form     map[string]fkSubForm
	// numbers are the secret numbers of the primary and of every subkey with a secret, regions the
	// bytes of every secret region that the file holds: of the primary if it is protected, of the
	// subkeys that are protected, garbage or stubs.
	numbers [][]byte
	regions [][]byte
	// attrs and attrBytes are the user attribute packets and the sum of their bodies.
	attrs, attrBytes int
}

// fkRichUserID is the user ID of a short name.
func fkRichUserID(name string) string { return fmt.Sprintf("%s person <%s@example.org>", name, name) }

// fkRichUsers are the user IDs of the rich file, in the order of the file.
var fkRichUsers = []string{"primary", "revoked", "expiring", "weak", "notaccepted", "critical", "tampered",
	"certified", "renewed", "samesecond", "newest", "equal", "misplaced", "bare"}

// fkRichSubs are the subkeys of the rich file, in the order of the file.
var fkRichSubs = []string{"valid", "expired", "revoked", "rebound", "revokedonly", "nobacksig", "backsig", "other",
	"twobind", "public", "dummy", "card", "card254", "otherpass", "garbage", "weakbind", "misplaced"}

// fkBuildRich makes the rich file of a template with the protection given to its primary.
//
// With clean set it leaves out what go-crypto refuses to read as a key ring: a signature that does not
// verify, a weak one, a misplaced one, a subkey with a garbage secret, a subkey with a card stub
// (go-crypto 1.5.2 does not skip the serial number of one), a subkey with no binding first or only the
// binding of another key. What is left reads in both.
func fkBuildRich(t testing.TB, b *fkBase, prot fkProt, clean bool) *fkRich {
	t.Helper()
	enc, sig, other := fkDonors(t)
	me := b.primaryPair()
	r := &fkRich{b: b, uid: map[string]int{}, sub: map[string]int{}, uidText: map[string]string{},
		donor: map[string]fkDonorKey{}, form: map[string]fkSubForm{}}
	var ps []fkPacket
	addRaw := func(raw []byte) {
		ps = append(ps, fkSplit(t, raw)...)
	}

	primary := fkSplit(t, b.file(t, prot))[0]
	ps = append(ps, primary)
	r.numbers = append(r.numbers, b.secrets(t).Primary...)
	if prot.Pass != "" {
		r.regions = append(r.regions, primary.Body[len(b.pubBody(t)):])
	}

	// The key itself: a direct-key signature, a key revocation, a signature of another type, and a
	// revocation of another key.
	addRaw(b.keySig(t, me, me.pub, fkSigSpec{Typ: gpacket.SigTypeDirectSignature, At: fkSigAt(900), Flags: 3, KeyLife: 100 * 86400}))
	kc := gpacket.KeyCompromised
	addRaw(b.keySig(t, me, me.pub, fkSigSpec{Typ: gpacket.SigTypeKeyRevocation, At: fkSigAt(1500), Reason: &kc}))
	if !clean {
		addRaw(b.keySig(t, me, me.pub, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1000)}))
	}
	if !clean {
		addRaw(b.keySig(t, other, me.pub, fkSigSpec{Typ: gpacket.SigTypeKeyRevocation, At: fkSigAt(1600)}))
	}

	cert := func(name string, s fkSigSpec) []byte {
		return b.certSig(t, me, me.pub, fkRichUserID(name), s)
	}
	uidPacket := func(name string) {
		r.uid[name] = len(r.uid)
		r.uidText[name] = fkRichUserID(name)
		ps = append(ps, fkPacket{13, []byte(fkRichUserID(name))})
	}
	unvalid := gpacket.UserIDNotValid
	for _, name := range fkRichUsers {
		if clean && (name == "weak" || name == "notaccepted" || name == "critical" || name == "tampered" || name == "misplaced") {
			continue
		}
		uidPacket(name)
		switch name {
		case "primary":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, Flags: 3, KeyLife: 365 * 86400, Primary: true}))
			// a photograph that the primary certified: counted and not read
			a := fkAttribute(t, 100)
			ps = append(ps, a)
			r.attrs++
			r.attrBytes += len(a.Body)
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1001)}))
		case "revoked":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert}))
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypeCertificationRevocation, At: fkSigAt(1100), Reason: &unvalid}))
		case "expiring":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, Life: 100}))
		case "weak":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, Hash: crypto.SHA1}))
		case "notaccepted":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, Hash: crypto.SHA224}))
		case "critical":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, Critical: true}))
		case "tampered":
			raw := cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert})
			raw[len(raw)-1] ^= 1
			addRaw(raw)
		case "certified":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert}))
			addRaw(b.certSig(t, other, me.pub, fkRichUserID(name), fkSigSpec{Typ: gpacket.SigTypeGenericCert}))
			addRaw(b.certSig(t, other, me.pub, fkRichUserID(name), fkSigSpec{Typ: gpacket.SigTypeCasualCert, At: fkSigAt(1010)}))
			addRaw(b.certSig(t, other, me.pub, fkRichUserID(name), fkSigSpec{Typ: gpacket.SigTypeCertificationRevocation, At: fkSigAt(1020)}))
		case "renewed":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypeCertificationRevocation, At: fkSigAt(1000)}))
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1050)}))
		case "samesecond":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1010)}))
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypeCertificationRevocation, At: fkSigAt(1010)}))
		case "newest":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1200), Flags: 1}))
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1100), Flags: 3, Primary: true}))
		case "equal":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1300), Flags: 1}))
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1300), Flags: 2}))
		case "misplaced":
			addRaw(cert(name, fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding}))
		case "bare":
			// a second photograph, with no signature
			a := fkAttribute(t, 250)
			ps = append(ps, a)
			r.attrs++
			r.attrBytes += len(a.Body)
		}
	}

	// The subkeys.
	next := 0
	bind := func(d fkDonorKey, s fkSigSpec) []byte { return b.subSig(t, me, d.pair.pub, s) }
	for _, name := range fkRichSubs {
		if clean && (name == "nobacksig" || name == "weakbind" || name == "misplaced" || name == "garbage" || name == "revokedonly" || name == "other" || name == "rebound" || name == "card" || name == "card254") {
			continue
		}
		form := fkAsSecret
		switch name {
		case "public":
			form = fkAsPublic
		case "dummy":
			form = fkAsDummy
		case "card":
			form = fkAsCard
		case "card254":
			form = fkAsCard254
		case "otherpass":
			form = fkAsOtherPass
		case "garbage":
			form = fkAsGarbage
		}
		var d fkDonorKey
		switch name {
		case "nobacksig":
			d = sig[0]
		case "backsig":
			d = sig[1]
		default:
			d = enc[next]
			next++
		}
		r.sub[name] = len(r.sub)
		r.donor[name] = d
		r.form[name] = form
		pkt := d.packet(t, form)
		ps = append(ps, pkt)
		if form != fkAsPublic {
			r.regions = append(r.regions, bytes.Clone(pkt.Body[len(d.pub.Body):]))
		}
		if form == fkAsSecret || form == fkAsOtherPass || form == fkAsGarbage {
			r.numbers = append(r.numbers, fkReadMPIs(t, d.sec.Body[len(d.pub.Body)+1:])...)
		}
		sp := fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding, Flags: 0x0C}
		switch name {
		case "valid":
			sp.KeyLife = 30 * 86400
			addRaw(bind(d, sp))
		case "expired":
			sp.Life, sp.KeyLife = 60, 60
			addRaw(bind(d, sp))
		case "revoked":
			addRaw(bind(d, sp))
			ret := gpacket.KeyRetired
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypeSubkeyRevocation, At: fkSigAt(1010), Reason: &ret}))
		case "rebound":
			ret := gpacket.KeyRetired
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypeSubkeyRevocation, At: fkSigAt(1000), Reason: &ret}))
			sp.At = fkSigAt(1010)
			addRaw(bind(d, sp))
		case "revokedonly":
			ret := gpacket.KeyRetired
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypeSubkeyRevocation, At: fkSigAt(1000), Reason: &ret}))
		case "nobacksig":
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding, Flags: 0x02}))
		case "backsig":
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding, Flags: 0x02, Back: b.backSig(t, d, fkSigAt(1000))}))
		case "other":
			addRaw(b.subSig(t, other, d.pair.pub, sp))
		case "twobind":
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding, Flags: 0x08, At: fkSigAt(1005)}))
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypeSubkeyBinding, Flags: 0x04, At: fkSigAt(1000)}))
		case "weakbind":
			sp.Hash = crypto.SHA1
			addRaw(bind(d, sp))
		case "misplaced":
			addRaw(bind(d, fkSigSpec{Typ: gpacket.SigTypePositiveCert}))
		default:
			addRaw(bind(d, sp))
		}
	}
	r.file = fkJoin(ps...)
	return r
}

var (
	fkRichMu    sync.Mutex
	fkRichCache = map[string]*fkRich{}
)

// fkRichOf returns the rich file of a template and a protection, made once for the test binary.
func fkRichOf(t testing.TB, b *fkBase, protected, clean bool) *fkRich {
	t.Helper()
	key := fmt.Sprintf("%s/%v/%v", b.name, protected, clean)
	fkRichMu.Lock()
	defer fkRichMu.Unlock()
	if r, ok := fkRichCache[key]; ok {
		return r
	}
	prot := fkProt{}
	if protected {
		prot = fkProt{Pass: fkPass}
	}
	r := fkBuildRich(t, b, prot, clean)
	fkRichCache[key] = r
	return r
}
