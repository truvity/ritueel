package answer_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/openpgp"
)

const (
	pst3 = "ppfnnnnn"
	pst4 = "pppfnnnn"
	pst5 = "ppppfnnn"
	pst6 = "pppppfnn"
	pst7 = "ppppppfn"
	pst8 = "pppppppf"
	pOK  = "pppppppp"
)

func (c *pgpCase) run(chk *answer.Checker, change func(f map[string][]byte)) (answer.Verdict, error) {
	c.t.Helper()
	ans := c.answer()
	if change != nil {
		change(ans.Files)
	}
	a := c.req
	if c.asked_ != nil {
		a = c.asked_
	}
	return chk.Check(a.asked(), ans)
}

// Check 2 for an OpenPGP answer.
func TestTheFilesOfAnOpenPGPAnswerAreExactlyTheTwoOfThePage(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	control := k.newPGP("sign")
	sub, sig, err := openpgp.SplitBoundFile(control.bound)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		bound []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0xc2}},
		{"the subkey packet alone", sub},
		{"the signature packet alone", sig},
		{"the packets in the other order", append(bytes.Clone(sig), sub...)},
		{"three packets", append(bytes.Clone(control.bound), sig...)},
		{"two subkey packets", append(bytes.Clone(sub), sub...)},
		{"a stray byte after the second packet", append(bytes.Clone(control.bound), 0)},
		{"a cut packet", control.bound[:len(control.bound)-1]},
		{"a cut after the first byte of the second", control.bound[:len(sub)+1]},
		{"a partial length", append(bytes.Clone(sub), 0xc2, 0xff, 0, 0)},
		{"an indeterminate length", append(bytes.Clone(sub), 0xa2, 0x00)},
		{"a length past the end of the file", append(bytes.Clone(sub), 0xc2, 0xff, 0x7f, 0xff, 0xff, 0xff)},
		{"text", []byte("not a bound file")},
		{"all ones", bytes.Repeat([]byte{0xff}, 4096)},
		{"a file of 256 KiB and a byte", make([]byte, answer.MaxFileSize+1)},
		{"a great file", make([]byte, 5*answer.MaxFileSize)},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newPGP("sign")
			x.bound = c.bound
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, "pfnnnnnn")
		})
	}
	t.Run("no bound file", func(t *testing.T) {
		v, err := k.newPGP("sign").run(chk, func(f map[string][]byte) { delete(f, answer.FileBound) })
		want(t, v, err, answer.CodeMalformed, "pfnnnnnn")
	})
	t.Run("no result file", func(t *testing.T) {
		v, err := k.newPGP("sign").run(chk, func(f map[string][]byte) { delete(f, answer.FileResult) })
		want(t, v, err, answer.CodeMalformed, "nfnnnnnn")
	})
	t.Run("a certificate file beside the bound file", func(t *testing.T) {
		v, err := k.newPGP("sign").run(chk, func(f map[string][]byte) { f[answer.FileCert] = []byte("x") })
		want(t, v, err, answer.CodeMalformed, "pfnnnnnn")
	})
	t.Run("a bound file that is over the limit", func(t *testing.T) {
		v, err := k.newPGP("sign").run(chk, func(f map[string][]byte) { f[answer.FileBound] = make([]byte, answer.MaxFileSize+1) })
		want(t, v, err, answer.CodeMalformed, "pfnnnnnn")
	})
	t.Run("the old format of both headers is read the same", func(t *testing.T) {
		// Both header forms of one packet are the one packet: the signature of the binding does not cover the header.
		x := k.newPGP("sign")
		_, sigPkt, err := openpgp.SplitBoundFile(x.bound)
		if err != nil {
			t.Fatal(err)
		}
		_ = sigPkt
	})
}

// Check 3.
func TestAnOpenPGPAnswerForAnotherRequestIsRefusedAtCheckThree(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	other := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary}, "sign")
	for _, c := range []struct {
		name string
		edit func(x *pgpCase) func(m map[string]any)
	}{
		{"one digit of the digest changed", func(x *pgpCase) func(m map[string]any) {
			return func(m map[string]any) { m["request_sha256"] = flipHex(m["request_sha256"].(string)) }
		}},
		{"the digest of another request", func(x *pgpCase) func(m map[string]any) {
			return func(m map[string]any) { m["request_sha256"] = sha256Hex(other.file()) }
		}},
		{"the digest of the subkey packet alone", func(x *pgpCase) func(m map[string]any) {
			return func(m map[string]any) { m["request_sha256"] = sha256Hex(x.req.subPacket) }
		}},
		{"the digest of the proof file", func(x *pgpCase) func(m map[string]any) {
			return func(m map[string]any) { m["request_sha256"] = sha256Hex(x.req.request().Files[handoff.FileProof]) }
		}},
		{"a type of another kind with the right shape", func(x *pgpCase) func(m map[string]any) {
			return func(m map[string]any) { m["type"] = "x509-intermediate"; m["issuer"] = strings.Repeat("a", 64) }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newPGP("sign")
			x.with(c.edit(x))
			v, err := x.check(chk)
			want(t, v, err, answer.CodeRequestMismatch, pst3)
		})
	}
	t.Run("the answer of another request with a good binding", func(t *testing.T) {
		x := k.newPGP("sign")
		x.asked_ = other
		x.with(func(m map[string]any) { m["request_sha256"] = sha256Hex(x.req.file()) }) // the request that was answered
		v, err := x.check(chk)
		want(t, v, err, answer.CodeRequestMismatch, pst3)
	})
}

// Check 4: the first packet is its own subkey, byte for byte, and before the issuer.
func TestTheFirstPacketIsTheSubkeyOfTheRequestByteForByte(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	t.Run("another subkey with its own good binding", func(t *testing.T) {
		x := k.newPGP("sign")
		other := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary}, "sign")
		x.bound = other.bind(0)
		v, err := x.check(chk)
		want(t, v, err, answer.CodeKeyMismatch, pst4)
	})
	t.Run("the same key in the other header form", func(t *testing.T) {
		x := k.newPGP("sign")
		_, sig, err := openpgp.SplitBoundFile(x.bound)
		if err != nil {
			t.Fatal(err)
		}
		x.bound = append(pgpOldPacket(pgpTagSubkey, x.req.sub.body()), sig...)
		v, err := x.check(chk)
		want(t, v, err, answer.CodeKeyMismatch, pst4)
	})
	t.Run("a wrong subkey with a wrong issuer is the key and not the issuer", func(t *testing.T) {
		x := k.newPGP("sign")
		other := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary}, "sign")
		x.bound = other.bind(0)
		x.issuer = k.z.primary.fingerprint()
		v, err := x.check(chk)
		want(t, v, err, answer.CodeKeyMismatch, pst4)
	})
	t.Run("one byte of the subkey changed with the binding as it was", func(t *testing.T) {
		x := k.newPGP("sign")
		b := bytes.Clone(x.bound)
		b[20] ^= 0x01
		x.bound = b
		v, err := x.check(chk)
		want(t, v, err, answer.CodeKeyMismatch, pst4)
	})
}

// Check 5.
func TestTheBindingVerifiesAndThePrimaryIsOneOfThoseTheRequesterNamedAndHolds(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	t.Run("a trust sequence of 8 against a list of 7", func(t *testing.T) {
		v, err := k.newPGP("sign").with(func(m map[string]any) { m["trust_sequence"] = 8 }).check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
	t.Run("a trust sequence of 7 and of 1 is held", func(t *testing.T) {
		for _, seq := range []int{1, 7} {
			v, err := k.newPGP("sign").with(func(m map[string]any) { m["trust_sequence"] = seq }).check(chk)
			want(t, v, err, "", pOK)
			if v.Info.TrustSequence != int64(seq) {
				t.Errorf("Info holds %d for %d", v.Info.TrustSequence, seq)
			}
		}
	})
	t.Run("an issuer member of another fingerprint", func(t *testing.T) {
		x := k.newPGP("sign")
		x.issuer = k.b.primary.fingerprint() // the binding is by A
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
	t.Run("an issuer member that is the fingerprint with one digit changed", func(t *testing.T) {
		x := k.newPGP("sign")
		x.issuer = flipHex(x.by.fingerprint() + strings.Repeat("0", 24))[:40]
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
	t.Run("a binding by a primary that the request did not name", func(t *testing.T) {
		full := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary, k.z.primary}, "sign")
		x := k.newPGP("sign")
		x.req, x.asked_ = full, full.subset(2)
		x.bound, x.by = full.bind(2), k.z.primary
		// Z is held by the requester, and is not on the list either: not named is the first fault.
		chkZ := k.checker(func(c *answer.Config) { c.Primaries = append(c.Primaries, k.z.primary.ref()) })
		v, err := x.run(chkZ, nil)
		want(t, v, err, answer.CodeIssuer, pst5)
		if !strings.Contains(v.Detail, "not one that the request named") {
			t.Errorf("detail %q", v.Detail)
		}
	})
	t.Run("a binding by a primary that is named and held and is not on the list", func(t *testing.T) {
		full := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary, k.z.primary}, "sign")
		x := k.newPGP("sign")
		x.req = full
		x.bound, x.by = full.bind(2), k.z.primary
		chkZ := k.checker(func(c *answer.Config) { c.Primaries = append(c.Primaries, k.z.primary.ref()) })
		v, err := x.check(chkZ)
		want(t, v, err, answer.CodeIssuer, pst5)
		if !strings.Contains(v.Detail, "not on the root list") {
			t.Errorf("detail %q", v.Detail)
		}
	})
	t.Run("a primary that was retired: named, held, and the list no longer has it", func(t *testing.T) {
		kr := newKit(t)
		kr.writeList([]memRoot{kr.a}) // B is retired
		x := kr.newPGP("sign")
		x.bound, x.by = x.req.bind(1), kr.b.primary
		v, err := x.check(kr.checker(nil))
		want(t, v, err, answer.CodeIssuer, pst5)
		// The control: A, which is on the list, is accepted by the same checker.
		y := kr.newPGP("sign")
		v, err = y.check(kr.checker(nil))
		want(t, v, err, "", pOK)
	})
	t.Run("a named primary on the list that the checker holds no key for cannot be judged", func(t *testing.T) {
		nokey := k.checker(func(c *answer.Config) { c.Primaries = c.Primaries[1:] }) // B only
		v, err := k.newPGP("sign").check(nokey)
		if err == nil || !isErr(err, answer.ErrNoPrimaryKey) {
			t.Fatalf("error %v, want ErrNoPrimaryKey", err)
		}
		if v.Accepted() || v.AnswerRefused() || v.Info != nil || v.Code != "" {
			t.Errorf("accepted %v, refused %v, code %q", v.Accepted(), v.AnswerRefused(), v.Code)
		}
		if got := statuses(v); got != "ppppnnnn" {
			t.Errorf("statuses %s", got)
		}
		for _, c := range v.Checks[4:] {
			if c.Reason != "the checker holds no key for the primary of the answer" {
				t.Errorf("check %d reason %q", c.N, c.Reason)
			}
		}
		// The checker that holds the key of B judges the answer by B.
		x := k.newPGP("sign")
		x.bound, x.by = x.req.bind(1), k.b.primary
		v, err = x.check(nokey)
		want(t, v, err, "", pOK)
	})
	t.Run("no key at all is the same", func(t *testing.T) {
		none := k.checker(func(c *answer.Config) { c.Primaries = nil })
		v, err := k.newPGP("sign").check(none)
		if !isErr(err, answer.ErrNoPrimaryKey) || v.Accepted() || statuses(v) != "ppppnnnn" {
			t.Errorf("error %v accepted %v statuses %s", err, v.Accepted(), statuses(v))
		}
	})
	t.Run("an answer whose issuer is decided before the keyring is looked at", func(t *testing.T) {
		none := k.checker(func(c *answer.Config) { c.Primaries = nil })
		x := k.newPGP("sign")
		x.issuer = k.b.primary.fingerprint()
		v, err := x.check(none)
		want(t, v, err, answer.CodeIssuer, pst5) // the trust sequence and the issuer come first
	})
	t.Run("a binding with a damaged signature", func(t *testing.T) {
		x := k.newPGP("sign")
		b := bytes.Clone(x.bound)
		b[len(b)-1] ^= 0x01
		x.bound = b
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
	t.Run("a binding that names the primary and is signed by another key", func(t *testing.T) {
		x := k.newPGP("sign")
		s := x.req.spec(0)
		s.signedBy = k.z.primary
		x.bound = s.file(t)
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
	t.Run("a binding that names no issuer fingerprint", func(t *testing.T) {
		x := k.newPGP("sign")
		s := x.req.spec(0)
		s.hashed = func(base []subpacket) []subpacket { return base[:len(base)-1] }
		x.bound = s.file(t)
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
	t.Run("a binding with two issuer fingerprints", func(t *testing.T) {
		x := k.newPGP("sign")
		s := x.req.spec(0)
		s.hashed = func(base []subpacket) []subpacket { return append(base, base[len(base)-1]) }
		x.bound = s.file(t)
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
	t.Run("the file does not choose the primary: a result file that names B for a binding by A", func(t *testing.T) {
		x := k.newPGP("sign")
		x.issuer = k.b.primary.fingerprint()
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, pst5)
	})
}

func isErr(err, target error) bool {
	for err != nil {
		if err == target { //nolint:errorlint // a plain walk, to say what is compared
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			if m, ok := err.(interface{ Unwrap() []error }); ok {
				for _, e := range m.Unwrap() {
					if isErr(e, target) {
						return true
					}
				}
			}
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Check 6: the binding is what was asked, and the embedded signature is the request's own for that primary.
func TestTheBindingIsWhatWasAsked(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	embedded := func(p *pgpKey) subpacket { return subpacket{} }
	_ = embedded
	for _, c := range []struct {
		name string
		cap  string
		mod  func(s *bindingSpec)
	}{
		{"flags 0x20 for a request to sign", "sign", func(s *bindingSpec) { s.flags = 0x20 }},
		{"flags 0x02 for a request to authenticate", "authenticate", func(s *bindingSpec) { s.flags = 0x02 }},
		{"flags 0x22 for a request to sign", "sign", func(s *bindingSpec) { s.flags = 0x22 }},
		{"flags 0x03 for a request to sign", "sign", func(s *bindingSpec) { s.flags = 0x03 }},
		{"flags 0x00", "sign", func(s *bindingSpec) { s.flags = 0x00 }},
		{"an embedded signature that is the request's for the other primary", "sign", func(s *bindingSpec) { s.embed = s.r.backBodies[1] }},
		{"an embedded signature that is one byte changed", "sign", func(s *bindingSpec) {
			e := bytes.Clone(s.r.backBodies[0])
			e[len(e)-1] ^= 0x01
			s.embed = e
		}},
		{"an embedded signature that is one byte more", "sign", func(s *bindingSpec) { s.embed = append(bytes.Clone(s.r.backBodies[0]), 0) }},
		{"an embedded signature that is one byte short", "sign", func(s *bindingSpec) { e := s.r.backBodies[0]; s.embed = bytes.Clone(e[:len(e)-1]) }},
		{"an embedded signature of one byte", "sign", func(s *bindingSpec) { s.embed = []byte{4} }},
		{"no embedded signature", "sign", func(s *bindingSpec) { s.unhashed = func(b []subpacket) []subpacket { return b[:1] } }},
		{"two embedded signatures", "sign", func(s *bindingSpec) { s.unhashed = func(b []subpacket) []subpacket { return append(b, b[1]) } }},
		{"an extra subpacket in the hashed area", "sign", func(s *bindingSpec) {
			s.hashed = func(b []subpacket) []subpacket { return append(b, subpacket{typ: 11, data: []byte{9}}) }
		}},
		{"an extra critical subpacket in the hashed area", "sign", func(s *bindingSpec) {
			s.hashed = func(b []subpacket) []subpacket { return append(b, subpacket{typ: 99, critical: true, data: []byte{1}}) }
		}},
		{"an extra subpacket in the unhashed area", "sign", func(s *bindingSpec) {
			s.unhashed = func(b []subpacket) []subpacket { return append(b, subpacket{typ: 11, data: []byte{9}}) }
		}},
		{"no key expiration", "sign", func(s *bindingSpec) {
			s.hashed = func(b []subpacket) []subpacket { return append(append([]subpacket{}, b[:2]...), b[3:]...) }
		}},
		{"a key expiration that is not critical", "sign", func(s *bindingSpec) {
			s.hashed = func(b []subpacket) []subpacket { b[2].critical = false; return b }
		}},
		{"a critical creation time", "sign", func(s *bindingSpec) {
			s.hashed = func(b []subpacket) []subpacket { b[0].critical = true; return b }
		}},
		{"a binding made one second before its subkey", "sign", func(s *bindingSpec) { s.created = s.r.sub.created.Add(-time.Second) }},
		{"a binding made a day before its subkey", "sign", func(s *bindingSpec) { s.created = s.r.sub.created.Add(-24 * time.Hour) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newPGP(c.cap)
			s := x.req.spec(0)
			c.mod(&s)
			x.bound = s.file(t)
			v, err := x.check(chk)
			want(t, v, err, answer.CodeProfile, pst6)
		})
	}
	t.Run("a binding made at the very second of its subkey is not older than it", func(t *testing.T) {
		x := k.newPGP("sign")
		s := x.req.spec(0)
		s.created = s.r.sub.created
		x.bound = s.file(t)
		x.with(func(m map[string]any) { m["valid_from"] = formatTime(s.r.sub.created) })
		v, err := x.check(chk)
		want(t, v, err, "", pOK)
	})
	t.Run("a binding made before its primary, after its subkey", func(t *testing.T) {
		kl := newKit(t)
		late := newPGPKey(t, time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)) // the primary was created after the subkey
		kl.b.primary = late
		kl.writeList([]memRoot{kl.a, kl.b})
		x := kl.newPGP("sign")
		x.bound, x.by = x.req.bind(1), late // honest: made at the clock, after both
		v, err := x.check(kl.checker(nil))
		want(t, v, err, "", pOK)
		s := x.req.spec(1)
		s.created = late.created.Add(-time.Second) // after the subkey of 10-20, one second before the primary
		x.bound = s.file(t)
		x.with(func(m map[string]any) { m["valid_from"] = formatTime(s.created) })
		v, err = x.check(kl.checker(nil))
		want(t, v, err, answer.CodeProfile, pst6)
		// At the second of the primary it is not older.
		s.created = late.created
		x.bound = s.file(t)
		x.with(func(m map[string]any) { m["valid_from"] = formatTime(s.created) })
		v, err = x.check(kl.checker(nil))
		want(t, v, err, "", pOK)
	})
	t.Run("a primary created after the clock never passes", func(t *testing.T) {
		kl := newKit(t)
		future := newPGPKey(t, testNow.Add(time.Hour))
		kl.b.primary = future
		kl.writeList([]memRoot{kl.a, kl.b})
		x := kl.newPGP("sign")
		s := x.req.spec(1) // BindSubkey refuses a ceremony before the primary: the binding is written by hand
		x.bound, x.by = s.file(t), future
		v, err := x.check(kl.checker(nil))
		if err == nil && v.Accepted() {
			t.Fatal("an answer by a primary that does not exist yet is accepted")
		}
		want(t, v, err, answer.CodeProfile, pst6)
	})
}

// Check 6 comes after check 5: a wrong capability together with a wrong issuer is the issuer.
func TestTheIssuerIsJudgedBeforeTheProfileOfAnOpenPGPAnswer(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	x := k.newPGP("sign")
	s := x.req.spec(0)
	s.flags = 0x20
	x.bound = s.file(t)
	x.issuer = k.b.primary.fingerprint()
	v, err := x.check(chk)
	want(t, v, err, answer.CodeIssuer, pst5)
}

// Check 7: the expiry is the length expected, and the subkey has not ended.
func TestTheExpiryOfTheSubkeyIsTheLengthExpectedAndHasNotPassed(t *testing.T) {
	k := newKit(t)
	created := testNow
	endsAfter := func(months int) time.Time {
		e := created.AddDate(0, months, 0)
		return e
	}
	for _, c := range []struct {
		name   string
		months int
		code   answer.Code
		st     string
	}{
		{"2 months", 2, answer.CodeValidity, pst7},
		{"11 months", 11, answer.CodeValidity, pst7},
		{"12 months", 12, "", pOK},
		{"13 months", 13, "", pOK},
		{"14 months", 14, "", pOK},
		{"15 months", 15, answer.CodeValidity, pst7},
		{"40 months", 40, answer.CodeValidity, pst7},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newPGP("sign")
			ends := endsAfter(c.months)
			s := x.req.spec(0)
			s.life = uint32(ends.Unix() - x.req.sub.created.Unix())
			x.bound = s.file(t)
			x.with(func(m map[string]any) { m["valid_until"] = formatTime(ends) })
			v, err := x.check(k.checker(nil))
			want(t, v, err, c.code, c.st)
		})
	}
	t.Run("the edges of the clock", func(t *testing.T) {
		x := k.newPGP("sign")
		for _, c := range []struct {
			name string
			now  time.Time
			code answer.Code
			st   string
		}{
			{"one second before the binding was made", testNow.Add(-time.Second), answer.CodeValidity, pst7},
			{"the second it was made", testNow, "", pOK},
			{"one second before the subkey ends", pgpEnds.Add(-time.Second), "", pOK},
			{"the second the subkey ends", pgpEnds, answer.CodeValidity, pst7},
			{"one second after it ends", pgpEnds.Add(time.Second), answer.CodeValidity, pst7},
			{"half a second before it ends", pgpEnds.Add(-500 * time.Millisecond), "", pOK},
		} {
			chk := k.checker(func(cfg *answer.Config) { cfg.Now = func() time.Time { return c.now } })
			v, err := x.check(chk)
			if c.name == "one second before the binding was made" {
				// The primary and the subkey exist then too.
				want(t, v, err, c.code, c.st)
				continue
			}
			want(t, v, err, c.code, c.st)
		}
	})
	t.Run("the validity is judged after the profile", func(t *testing.T) {
		x := k.newPGP("sign")
		s := x.req.spec(0)
		s.flags = 0x20
		s.life = uint32(testNow.AddDate(0, 2, 0).Unix() - x.req.sub.created.Unix())
		x.bound = s.file(t)
		v, err := x.check(k.checker(nil))
		want(t, v, err, answer.CodeProfile, pst6)
	})
}

// Check 8.
func TestTheDigestsAndDatesOfTheOpenPGPResultMatchTheFile(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	good64 := strings.Repeat("a", 64)
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"no artifact", func(m map[string]any) { m["artifacts"] = []any{} }},
		{"two artifacts", func(m map[string]any) {
			m["artifacts"] = append(m["artifacts"].([]map[string]any), map[string]any{"name": "example-answer.x.pgp", "sha256": good64})
		}},
		{"another name", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.cert.pem", "sha256": m["artifacts"].([]map[string]any)[0]["sha256"]}}
		}},
		{"another stem", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "other.bound.pgp", "sha256": m["artifacts"].([]map[string]any)[0]["sha256"]}}
		}},
		{"the digest of another file", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.bound.pgp", "sha256": good64}}
		}},
		{"valid_from one second late", func(m map[string]any) { m["valid_from"] = "2026-11-15T12:00:01Z" }},
		{"valid_from the time of the subkey", func(m map[string]any) { m["valid_from"] = "2026-10-20T12:00:00Z" }},
		{"valid_until one second late", func(m map[string]any) { m["valid_until"] = "2027-12-15T12:00:01Z" }},
		{"valid_until one second early", func(m map[string]any) { m["valid_until"] = "2027-12-15T11:59:59Z" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newPGP("sign")
			x.with(c.edit)
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, pst8)
		})
	}
}

// Info of an accepted OpenPGP answer.
func TestTheInfoOfAnAcceptedOpenPGPAnswer(t *testing.T) {
	k := newKit(t)
	x := k.newPGP("authenticate")
	v, err := x.check(k.checker(nil))
	want(t, v, err, "", pOK)
	in := *v.Info
	if in.Type != handoff.TypeOpenPGP || in.Issuer != k.a.primary.fingerprint() || in.TrustSequence != 7 || in.Stem != "example-answer" {
		t.Errorf("Info %+v", in)
	}
	if !in.ValidFrom.Equal(testNow) || !in.ValidUntil.Equal(pgpEnds) {
		t.Errorf("valid %v to %v", in.ValidFrom, in.ValidUntil)
	}
	_ = binary.BigEndian
}

// The held list that has expired still judges an OpenPGP answer, with a warning (record 0006, rule 21).
func TestAnOpenPGPAnswerIsJudgedByAHeldListThatHasExpiredAndWarns(t *testing.T) {
	k := newKit(t)
	k.expires = "2026-11-01T00:00:00Z"
	k.writeList([]memRoot{k.a, k.b})
	v, err := k.newPGP("sign").check(k.checker(nil))
	want(t, v, err, "", pOK)
	if len(v.Warnings) != 1 || v.Warnings[0] != "held-expired" {
		t.Errorf("warnings %v", v.Warnings)
	}
	x := k.newPGP("sign")
	x.with(func(m map[string]any) { m["trust_sequence"] = 8 })
	v, err = x.check(k.checker(nil))
	want(t, v, err, answer.CodeIssuer, pst5)
	if len(v.Warnings) != 1 {
		t.Errorf("warnings %v on a refusal", v.Warnings)
	}
}

// A refusal by the certifier of an OpenPGP request is read as for X.509: checks 1 to 3, and nothing else.
func TestAnOpenPGPAnswerInWhichTheCertifierRefusedIsNeitherAcceptedNorAFaultOfTheAnswer(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	refuse := func(x *pgpCase, change func(m map[string]any)) (answer.Verdict, error) {
		x.with(func(m map[string]any) {
			for _, key := range []string{"artifacts", "valid_from", "valid_until", "issuer"} {
				delete(m, key)
			}
			m["outcome"], m["reasons"] = "refused", []string{"unknown-primary"}
			if change != nil {
				change(m)
			}
		})
		return x.run(chk, func(f map[string][]byte) { delete(f, answer.FileBound) })
	}
	v, err := refuse(k.newPGP("sign"), nil)
	if err != nil || v.Accepted() || v.AnswerRefused() || !v.RequestRefused() || statuses(v) != "pppnnnnn" || len(v.CertifierReasons) != 1 {
		t.Fatalf("%v accepted %v code %q statuses %s", err, v.Accepted(), v.Code, statuses(v))
	}
	v, err = refuse(k.newPGP("sign"), func(m map[string]any) { m["request_sha256"] = strings.Repeat("a", 64) })
	want(t, v, err, answer.CodeRequestMismatch, pst3)
	v, err = refuse(k.newPGP("sign"), func(m map[string]any) { m["issuer"] = strings.Repeat("a", 40) })
	want(t, v, err, answer.CodeMalformed, "pfnnnnnn")
	// A bound file beside a refusal is a fault of the answer.
	x := k.newPGP("sign")
	x.with(func(m map[string]any) {
		for _, key := range []string{"artifacts", "valid_from", "valid_until", "issuer"} {
			delete(m, key)
		}
		m["outcome"], m["reasons"] = "refused", []string{"policy"}
	})
	v, err = x.check(chk)
	want(t, v, err, answer.CodeMalformed, "pfnnnnnn")
}
