package rootlist_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
)

// The fuzz targets run the pure functions of the package on any bytes: none starts a process or
// touches a file. They must never panic, and a candidate that is accepted must be one that the
// holder of the keys signed. The seeds are the vector files, which the manifest names.

// vectorSet is the lists of the manifest, read once.
type vectorSet struct {
	m      *manifest
	pairs  []rootlist.Signed
	helds  []*rootlist.Held // nil for a list that is not a list
	lists  []*rootlist.List
	clocks []time.Time
	pins   rootlist.Trust
	allP   []string
}

var (
	vsOnce sync.Once
	vs     *vectorSet
)

func vectors(t testing.TB) *vectorSet {
	t.Helper()
	vsOnce.Do(func() {
		m := loadManifest(t)
		v := &vectorSet{m: m}
		for _, l := range m.Lists {
			p := m.listFiles(t, l.ID)
			v.pairs = append(v.pairs, p)
			h, err := rootlist.ParseHeld(p.JSON)
			if err != nil {
				v.helds = append(v.helds, nil)
				v.lists = append(v.lists, nil)
				continue
			}
			v.helds = append(v.helds, h)
			v.lists = append(v.lists, h.List)
		}
		seen := map[time.Time]bool{}
		add := func(c string) {
			if c == "" {
				return
			}
			if tm := mustTime(c); !seen[tm] {
				seen[tm] = true
				v.clocks = append(v.clocks, tm)
			}
		}
		add(m.Clock)
		for _, c := range m.Cases {
			add(c.Clock)
		}
		v.clocks = append(v.clocks, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), time.Time{})
		v.pins = m.trustOf(t, nil)
		for _, r := range m.Roots {
			v.allP = append(v.allP, r.Pin)
		}
		vs = v
	})
	return vs
}

func (v *vectorSet) clockAt(i uint8) time.Time { return v.clocks[int(i)%len(v.clocks)] }

// trustAt is the trust for a selector: 0 is the initial pins, n is the held list n-1.
func (v *vectorSet) trustAt(i uint8) rootlist.Trust {
	n := int(i) % (len(v.helds) + 1)
	if n == 0 || v.helds[n-1] == nil {
		return v.pins
	}
	return rootlist.HeldTrust(v.helds[n-1])
}

// heldAt is the held list of a selector, or nil when the selector is the initial pins.
func (v *vectorSet) heldAt(i uint8) *rootlist.Held {
	n := int(i) % (len(v.helds) + 1)
	if n == 0 {
		return nil
	}
	return v.helds[n-1]
}

func (v *vectorSet) indexOf(id *string) uint8 {
	if id == nil {
		return 0
	}
	for i, l := range v.m.Lists {
		if l.ID == *id {
			return uint8(i + 1)
		}
	}
	return 0
}

func (v *vectorSet) clockIndex(c string) uint8 {
	if c == "" {
		c = v.m.Clock
	}
	for i, tm := range v.clocks {
		if tm.Equal(mustTime(c)) {
			return uint8(i)
		}
	}
	return 0
}

// checkList is what every successful reading of a list must satisfy.
func checkList(t *testing.T, data []byte, l *rootlist.List) {
	t.Helper()
	if len(data) > rootlist.MaxBytes {
		t.Fatalf("a list of %d bytes was read", len(data))
	}
	if l.Version != 1 || l.Sequence < 1 || l.Sequence > 9007199254740991 || len(l.Roots) == 0 {
		t.Fatalf("a list that is not of the form: %+v", l)
	}
	for _, tm := range []time.Time{l.SignedAt, l.ExpiresAt} {
		if tm.Location() != time.UTC || tm.Nanosecond() != 0 || !strings.Contains(string(data), tm.Format(rootlist.TimeLayout)) {
			t.Fatalf("a time that is not of the form: %v", tm)
		}
	}
	labels, pins := map[string]bool{}, map[string]bool{}
	for _, r := range l.Roots {
		if len(r.Label) != 1 || r.Label[0] < 'A' || r.Label[0] > 'Z' || !lowerHex(r.X509SPKISHA256, 64) || (r.OpenPGPFingerprint != "" && !lowerHex(r.OpenPGPFingerprint, 40)) {
			t.Fatalf("a root that is not of the form: %+v", r)
		}
		if labels[r.Label] || pins[r.X509SPKISHA256] {
			t.Fatalf("a label or a pin twice: %+v", r)
		}
		labels[r.Label], pins[r.X509SPKISHA256] = true, true
	}
	if l.LastRecordSHA256 != "" && !lowerHex(l.LastRecordSHA256, 64) {
		t.Fatalf("a digest that is not of the form: %q", l.LastRecordSHA256)
	}
	removed := map[string]bool{}
	for _, r := range l.Removals {
		if len(r.Label) != 1 || !lowerHex(r.X509SPKISHA256, 64) || r.Authorisation == "" || removed[r.X509SPKISHA256] {
			t.Fatalf("a removal that is not of the form: %+v", r)
		}
		removed[r.X509SPKISHA256] = true
	}
}

func lowerHex(s string, n int) bool {
	return len(s) == n && strings.Trim(s, "0123456789abcdef") == ""
}

func FuzzParseList(f *testing.F) {
	v := vectors(f)
	for _, p := range v.pairs {
		f.Add(p.JSON)
	}
	w := newWorld(f)
	f.Add(listOf(7, w.a, w.b).json())
	f.Add(listOf(8, w.b).withRemovals(removalOf(f, w.a)).json())
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := rootlist.ParseList(data)
		h, herr := rootlist.ParseHeld(data)
		if (err == nil) != (herr == nil) {
			t.Fatalf("ParseList and ParseHeld disagree: %v, %v", err, herr)
		}
		if err != nil {
			if l != nil || h != nil {
				t.Fatalf("a refusal has a value")
			}
			mustBeASCII(t, "the error text", err.Error())
			return
		}
		checkList(t, data, l)
		if !reflect.DeepEqual(l, h.List) || !bytes.Equal(h.JSON, data) {
			t.Fatalf("ParseHeld read another list")
		}
	})
}

var knownReasons = []rootlist.Reason{rootlist.Malformed, rootlist.UnknownSigner, rootlist.SignatureInvalid, rootlist.VersionUnsupported, rootlist.Rollback, rootlist.SequenceConflict, rootlist.RemovalInvalid, rootlist.InsufficientSigners, rootlist.Expired}

// FuzzVerify takes any bytes for the two files, one of the trusts of the vectors and one of their
// clocks. The keys of the vectors are the only ones the fuzzer has, and it has no private key: a
// candidate that is accepted must have a root-list.json that is one of the vectors' own, byte for
// byte, because no signature over any other bytes exists.
func FuzzVerify(f *testing.F) {
	v := vectors(f)
	for _, c := range v.m.Cases {
		if c.Candidate == nil {
			continue
		}
		p := v.m.listFiles(f, *c.Candidate)
		f.Add(p.JSON, p.JWS, v.indexOf(c.Held), v.clockIndex(c.Clock))
	}
	for _, p := range v.pairs {
		f.Add(p.JSON, p.JWS, uint8(0), uint8(0))
	}
	f.Add([]byte{}, []byte{}, uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, jsonData, jwsData []byte, heldSel, clockSel uint8) {
		v := vectors(t)
		cand := rootlist.Signed{JSON: bytes.Clone(jsonData), JWS: bytes.Clone(jwsData)}
		trust, now := v.trustAt(heldSel), v.clockAt(clockSel)
		got := rootlist.Verify(cand, trust, now)
		if !bytes.Equal(cand.JSON, jsonData) || !bytes.Equal(cand.JWS, jwsData) {
			t.Fatalf("Verify changed its input")
		}
		if again := rootlist.Verify(cand, trust, now); again.Accepted != got.Accepted || again.Reason != got.Reason || again.Check != got.Check {
			t.Fatalf("two runs differ")
		}
		if !got.Accepted {
			if got.List != nil || got.Again || got.Check < 1 || got.Check > 11 || !slices.Contains(knownReasons, got.Reason) || rootlist.Checks()[got.Check-1].Reason != got.Reason {
				t.Fatalf("a refusal that is not of the form: %+v", got)
			}
			mustBeASCII(t, "Detail", got.Detail)
			return
		}
		if got.Reason != "" || got.Check != 0 || got.Detail != "" || got.List == nil {
			t.Fatalf("an acceptance that is not of the form: %+v", got)
		}
		// Again says that the host received the list it holds: the same bytes, the same sequence. A
		// list that is new has a higher sequence than the held one.
		if h := v.heldAt(heldSel); h != nil {
			same := bytes.Equal(jsonData, h.JSON)
			if got.Again != same || (same && got.List.Sequence != h.List.Sequence) || (!same && got.List.Sequence <= h.List.Sequence) {
				t.Fatalf("Again = %v for bytes that are the held list's = %v: %+v", got.Again, same, got)
			}
		} else if got.Again {
			t.Fatalf("Again with no held list")
		}
		signedByTheVectors := false
		for _, p := range v.pairs {
			if bytes.Equal(p.JSON, jsonData) {
				signedByTheVectors = true
			}
		}
		if !signedByTheVectors {
			t.Fatalf("ACCEPTED bytes that no vector signed:\njson=%q\njws=%q\nheld=%d clock=%d", jsonData, jwsData, heldSel, clockSel)
		}
		want, err := rootlist.ParseList(jsonData)
		if err != nil || !reflect.DeepEqual(want, got.List) || !now.Before(got.List.ExpiresAt) {
			t.Fatalf("the accepted list is not the one read from the bytes, or has expired: %v", err)
		}
		// An accepted list has its expiry 13 calendar months after its signing time
		// (by the test's own arithmetic, in dates_test.go), and was not signed after the clock.
		if !got.List.ExpiresAt.Equal(plusMonths(got.List.SignedAt, 13)) || got.List.SignedAt.After(now) {
			t.Fatalf("ACCEPTED a list with dates that break the rules: signed %s, expires %s, clock %s", got.List.SignedAt, got.List.ExpiresAt, now)
		}
	})
}

// forger signs any bytes with one key that the host trusts, so that the fuzzer reaches the members
// behind the signature.
var (
	forgerOnce sync.Once
	forgerKey  *key
)

func forger(t testing.TB) *key {
	forgerOnce.Do(func() { forgerKey = newKey(t, "A") })
	return forgerKey
}

// FuzzVerifySigned signs the bytes it is given with the one key the host trusts, so the list is
// read whatever it holds. What is accepted must be a list of exactly that key: the host trusts
// no other key, so a list that holds another root key is refused for want of its signature.
func FuzzVerifySigned(f *testing.F) {
	k := forger(f)
	v := vectors(f)
	for _, p := range v.pairs {
		f.Add(p.JSON, uint8(0))
	}
	f.Add(listOf(1, k).json(), uint8(0))
	f.Add(listOf(8, k).json(), uint8(1))
	other := newKey(f, "B")
	f.Add(listOf(1, k, other).json(), uint8(0))
	f.Add(listOf(2, other).withRemovals(removalOf(f, k)).json(), uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, clockSel uint8) {
		k := forger(t)
		v := vectors(t)
		trust := pinsOf(t, k.pin)
		now := v.clockAt(clockSel)
		cand := rootlist.Signed{JSON: data, JWS: sign(t, data, k)}
		got := rootlist.Verify(cand, trust, now)
		if !got.Accepted {
			mustBeASCII(t, "Detail", got.Detail)
			if got.Check < 1 || got.Check > 11 || rootlist.Checks()[got.Check-1].Reason != got.Reason {
				t.Fatalf("a refusal that is not of the form: %+v", got)
			}
			return
		}
		if got.Again {
			t.Fatalf("Again against initial pins")
		}
		l, err := rootlist.ParseList(data)
		if err != nil || !reflect.DeepEqual(l, got.List) {
			t.Fatalf("accepted a list that ParseList does not read: %v", err)
		}
		checkList(t, data, l)
		if !now.Before(l.ExpiresAt) {
			t.Fatalf("accepted a list that has expired")
		}
		if pins := l.Pins(); len(pins) != 1 || pins[0] != k.pin {
			t.Fatalf("accepted a list with root keys that did not sign it: %v", pins)
		}
		if len(l.Removals) != 0 {
			for _, r := range l.Removals {
				if r.X509SPKISHA256 == k.pin {
					t.Fatalf("accepted a removal of the key that signs")
				}
			}
		}
	})
}

func FuzzVerifyCABundle(f *testing.F) {
	v := vectors(f)
	for _, b := range v.m.Bundles {
		data := readVector(f, b.File)
		for i := range v.lists {
			f.Add(data, uint8(i))
		}
	}
	w := newWorld(f)
	f.Add([]byte(bundleOf(7, w.a, w.b)), uint8(0))
	f.Add([]byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, sel uint8) {
		v := vectors(t)
		var lists []*rootlist.List
		for _, l := range v.lists {
			if l != nil {
				lists = append(lists, l)
			}
		}
		if len(lists) == 0 {
			t.Skip("no list")
		}
		l := lists[int(sel)%len(lists)]
		got := rootlist.VerifyCABundle(data, l)
		if !got.Accepted {
			if got.Reason != rootlist.CABundleMismatch || got.Check != 0 || got.List != nil {
				t.Fatalf("a refusal that is not of the form: %+v", got)
			}
			mustBeASCII(t, "Detail", got.Detail)
			return
		}
		// What is accepted is the first line and the blocks of the roots of the list, as an encoder
		// writes them, and nothing else.
		want := []byte("# trust-sequence: " + strconv.FormatInt(l.Sequence, 10) + "\n")
		rest := bytes.TrimPrefix(data, want)
		if len(rest) == len(data) {
			t.Fatalf("ACCEPTED a bundle with another first line: %q", data[:min(len(data), 40)])
		}
		for _, r := range l.Roots {
			blk, tail := pem.Decode(rest)
			if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 || !bytes.Equal(rest[:len(rest)-len(tail)], pem.EncodeToMemory(blk)) {
				t.Fatalf("ACCEPTED a bundle with a block that is not one spelling: %q", data)
			}
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatalf("ACCEPTED a block that is no certificate: %v", err)
			}
			if sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo); hex.EncodeToString(sum[:]) != r.X509SPKISHA256 {
				t.Fatalf("ACCEPTED a certificate that is not the key of root %s", r.Label)
			}
			// A CA certificate that verifies with its own key.
			if !cert.BasicConstraintsValid || !cert.IsCA {
				t.Fatalf("ACCEPTED a certificate of root %s that is not a CA certificate", r.Label)
			}
			if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				t.Fatalf("ACCEPTED a certificate of root %s whose issuer is not its subject", r.Label)
			}
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				t.Fatalf("ACCEPTED a certificate of root %s that does not verify with its own key: %v", r.Label, err)
			}
			rest = tail
		}
		if len(rest) != 0 {
			t.Fatalf("ACCEPTED a bundle with %d bytes after the last block", len(rest))
		}
	})
}

func FuzzCheckRemoval(f *testing.F) {
	v := vectors(f)
	for _, r := range v.m.Removals {
		f.Add(string(readVector(f, r.File)), v.m.pin(f, r.Label), uint8(0))
	}
	f.Add(``, ``, uint8(0))
	f.Fuzz(func(t *testing.T, auth, pin string, sel uint8) {
		v := vectors(t)
		cand := &rootlist.List{Roots: []rootlist.Root{{Label: "Q", X509SPKISHA256: strings.Repeat("0", 64)}}}
		err := rootlist.CheckRemoval(rootlist.Removal{Label: "A", X509SPKISHA256: pin, Authorisation: auth}, cand, v.allP)
		if err != nil {
			if !errors.Is(err, rootlist.ErrRemovalInvalid) {
				t.Fatalf("the error does not wrap ErrRemovalInvalid: %v", err)
			}
			mustBeASCII(t, "the error text", err.Error())
			return
		}
		// Accepted: the text is one of the authorisations that the holder stored, and for its pin.
		found := false
		for _, r := range v.m.Removals {
			if string(readVector(t, r.File)) == auth && v.m.pin(t, r.Label) == pin {
				found = true
			}
		}
		if !found {
			t.Fatalf("ACCEPTED an authorisation that no root key made: %q (pin %q)", auth, pin)
		}
	})
}

func FuzzPinTrust(f *testing.F) {
	f.Add("")
	f.Add(strings.Repeat("a", 64))
	f.Add(strings.Repeat("A", 64))
	f.Fuzz(func(t *testing.T, pin string) {
		tr, err := rootlist.PinTrust([]string{pin})
		if err != nil {
			mustBeASCII(t, "the error text", err.Error())
			return
		}
		if !lowerHex(pin, 64) {
			t.Fatalf("accepted the pin %q", pin)
		}
		_ = tr
	})
}
