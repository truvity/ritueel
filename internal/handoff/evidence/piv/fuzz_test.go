package piv_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/handoff/evidence/piv"
)

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// checkEvidence holds what every accepted piv evidence is: a P-384 key, a firmware of the form a.b.c, a PIN
// word and a touch word from the allowed sets, printable details, and the details the page gives.
func checkEvidence(t *testing.T, ev *handoff.Evidence) {
	t.Helper()
	if ev == nil || ev.Key == nil || ev.Key.Curve.Params().Name != "P-384" {
		t.Fatalf("evidence %+v", ev)
	}
	parts := strings.Split(ev.Firmware, ".")
	if len(parts) != 3 {
		t.Fatalf("firmware %q", ev.Firmware)
	}
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 || strconv.Itoa(n) != p {
			t.Fatalf("firmware %q", ev.Firmware)
		}
	}
	if !slices.Contains([]handoff.PINPolicy{handoff.PINNever, handoff.PINOnce, handoff.PINAlways}, ev.PINPolicy) {
		t.Fatalf("PIN policy %q", ev.PINPolicy)
	}
	if !slices.Contains([]string{"never", "always", "cached"}, ev.TouchPolicy) {
		t.Fatalf("touch policy %q", ev.TouchPolicy)
	}
	if ev.Unprotected || len(ev.SignPrincipals) != 0 {
		t.Fatalf("evidence %+v", ev)
	}
	for k, v := range ev.Details {
		if !printable(k) || !printable(v) {
			t.Fatalf("detail %q = %q is not printable ASCII", k, v)
		}
	}
	if !slices.Contains(piv.Slots(), ev.Details[attest.DetailSlot]) {
		t.Fatalf("slot %q", ev.Details[attest.DetailSlot])
	}
	if n, err := strconv.ParseUint(ev.Details[attest.DetailSerial], 10, 63); err != nil || n == 0 {
		t.Fatalf("serial %q", ev.Details[attest.DetailSerial])
	}
	if ff, ok := ev.Details[attest.DetailFormFactor]; ok {
		if n, err := strconv.Atoi(ff); err != nil || n < 0 || n > 255 {
			t.Fatalf("form factor %q", ff)
		}
	}
	if ev.Details[attest.DetailPolicyRead] != "true" {
		t.Fatalf("policy_read %q", ev.Details[attest.DetailPolicyRead])
	}
}

func checkRefusal(t *testing.T, ev *handoff.Evidence, err error) {
	t.Helper()
	if ev != nil {
		t.Fatalf("evidence beside an error: %+v", ev)
	}
	var ce *handoff.CodeError
	if !errors.As(err, &ce) || (ce.Code != handoff.CodeMalformed && ce.Code != handoff.CodeProofInvalid) || ce.Detail == "" || !printable(ce.Detail) {
		t.Fatalf("error %v is not a refusal of the evidence", err)
	}
}

// FuzzVerifyPIV runs the verifier on any evidence bytes at the clock of the vectors against the bundle of
// the vectors. Seeds: the evidence of the 36 vector cases and the made-up ones.
func FuzzVerifyPIV(f *testing.F) {
	for _, stem := range attesttest.VectorEvidenceStems(f) {
		f.Add([]byte(attesttest.VectorProof(f, stem).Evidence))
	}
	m := newMaker(f)
	leaf, token := m.PIVChain(f, p384(f), attesttest.Slot{})
	f.Add(attesttest.EvidenceJSON(f, leaf, token))
	f.Add(attesttest.EvidenceJSON(f, leaf, token, leaf))
	f.Add(attesttest.EvidenceJSON(f, token, leaf))
	f.Add([]byte(`{"attestation":["AA==","AA=="]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})
	v := newVerifier(f, attesttest.VectorBundle(f))
	f.Fuzz(func(t *testing.T, evidence []byte) {
		ev, err := v.Verify(t.Context(), nil, proofOf(handoff.StorePIV, evidence), vectorTime(t))
		if err != nil {
			checkRefusal(t, ev, err)
			return
		}
		checkEvidence(t, ev)
	})
}

// FuzzVerifyPIVValues makes a slot certificate whose subject and extension values are the fuzzed bytes, signed
// by a token that chains to a pinned root, so that the readers of the values are reached for every input. A
// value that is accepted is checked against what the bytes say.
func FuzzVerifyPIVValues(f *testing.F) {
	m := newMaker(f)
	v := newVerifier(f, m.Bundle(f))
	key := p384(f)
	f.Add([]byte{5, 8, 0}, []byte{0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e}, []byte{2, 1}, []byte{2}, []byte("YubiKey PIV Attestation 9c"))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{}, []byte{})
	f.Add([]byte{255, 255, 255}, []byte{0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, []byte{3, 3}, []byte{255}, []byte("YubiKey PIV Attestation 95"))
	f.Add([]byte{1}, []byte{0x02, 0x01, 0x00}, []byte{0, 0}, []byte{1, 2}, []byte("YubiKey PIV Attestation 9C"))
	f.Fuzz(func(t *testing.T, fw, serial, policy, form, cn []byte) {
		ev, err := v.Verify(t.Context(), nil, proofOf(handoff.StorePIV, m.PIVEvidence(t, key, attesttest.Slot{
			Firmware: nonNil(fw), Serial: nonNil(serial), Policy: nonNil(policy), Form: nonNil(form),
			Tweak: func(c *x509.Certificate) { c.RawSubject = rawName(t, []atv{{oidCN, 0x0c, string(cn)}}) },
			Check: attesttest.CheckNone,
		})), clock)
		if err != nil {
			checkRefusal(t, ev, err)
			return
		}
		checkEvidence(t, ev)
		if want := fmt.Sprintf("%d.%d.%d", fw[0], fw[1], fw[2]); ev.Firmware != want {
			t.Fatalf("firmware %q from %v", ev.Firmware, fw)
		}
		if ev.Details[attest.DetailSlot] != strings.TrimPrefix(string(cn), "YubiKey PIV Attestation ") {
			t.Fatalf("slot %q from %q", ev.Details[attest.DetailSlot], cn)
		}
		if !bytes.Equal(serial, encodeSerial(ev.Details[attest.DetailSerial])) {
			t.Fatalf("serial %q does not write back to %x", ev.Details[attest.DetailSerial], serial)
		}
	})
}

// nonNil keeps an empty fuzzed value empty, not the maker's default.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// encodeSerial writes a decimal number as the shortest DER INTEGER.
func encodeSerial(dec string) []byte {
	n, err := strconv.ParseUint(dec, 10, 64)
	if err != nil {
		return nil
	}
	var c []byte
	for x := n; x > 0; x >>= 8 {
		c = append([]byte{byte(x)}, c...)
	}
	if len(c) == 0 || c[0]&0x80 != 0 {
		c = append([]byte{0}, c...)
	}
	return append([]byte{0x02, byte(len(c))}, c...)
}

// FuzzDecodeSlotExtensions feeds the four readers of the extension values any bytes. An accepted value
// written out again gives the input bytes (so no two inputs have one meaning).
func FuzzDecodeSlotExtensions(f *testing.F) {
	f.Add([]byte{5, 8, 0})
	f.Add([]byte{0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e})
	f.Add([]byte{2, 1})
	f.Add([]byte{2})
	f.Add([]byte{})
	f.Add([]byte{0x02, 0x01, 0x80})
	f.Add(bytes.Repeat([]byte{0xff}, 300))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if fw, err := piv.DecodeFirmware(raw); err == nil {
			var a, b, c int
			if n, _ := fmt.Sscanf(fw, "%d.%d.%d", &a, &b, &c); n != 3 || !bytes.Equal(raw, []byte{byte(a), byte(b), byte(c)}) {
				t.Fatalf("firmware %q from %x", fw, raw)
			}
		} else if fw != "" {
			t.Fatalf("a value beside an error: %q", fw)
		}
		if s, err := piv.DecodeSerial(raw); err == nil {
			if !bytes.Equal(raw, encodeSerial(s)) {
				t.Fatalf("serial %q from %x", s, raw)
			}
		} else if s != "" {
			t.Fatalf("a value beside an error: %q", s)
		}
		pin, touch, err := piv.DecodePolicy(raw)
		if err == nil {
			p := map[handoff.PINPolicy]byte{handoff.PINNever: 1, handoff.PINOnce: 2, handoff.PINAlways: 3}[pin]
			h := map[string]byte{"never": 1, "always": 2, "cached": 3}[touch]
			if !bytes.Equal(raw, []byte{p, h}) || p == 0 || h == 0 {
				t.Fatalf("policy %q %q from %x", pin, touch, raw)
			}
		} else if pin != "" || touch != "" {
			t.Fatalf("a value beside an error: %q %q", pin, touch)
		}
		if ff, err := piv.DecodeFormFactor(raw); err == nil {
			if n, e := strconv.Atoi(ff); e != nil || !bytes.Equal(raw, []byte{byte(n)}) {
				t.Fatalf("form factor %q from %x", ff, raw)
			}
		} else if ff != "" {
			t.Fatalf("a value beside an error: %q", ff)
		}
	})
}

// FuzzSlotSubject feeds the reader of the subject any bytes. A name that is accepted is the one the page
// gives, written in DER by one of the two string types.
func FuzzSlotSubject(f *testing.F) {
	for _, slot := range []string{"9a", "9c", "95", "f9", ""} {
		f.Add(mustRawName(slot, 0x0c))
		f.Add(mustRawName(slot, 0x13))
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add(bytes.Repeat([]byte{0x30, 0x02}, 100))
	f.Fuzz(func(t *testing.T, raw []byte) {
		slot, err := piv.SlotOf(&x509.Certificate{RawSubject: raw})
		if err != nil {
			if slot != "" {
				t.Fatalf("a slot beside an error: %q", slot)
			}
			return
		}
		if !slices.Contains(piv.Slots(), slot) {
			t.Fatalf("slot %q", slot)
		}
		if !bytes.Equal(raw, mustRawName(slot, 0x0c)) && !bytes.Equal(raw, mustRawName(slot, 0x13)) {
			t.Fatalf("the name %x is accepted and is not the page's, written by one of the two string types", raw)
		}
	})
}

func mustRawName(slot string, tag int) []byte {
	return rawNameBytes([]atv{{oidCN, tag, "YubiKey PIV Attestation " + slot}})
}
