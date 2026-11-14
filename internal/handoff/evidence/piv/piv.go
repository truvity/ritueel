// Package piv is check 7 of the hand-off contract for the key store piv: the evidence of a key in a PIV
// slot, which is the slot's attestation certificate and the token's own certificate ("Evidence for a PIV
// key (check 7)" and the section piv of docs/reference/hand-off-contract.md). [Verifier] verifies that the
// chain leads to a pinned maker root, reads the slot, the firmware, the serial number and the policies
// from the slot certificate, and returns the attested key with them. The checker then does check 8 (the
// key is the request's key) and check 9 (firmware and PIN policy) with what was returned.
//
// The order is parse, chain, then values: the subject, the extensions and the key of a certificate whose
// chain failed are never read, and no evidence is returned beside an error. The package reads bytes only:
// no file, no network, no card, no outside program.
package piv

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
)

// Verifier is check 7 for the store piv. It is made by [New], is immutable and is safe for concurrent use.
// The zero Verifier refuses every call (with an error that is not a verdict on the evidence).
type Verifier struct {
	b *attest.Bundle
}

var _ handoff.EvidenceVerifier = (*Verifier)(nil)

// New returns the verifier of piv evidence that trusts the pinned set b. A nil bundle is an error.
func New(b *attest.Bundle) (*Verifier, error) {
	if b == nil {
		return nil, errors.New("piv: no attestation bundle")
	}
	return &Verifier{b: b}, nil
}

// Slots returns the 24 slot names in the order of record 0003, rule 3: 9a, 9c, 9d, 9e, then 82 to 95
// (hexadecimal, lower case). It returns a new slice at each call.
func Slots() []string {
	s := []string{"9a", "9c", "9d", "9e"}
	for n := 0x82; n <= 0x95; n++ {
		s = append(s, strconv.FormatInt(int64(n), 16))
	}
	return s
}

// subjectPrefix is the common name of a slot certificate before the slot.
const subjectPrefix = "YubiKey PIV Attestation "

// The extensions of the slot certificate that are read ("piv": Extension 1.3.6.1.4.1.41482.3.…).
var (
	oidFirmware   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
	oidFormFactor = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}
	oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// Verify implements [handoff.EvidenceVerifier] for the store piv. r is not read. It returns evidence only
// when the chain verified at now and every value of the slot certificate was read:
//
//   - the slot certificate's subject is exactly one common name, "YubiKey PIV Attestation " and a slot of
//     [Slots];
//   - the extensions .3, .7 and .8 are present once each, and .9 may be absent;
//   - Firmware is "a.b.c" from the three raw octets of .3; the serial is a positive DER INTEGER of at
//     most 8 octets, in decimal in Details["serial"]; PINPolicy is never, once or always and
//     TouchPolicy is never, always or cached, from the two octets of .8; the form factor is one
//     octet, in decimal in Details["form_factor"] when present.
//
// Details also holds "slot", "policy_read" = "true" and the version and the digest of the bundle. A refusal
// is a *[handoff.CodeError] with proof-invalid or malformed. A done or nil context, a nil proof, a proof of
// another store, a zero now and a zero Verifier are errors that are not a refusal.
func (v *Verifier) Verify(ctx context.Context, r *handoff.Request, p *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
	if v == nil || v.b == nil {
		return nil, errors.New("piv: the verifier was not made by New")
	}
	att, err := v.b.Attest(ctx, attest.AppletPIV, p, now)
	if err != nil {
		return nil, err
	}
	leaf := att.Leaf

	slot, err := slotOf(leaf)
	if err != nil {
		return nil, refuse(err.Error())
	}
	var fw, serial, policy, form []byte
	var have [4]bool
	for _, e := range leaf.Extensions {
		var dst *[]byte
		var i int
		switch {
		case e.Id.Equal(oidFirmware):
			dst, i = &fw, 0
		case e.Id.Equal(oidSerial):
			dst, i = &serial, 1
		case e.Id.Equal(oidPolicy):
			dst, i = &policy, 2
		case e.Id.Equal(oidFormFactor):
			dst, i = &form, 3
		default:
			continue
		}
		if have[i] {
			return nil, refuse("the key's certificate has an extension twice")
		}
		have[i] = true
		*dst = bytes.Clone(e.Value)
	}
	if !have[0] || !have[1] || !have[2] {
		return nil, refuse("the key's certificate lacks the firmware, the serial number or the policy extension")
	}
	ev := &handoff.Evidence{}
	if ev.Firmware, err = decodeFirmware(fw); err != nil {
		return nil, refuse(err.Error())
	}
	sn, err := decodeSerial(serial)
	if err != nil {
		return nil, refuse(err.Error())
	}
	if ev.PINPolicy, ev.TouchPolicy, err = decodePolicy(policy); err != nil {
		return nil, refuse(err.Error())
	}
	details := map[string]string{
		attest.DetailSlot:          slot,
		attest.DetailSerial:        sn,
		attest.DetailPolicyRead:    "true",
		attest.DetailBundleVersion: v.b.Version(),
		attest.DetailBundleSHA256:  v.b.SHA256(),
	}
	if have[3] {
		ff, err := decodeFormFactor(form)
		if err != nil {
			return nil, refuse(err.Error())
		}
		details[attest.DetailFormFactor] = ff
	}
	if ev.Key, err = attest.KeyOf(leaf); err != nil {
		return nil, err
	}
	ev.Details = details
	return ev, nil
}

// refuse makes the refusal of the evidence with fixed words.
func refuse(detail string) error {
	return &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: detail}
}

// slotOf reads the subject of a slot certificate: exactly one relative name with one attribute, the common
// name, whose value is "YubiKey PIV Attestation " and one slot of [Slots]. The value is a UTF8String or a
// PrintableString. The error says in fixed words what was wrong.
func slotOf(leaf *x509.Certificate) (string, error) {
	cn, ok := soleCommonName(leaf.RawSubject)
	if !ok {
		return "", errors.New("the subject of the slot certificate is not one common name")
	}
	slot, found := strings.CutPrefix(cn, subjectPrefix)
	if !found {
		return "", errors.New("the subject of the slot certificate is not a PIV attestation of a slot")
	}
	for _, s := range Slots() {
		if slot == s {
			return s, nil
		}
	}
	return "", errors.New("the subject of the slot certificate names no slot of the PIV applet")
}

// soleCommonName reads a DER name that is one relative name of one attribute, the common name, as a
// UTF8String or a PrintableString, and returns its value.
func soleCommonName(rawSubject []byte) (string, bool) {
	seq, ok := oneValue(rawSubject, asn1.TagSequence)
	if !ok {
		return "", false
	}
	set, ok := oneValue(seq, asn1.TagSet)
	if !ok {
		return "", false
	}
	atv, ok := oneValue(set, asn1.TagSequence)
	if !ok {
		return "", false
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(atv, &oid)
	if err != nil || !oid.Equal(oidCommonName) {
		return "", false
	}
	var val asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &val)
	if err != nil || len(rest) != 0 || val.Class != asn1.ClassUniversal || val.IsCompound {
		return "", false
	}
	if val.Tag != asn1.TagUTF8String && val.Tag != asn1.TagPrintableString {
		return "", false
	}
	return string(val.Bytes), true
}

// oneValue reads one universal, constructed value of the tag and nothing after it, and returns its content.
func oneValue(der []byte, tag int) ([]byte, bool) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil || len(rest) != 0 || v.Class != asn1.ClassUniversal || v.Tag != tag || !v.IsCompound {
		return nil, false
	}
	return v.Bytes, true
}

// decodeFirmware reads extension .3: three raw octets, major, minor and patch, written "5.8.0".
func decodeFirmware(v []byte) (string, error) {
	if len(v) != 3 {
		return "", errors.New("the firmware extension is not three octets")
	}
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]), nil
}

// decodeSerial reads extension .7: one DER INTEGER and nothing after it, positive, in its shortest form,
// with at most 8 octets of content. It returns the number in decimal.
func decodeSerial(v []byte) (string, error) {
	const bad = "the serial number extension is not a positive DER INTEGER of at most 8 octets"
	if len(v) < 3 || v[0] != 0x02 || int(v[1]) != len(v)-2 || v[1] > 8 {
		return "", errors.New(bad)
	}
	c := v[2:]
	if c[0]&0x80 != 0 {
		return "", errors.New(bad)
	}
	if len(c) > 1 && c[0] == 0 && c[1]&0x80 == 0 {
		return "", errors.New(bad)
	}
	var n uint64
	for _, b := range c {
		n = n<<8 | uint64(b)
	}
	if n == 0 {
		return "", errors.New(bad)
	}
	return strconv.FormatUint(n, 10), nil
}

// decodePolicy reads extension .8: two raw octets, the PIN policy (1 never, 2 once, 3 always) and then the
// touch policy (1 never, 2 always, 3 cached).
func decodePolicy(v []byte) (handoff.PINPolicy, string, error) {
	if len(v) != 2 {
		return "", "", errors.New("the policy extension is not two octets")
	}
	var pin handoff.PINPolicy
	switch v[0] {
	case 1:
		pin = handoff.PINNever
	case 2:
		pin = handoff.PINOnce
	case 3:
		pin = handoff.PINAlways
	default:
		return "", "", errors.New("the PIN policy of the policy extension is not known")
	}
	var touch string
	switch v[1] {
	case 1:
		touch = "never"
	case 2:
		touch = "always"
	case 3:
		touch = "cached"
	default:
		return "", "", errors.New("the touch policy of the policy extension is not known")
	}
	return pin, touch, nil
}

// decodeFormFactor reads extension .9: one raw octet, written in decimal.
func decodeFormFactor(v []byte) (string, error) {
	if len(v) != 1 {
		return "", errors.New("the form factor extension is not one octet")
	}
	return strconv.Itoa(int(v[0])), nil
}
