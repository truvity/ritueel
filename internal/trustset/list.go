package trustset

import (
	"slices"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
)

// Root is one entry of roots: a key label with its pins (the list page's "Each member of roots").
type Root struct {
	// Label is one of A to Z.
	Label string
	// X509SPKISHA256 is the pin: 64 lower-case hexadecimal digits.
	X509SPKISHA256 string
	// OpenPGPFingerprint is 40 lower-case hexadecimal digits, or empty for a bundle with no
	// OpenPGP root.
	OpenPGPFingerprint string
}

// Removal is one entry of removals.
type Removal struct {
	// Label is the label of the removed key, as the list that held it wrote it.
	Label string
	// X509SPKISHA256 is the pin of the removed key.
	X509SPKISHA256 string
	// Authorisation is the compact JWS of the removal authorisation, as stored.
	Authorisation string
}

// ListSpec is everything root-list.json holds. Nothing in it is read from the clock, and
// expires_at is not in it: it is computed from SignedAt.
type ListSpec struct {
	// Sequence is the trust sequence: 1 to strictjson.MaxSafeInt.
	Sequence int64
	// SignedAt is the time of the ceremony, in whole seconds, in the years 1 to 9999.
	SignedAt time.Time
	// Roots are the active root keys, in any order; the list writes them in label order.
	Roots []Root
	// LastRecordSHA256 is 64 lower-case hexadecimal digits, and empty exactly when Sequence is 1.
	LastRecordSHA256 string
	// Removals may be empty; the list writes them in label order.
	Removals []Removal
}

// The members of the list as the writer spells them. The canonical form sorts the members, so the
// order of the fields here is only for reading.
type rootDoc struct {
	Label       string `json:"label"`
	Fingerprint string `json:"openpgp_fingerprint,omitempty"`
	X509        string `json:"x509_spki_sha256"`
}

type removalDoc struct {
	Authorisation string `json:"authorisation"`
	Label         string `json:"label"`
	X509          string `json:"x509_spki_sha256"`
}

type listDoc struct {
	ExpiresAt        string       `json:"expires_at"`
	LastRecordSHA256 string       `json:"last_record_sha256,omitempty"`
	Removals         []removalDoc `json:"removals,omitempty"`
	Roots            []rootDoc    `json:"roots"`
	Sequence         int64        `json:"sequence"`
	SignedAt         string       `json:"signed_at"`
	Version          int          `json:"version"`
}

// MarshalList returns the bytes of root-list.json: one canonical JSON object (RFC 8785, through
// package canonjson), no trailing newline, with expires_at equal to rootlist.ExpiresFor(SignedAt).
// It writes roots in label order and removals in label order. It refuses what rootlist.ParseList
// refuses (a sequence below 1 or above strictjson.MaxSafeInt, no root, more than MaxRoots, a label
// that is not A to Z, a label or a pin twice, a pin or a fingerprint of the wrong form, a digest of
// the wrong form, an empty authorisation, a pin twice in removals), a label twice in removals, a
// pin that stands in roots and in removals, a SignedAt that is the zero time, a fingerprint twice,
// entries of which some have a fingerprint and some have none, a last_record_sha256 given in the
// first list or missing in a later one, a SignedAt with a fraction of a second or outside the
// years 1 to 9999, an expires_at that would pass the year 9999, more than MaxRoots removals, and
// an output over MaxBytes. The bytes are read back with rootlist.ParseList and must give the spec
// again; nothing is returned otherwise. It judges no signature and no authorisation. Every error
// wraps ErrParams, and no bytes come with an error.
func MarshalList(spec ListSpec) ([]byte, error) {
	if err := checkSequence(spec.Sequence); err != nil {
		return nil, err
	}
	signed, expires, err := listTimes(spec.SignedAt)
	if err != nil {
		return nil, err
	}
	if err := checkRoots(spec.Roots); err != nil {
		return nil, err
	}
	if err := checkAnchor(spec.Sequence, spec.LastRecordSHA256); err != nil {
		return nil, err
	}
	if err := checkRemovals(spec.Removals, spec.Roots); err != nil {
		return nil, err
	}
	roots := sortRoots(spec.Roots)
	removals := sortRemovals(spec.Removals)

	doc := listDoc{
		ExpiresAt:        expires.Format(rootlist.TimeLayout),
		LastRecordSHA256: spec.LastRecordSHA256,
		Roots:            make([]rootDoc, len(roots)),
		Sequence:         spec.Sequence,
		SignedAt:         signed.Format(rootlist.TimeLayout),
		Version:          rootlist.Version,
	}
	for i, r := range roots {
		doc.Roots[i] = rootDoc{Label: r.Label, Fingerprint: r.OpenPGPFingerprint, X509: r.X509SPKISHA256}
	}
	for _, r := range removals {
		doc.Removals = append(doc.Removals, removalDoc{Authorisation: r.Authorisation, Label: r.Label, X509: r.X509SPKISHA256})
	}
	out, err := canonjson.Marshal(doc)
	if err != nil {
		return nil, failWith(ErrParams, "the list cannot be written", err)
	}
	if len(out) > MaxBytes {
		return nil, fail(ErrParams, "root-list.json is longer than %d bytes", MaxBytes)
	}
	if err := readBack(out, spec, roots, removals, signed, expires); err != nil {
		return nil, err
	}
	return out, nil
}

// readBack reads the bytes with the reader of the page and demands the spec again, in canonical
// form: the builder never invents a second reading of its own output.
func readBack(out []byte, spec ListSpec, roots []Root, removals []Removal, signed, expires time.Time) error {
	l, err := rootlist.ParseList(out)
	if err != nil {
		return failWith(ErrParams, "the reader of the page refuses the list that was written", err)
	}
	ok := l.Version == rootlist.Version &&
		l.Sequence == spec.Sequence &&
		l.SignedAt.Equal(signed) &&
		l.ExpiresAt.Equal(expires) &&
		l.LastRecordSHA256 == spec.LastRecordSHA256 &&
		len(l.Roots) == len(roots) &&
		len(l.Removals) == len(removals)
	for i := 0; ok && i < len(roots); i++ {
		ok = l.Roots[i] == rootlist.Root(roots[i])
	}
	for i := 0; ok && i < len(removals); i++ {
		ok = l.Removals[i] == rootlist.Removal(removals[i])
	}
	if !ok {
		return fail(ErrParams, "the list that was written reads back as another list")
	}
	if canonical, err := canonjson.IsCanonical(out); err != nil || !canonical {
		return fail(ErrParams, "the list that was written is not in the canonical form")
	}
	return nil
}

// checkSequence takes the sequence of a list: 1 to strictjson.MaxSafeInt.
func checkSequence(sequence int64) error {
	if sequence < 1 || sequence > strictjson.MaxSafeInt {
		return fail(ErrParams, "the sequence %d is not an integer from 1 to %d", sequence, int64(strictjson.MaxSafeInt))
	}
	return nil
}

// listTimes returns signed_at in UTC and the expires_at of the page for it. signed_at has no
// fraction of a second and neither time leaves the years 1 to 9999.
func listTimes(signedAt time.Time) (signed, expires time.Time, err error) {
	if signedAt.IsZero() {
		return time.Time{}, time.Time{}, fail(ErrParams, "signed_at is not given")
	}
	signed = signedAt.UTC()
	if signed.Nanosecond() != 0 {
		return time.Time{}, time.Time{}, fail(ErrParams, "signed_at has a fraction of a second")
	}
	if y := signed.Year(); y < 1 || y > 9999 {
		return time.Time{}, time.Time{}, fail(ErrParams, "signed_at is outside the years 1 to 9999")
	}
	expires = rootlist.ExpiresFor(signed)
	if y := expires.Year(); y < 1 || y > 9999 {
		return time.Time{}, time.Time{}, fail(ErrParams, "expires_at is outside the years 1 to 9999")
	}
	return signed, expires, nil
}

// checkRoots takes the entries of roots: one to MaxRoots, each with a label, a pin and, for all or
// for none, a fingerprint; no label, pin or fingerprint twice.
func checkRoots(roots []Root) error {
	if len(roots) == 0 {
		return fail(ErrParams, "a list holds at least one root key")
	}
	if len(roots) > MaxRoots {
		return fail(ErrParams, "a list holds at most %d root keys, there are %d", MaxRoots, len(roots))
	}
	labels := make(map[string]bool, len(roots))
	pins := make(map[string]bool, len(roots))
	prints := make(map[string]bool, len(roots))
	withPrint := 0
	for i, r := range roots {
		if !isLabel(r.Label) {
			return fail(ErrParams, "root %d: the label is not one upper-case letter A to Z", i)
		}
		if !isLowerHex(r.X509SPKISHA256, 64) {
			return fail(ErrParams, "root %s: the pin is not 64 lower-case hexadecimal digits", r.Label)
		}
		if labels[r.Label] {
			return fail(ErrParams, "the label %s appears twice", r.Label)
		}
		if pins[r.X509SPKISHA256] {
			return fail(ErrParams, "root %s: the pin appears twice", r.Label)
		}
		labels[r.Label], pins[r.X509SPKISHA256] = true, true
		if r.OpenPGPFingerprint == "" {
			continue
		}
		if !isLowerHex(r.OpenPGPFingerprint, 40) {
			return fail(ErrParams, "root %s: the fingerprint is not 40 lower-case hexadecimal digits", r.Label)
		}
		if prints[r.OpenPGPFingerprint] {
			return fail(ErrParams, "root %s: the fingerprint appears twice", r.Label)
		}
		prints[r.OpenPGPFingerprint] = true
		withPrint++
	}
	if mixedFingerprints && withPrint != 0 && withPrint != len(roots) {
		return fail(ErrParams, "some roots have an OpenPGP fingerprint and some have none")
	}
	return nil
}

// mixedFingerprints is the one switch of the proposed rule that all entries of a list have an
// OpenPGP fingerprint or none has. The list page ties the member to the bundle ("when the bundle
// has an OpenPGP root") and record 0006, rule 17 to the key; no vector has a mixed list.
const mixedFingerprints = true

// checkAnchor takes last_record_sha256: absent exactly in the first list.
func checkAnchor(sequence int64, anchor string) error {
	if sequence == 1 {
		if anchor != "" {
			return fail(ErrParams, "the first list has no last_record_sha256")
		}
		return nil
	}
	if !isLowerHex(anchor, 64) {
		return fail(ErrParams, "last_record_sha256 is required after the first list and is 64 lower-case hexadecimal digits")
	}
	return nil
}

// checkRemovals takes the entries of removals: at most MaxRoots, each with a label, a pin and a
// non-empty authorisation of at most MaxBytes; no label twice (a label names a key and is never
// used again) and no pin twice; no pin that is also the pin of an entry of roots (a host refuses
// such a list: the removed key is "not on this list"). It does not read the authorisation.
func checkRemovals(removals []Removal, roots []Root) error {
	if len(removals) > MaxRoots {
		return fail(ErrParams, "a list holds at most %d removals, there are %d", MaxRoots, len(removals))
	}
	active := make(map[string]bool, len(roots))
	for _, r := range roots {
		active[r.X509SPKISHA256] = true
	}
	labels := make(map[string]bool, len(removals))
	pins := make(map[string]bool, len(removals))
	for i, r := range removals {
		if !isLabel(r.Label) {
			return fail(ErrParams, "removal %d: the label is not one upper-case letter A to Z", i)
		}
		if !isLowerHex(r.X509SPKISHA256, 64) {
			return fail(ErrParams, "removal %s: the pin is not 64 lower-case hexadecimal digits", r.Label)
		}
		if r.Authorisation == "" {
			return fail(ErrParams, "removal %s: the authorisation is empty", r.Label)
		}
		if len(r.Authorisation) > MaxBytes {
			return fail(ErrParams, "removal %s: the authorisation is longer than %d bytes", r.Label, MaxBytes)
		}
		if labels[r.Label] {
			return fail(ErrParams, "removal %s: the label appears twice in removals", r.Label)
		}
		if pins[r.X509SPKISHA256] {
			return fail(ErrParams, "removal %s: the pin appears twice", r.Label)
		}
		if active[r.X509SPKISHA256] {
			return fail(ErrParams, "removal %s: the pin is also the pin of a root key of the list", r.Label)
		}
		labels[r.Label], pins[r.X509SPKISHA256] = true, true
	}
	return nil
}

// sortRoots returns a copy of roots in label order: the one order of roots that the writer uses
// (the page says "a fixed order" and does not say which; every vector list is in label order).
func sortRoots(roots []Root) []Root {
	out := slices.Clone(roots)
	slices.SortStableFunc(out, func(a, b Root) int { return strings.Compare(a.Label, b.Label) })
	return out
}

// sortRemovals returns a copy of removals in label order (list page, "The list").
func sortRemovals(removals []Removal) []Removal {
	out := slices.Clone(removals)
	slices.SortStableFunc(out, func(a, b Removal) int { return strings.Compare(a.Label, b.Label) })
	return out
}

// isLabel reports whether s is one upper-case ASCII letter.
func isLabel(s string) bool { return len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' }

// isLowerHex reports whether s is exactly n lower-case hexadecimal digits.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
