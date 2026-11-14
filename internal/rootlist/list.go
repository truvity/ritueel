// Package rootlist is the host's side of the signed root list: it reads root-list.json, checks it
// and its detached signature in the eleven checks of docs/reference/root-list.md ("How a host reads
// it"), checks a removal authorisation, and checks a CA bundle against a list. It signs and writes
// nothing. The signature code is package jws; the JSON rules are those of package strictjson.
//
// The one rule that runs through the package: the host verifies the bytes it received. The bytes
// of root-list.json are hashed as they were read and never written again, a list is read into a
// struct only after its signature has been checked, and what is compared with the list the host
// holds (check 7) is the bytes of both files. Nothing here calls a function that writes JSON.
package rootlist

import (
	"errors"
	"fmt"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
)

// MaxBytes is the most bytes of root-list.json, of root-list.jws and of a CA bundle that this
// package takes: 256 KiB, the limit of the page for the list.
const MaxBytes = strictjson.DefaultMaxBytes

// TimeLayout is the one form of a time of the list: YYYY-MM-DDThh:mm:ssZ, UTC, whole seconds.
const TimeLayout = "2006-01-02T15:04:05Z"

// Version is the version of the format that this package reads.
const Version = 1

// ErrUnsupportedVersion is wrapped by the error of reading a list whose version is another
// integer than 1.
var ErrUnsupportedVersion = errors.New("unsupported root list version")

// Root is an entry of the member roots: one key label with its pins.
type Root struct {
	// Label is one upper-case letter.
	Label string
	// X509SPKISHA256 is the pin: SHA-256 of the DER SubjectPublicKeyInfo, 64 lower-case hex digits.
	X509SPKISHA256 string
	// OpenPGPFingerprint is the fingerprint of the OpenPGP primary, 40 lower-case hex digits; empty
	// when the entry has none.
	OpenPGPFingerprint string
}

// Removal is an entry of the member removals.
type Removal struct {
	// Label is one upper-case letter.
	Label string
	// X509SPKISHA256 is the pin of the root key that leaves.
	X509SPKISHA256 string
	// Authorisation is the removal authorisation of that key as a compact JWS.
	Authorisation string
}

// List is root-list.json as it was read.
type List struct {
	// Version is always 1.
	Version int
	// Sequence is the trust sequence, at least 1.
	Sequence int64
	// SignedAt and ExpiresAt are in UTC.
	SignedAt, ExpiresAt time.Time
	// Roots are the active root keys, in the order of the file; there is at least one.
	Roots []Root
	// LastRecordSHA256 is empty in the first list.
	LastRecordSHA256 string
	// Removals are the entries of the member removals, in the order of the file; none when the
	// member is absent.
	Removals []Removal
}

// Pins returns the pins of the root keys of the list, in the order of the list; none for a nil list.
func (l *List) Pins() []string {
	if l == nil {
		return nil
	}
	out := make([]string, len(l.Roots))
	for i, r := range l.Roots {
		out[i] = r.X509SPKISHA256
	}
	return out
}

type rootJSON struct {
	Label       *string `json:"label"`
	X509        *string `json:"x509_spki_sha256"`
	Fingerprint *string `json:"openpgp_fingerprint"`
}

type removalJSON struct {
	Label         *string `json:"label"`
	X509          *string `json:"x509_spki_sha256"`
	Authorisation *string `json:"authorisation"`
}

type listJSON struct {
	Version          *int64        `json:"version"`
	Sequence         *int64        `json:"sequence"`
	SignedAt         *string       `json:"signed_at"`
	ExpiresAt        *string       `json:"expires_at"`
	Roots            []rootJSON    `json:"roots"`
	LastRecordSHA256 *string       `json:"last_record_sha256"`
	Removals         []removalJSON `json:"removals"`
}

func path(steps ...jsonset.Step) jsonset.Path { return steps }

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

// isLabel reports whether s is one upper-case ASCII letter.
func isLabel(s string) bool { return len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' }

// ExpiryMonths is how long a list lives: 13 calendar months from signed_at.
const ExpiryMonths = 13

// ExpiresFor is the expires_at that a list signed at signedAt must carry: ExpiryMonths calendar
// months later, on the same day and at the same time of the month, or on the last day of the month
// if it has none (the rule of "The list" in docs/reference/root-list.md, the same as for an
// intermediate). It is the one place of the arithmetic, for the host's check 5 and for the writer
// of a list. signedAt is taken in UTC.
func ExpiresFor(signedAt time.Time) time.Time {
	t := signedAt.UTC()
	y, m, d := t.Date()
	// The first day of the target month, then the day clamped to the length of that month.
	first := time.Date(y, m+ExpiryMonths, 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	last := first.AddDate(0, 1, -1).Day()
	return time.Date(first.Year(), first.Month(), min(d, last), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}

// parseTime reads a time in the one form of the page and nothing else: the text must be what
// TimeLayout writes for the time it names.
func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil || t.Format(TimeLayout) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ParseList reads root-list.json under the rules of the page: the JSON rules of package strictjson
// (one object of at most 256 KiB, no unknown or repeated member, integers only, no null), the
// members of "The list", and the forms of their values. It does not check a signature, and it does
// not require the canonical form: the writer's form is not a rule of the host, which never writes
// the list again. A list of another version than 1 gives an error that wraps ErrUnsupportedVersion,
// any other fault an error that wraps strictjson.ErrMalformed.
//
// Two forms are not on the page and are the smallest refusal that keeps a list a set: a label or
// a pin twice among roots, and a pin twice among removals, are refused; and an OpenPGP
// fingerprint is 40 lower-case hexadecimal digits (the page says "hexadecimal digits").
func ParseList(data []byte) (*List, error) {
	var raw listJSON
	if err := strictjson.Unmarshal(data, &raw, strictjson.Options{MaxBytes: MaxBytes}); err != nil {
		return nil, err
	}
	l := &List{Version: Version}
	if raw.Version == nil {
		return nil, jsonset.Errorf(path(jsonset.Member("version")), "the member is required")
	}
	if *raw.Version != Version {
		return nil, fmt.Errorf("%w: version %d", ErrUnsupportedVersion, *raw.Version)
	}
	if raw.Sequence == nil {
		return nil, jsonset.Errorf(path(jsonset.Member("sequence")), "the member is required")
	}
	if *raw.Sequence < 1 {
		return nil, jsonset.Errorf(path(jsonset.Member("sequence")), "must be an integer of at least 1")
	}
	l.Sequence = *raw.Sequence
	var ok bool
	if l.SignedAt, ok = timeMember(raw.SignedAt); !ok {
		return nil, timeError("signed_at", raw.SignedAt)
	}
	if l.ExpiresAt, ok = timeMember(raw.ExpiresAt); !ok {
		return nil, timeError("expires_at", raw.ExpiresAt)
	}
	if len(raw.Roots) == 0 {
		return nil, jsonset.Errorf(path(jsonset.Member("roots")), "the member is required and holds at least one root key")
	}
	labels := map[string]bool{}
	pins := map[string]bool{}
	for i, r := range raw.Roots {
		at := func(name string) jsonset.Path {
			return path(jsonset.Member("roots"), jsonset.Element(i), jsonset.Member(name))
		}
		if r.Label == nil || !isLabel(*r.Label) {
			return nil, jsonset.Errorf(at("label"), "the member is required and is one upper-case letter A to Z")
		}
		if r.X509 == nil || !isLowerHex(*r.X509, 64) {
			return nil, jsonset.Errorf(at("x509_spki_sha256"), "the member is required and is 64 lower-case hexadecimal digits")
		}
		root := Root{Label: *r.Label, X509SPKISHA256: *r.X509}
		if r.Fingerprint != nil {
			if !isLowerHex(*r.Fingerprint, 40) {
				return nil, jsonset.Errorf(at("openpgp_fingerprint"), "must be 40 lower-case hexadecimal digits")
			}
			root.OpenPGPFingerprint = *r.Fingerprint
		}
		if labels[root.Label] {
			return nil, jsonset.Errorf(at("label"), "the label appears twice")
		}
		if pins[root.X509SPKISHA256] {
			return nil, jsonset.Errorf(at("x509_spki_sha256"), "the pin appears twice")
		}
		labels[root.Label], pins[root.X509SPKISHA256] = true, true
		l.Roots = append(l.Roots, root)
	}
	if raw.LastRecordSHA256 != nil {
		if !isLowerHex(*raw.LastRecordSHA256, 64) {
			return nil, jsonset.Errorf(path(jsonset.Member("last_record_sha256")), "must be 64 lower-case hexadecimal digits")
		}
		l.LastRecordSHA256 = *raw.LastRecordSHA256
	}
	removed := map[string]bool{}
	for i, r := range raw.Removals {
		at := func(name string) jsonset.Path {
			return path(jsonset.Member("removals"), jsonset.Element(i), jsonset.Member(name))
		}
		if r.Label == nil || !isLabel(*r.Label) {
			return nil, jsonset.Errorf(at("label"), "the member is required and is one upper-case letter A to Z")
		}
		if r.X509 == nil || !isLowerHex(*r.X509, 64) {
			return nil, jsonset.Errorf(at("x509_spki_sha256"), "the member is required and is 64 lower-case hexadecimal digits")
		}
		if r.Authorisation == nil || *r.Authorisation == "" {
			return nil, jsonset.Errorf(at("authorisation"), "the member is required and is not empty")
		}
		if removed[*r.X509] {
			return nil, jsonset.Errorf(at("x509_spki_sha256"), "the pin appears twice")
		}
		removed[*r.X509] = true
		l.Removals = append(l.Removals, Removal{Label: *r.Label, X509SPKISHA256: *r.X509, Authorisation: *r.Authorisation})
	}
	return l, nil
}

func timeMember(s *string) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	return parseTime(*s)
}

func timeError(name string, s *string) error {
	if s == nil {
		return jsonset.Errorf(path(jsonset.Member(name)), "the member is required")
	}
	return jsonset.Errorf(path(jsonset.Member(name)), "must be a time in the form YYYY-MM-DDThh:mm:ssZ, UTC, whole seconds")
}
