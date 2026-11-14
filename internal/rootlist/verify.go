package rootlist

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/strictjson"
)

// Reason is a reason code of the page, the code of the first check that fails.
type Reason string

// The reason codes of docs/reference/root-list.md.
const (
	// Malformed is a file that breaks the form of the page (checks 1 and 5).
	Malformed Reason = "malformed"
	// UnknownSigner is a signature by a key the host does not know (checks 2 and 8).
	UnknownSigner Reason = "unknown-signer"
	// SignatureInvalid is a signature that does not verify (check 3).
	SignatureInvalid Reason = "signature-invalid"
	// VersionUnsupported is a version other than 1 (check 4).
	VersionUnsupported Reason = "version-unsupported"
	// Rollback is a sequence lower than the held one (check 6).
	Rollback Reason = "rollback"
	// SequenceConflict is another list at the held sequence (check 7).
	SequenceConflict Reason = "sequence-conflict"
	// RemovalInvalid is a removals entry that is not a valid authorisation (check 9).
	RemovalInvalid Reason = "removal-invalid"
	// InsufficientSigners is a change of the root keys without the signatures it needs (check 10).
	InsufficientSigners Reason = "insufficient-signers"
	// Expired is a list whose expires_at has passed (check 11).
	Expired Reason = "expired"
	// CABundleMismatch is a CA bundle that does not match the list (not one of the eleven).
	CABundleMismatch Reason = "ca-bundle-mismatch"
)

// WarningHeldExpired is the warning of a held list that has expired and has not been replaced.
const WarningHeldExpired = "held-expired"

// Signed is a root list as the host received it: the two files, as read.
type Signed struct {
	// JSON is root-list.json.
	JSON []byte
	// JWS is root-list.jws.
	JWS []byte
}

// Held is the list the host holds: the last good one. Only its root-list.json counts: the host
// accepted it once, and a signature over it cannot be checked alone, since a root key that signed
// it may be off the list by now (check 8 reads the list before it).
type Held struct {
	// List is the list, read from JSON.
	List *List
	// JSON is the bytes of root-list.json, as the host holds them; check 7 compares them.
	JSON []byte
}

// ParseHeld reads the root-list.json that a host holds. It takes the rules of ParseList. The error
// is the host's own: a held list that cannot be read is no refusal of a candidate.
func ParseHeld(jsonData []byte) (*Held, error) {
	l, err := ParseList(jsonData)
	if err != nil {
		return nil, err
	}
	return &Held{List: l, JSON: bytes.Clone(jsonData)}, nil
}

// Trust is what the host trusts before a candidate arrives: the list it holds, or its initial
// pins. Make one with HeldTrust or PinTrust; the zero value trusts nothing, and every candidate
// is refused with unknown-signer.
type Trust struct {
	held *Held
	pins []string
	// minSequence is the lowest sequence that a host with only pins accepts; 0 when it has not
	// given one. It is set by WithMinSequence and only on a Trust made by PinTrust.
	minSequence int64
}

// WithMinSequence returns the trust with a lowest sequence: a list whose sequence is lower is
// refused with Rollback in check 6, which a host with only pins has no held sequence to do. It
// applies to a Trust made by PinTrust and to no other (a host that holds a list has the sequence
// of that list), and n must be at least 1 and at most strictjson.MaxSafeInt, the range of the
// sequence in the list. Without it nothing changes.
func (t Trust) WithMinSequence(n int64) (Trust, error) {
	if t.held != nil || len(t.pins) == 0 {
		return Trust{}, fmt.Errorf("a lowest sequence is for initial pins; a host that holds a list has its sequence")
	}
	if n < 1 || n > strictjson.MaxSafeInt {
		return Trust{}, fmt.Errorf("the lowest sequence must be an integer from 1 to %d", int64(strictjson.MaxSafeInt))
	}
	t.minSequence = n
	return t, nil
}

// HeldTrust is the trust of a host that holds a list. A nil Held, and a Held that has no list
// (the zero value), hold nothing: the trust is then the zero Trust, which trusts nothing. This is
// the one place where a Held enters a Trust, and Trust has no exported field, so every Trust that
// Verify meets has either a held list with its List set, or none.
func HeldTrust(h *Held) Trust {
	if h == nil || h.List == nil {
		return Trust{}
	}
	return Trust{held: h}
}

// PinTrust is the trust of a host that holds initial pins: the x509_spki_sha256 of the root keys
// it was installed to trust. Each must be 64 lower-case hexadecimal digits; a pin given twice
// counts once. At least one is needed.
func PinTrust(pins []string) (Trust, error) {
	if len(pins) == 0 {
		return Trust{}, fmt.Errorf("at least one initial pin is needed")
	}
	var out []string
	for _, p := range pins {
		if !isLowerHex(p, 64) {
			return Trust{}, fmt.Errorf("the pin %s is not 64 lower-case hexadecimal digits", jsonset.Quote(p))
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return Trust{pins: out}, nil
}

// pins are the pins of the root keys the host trusts: the active root keys of the held list, or
// the initial pins.
func (t Trust) trusted() []string {
	if t.held != nil {
		return t.held.List.Pins()
	}
	return t.pins
}

// Verdict is the outcome of checking one list.
type Verdict struct {
	// Accepted is true when every check passed.
	Accepted bool
	// Reason is the code of the first check that failed; empty when Accepted.
	Reason Reason
	// Check is the number of the check that failed, 1 to 11; 0 for a CA bundle and when Accepted.
	Check int
	// Detail says what is wrong, for a person. It is printable ASCII only, whatever the files held,
	// and its wording is not part of any format.
	Detail string
	// List is the list that was accepted; nil when it was refused.
	List *List
	// Again is true for an accepted list that is the held list again: the same sequence and the
	// same bytes of root-list.json. Such a list brings nothing new (see againOf), and a caller that
	// replaces the held list with it replaces it with an identical file. It is false for every
	// refusal and for every list that is new.
	Again bool
}

// CheckInfo describes one of the eleven checks.
type CheckInfo struct {
	// N is the number of the check on the page, 1 to 11.
	N int
	// Name says what the check looks at.
	Name string
	// Reason is the code a failure gives.
	Reason Reason
}

// state is what the checks share: the inputs and what earlier checks read.
type state struct {
	cand Signed
	t    Trust
	now  time.Time

	sigs *jws.General // set by check 1
	list *List        // set by check 5
	// again is set by check 7: the candidate is the held list again. Checks 8, 9 and 10 do not
	// apply to it (see againOf).
	again bool
}

func (s *state) kids() []string {
	out := make([]string, len(s.sigs.Signatures))
	for i, sg := range s.sigs.Signatures {
		out[i] = sg.Header.Kid
	}
	return out
}

// check is one row of the table of "How a host reads it". run returns what is wrong when the check
// fails, and ok when it passes.
type check struct {
	n      int
	name   string
	reason Reason
	run    func(*state) (detail string, ok bool)
}

// checks is the table of the page, in its order: the one place where the order is written. Verify
// runs the rows in order and stops at the first failure, and no row is skipped.
var checks = []check{
	{1, "root-list.jws is a detached general JWS of the form of the page", Malformed, checkJWSForm},
	{2, "a signer is a root key of the held list or an initial pin", UnknownSigner, checkSomeSignerKnown},
	{3, "every signature verifies over the bytes of root-list.json", SignatureInvalid, checkSignatures},
	{4, "version is 1", VersionUnsupported, checkVersion},
	{5, "root-list.json follows the JSON rules and the members", Malformed, checkMembers},
	{6, "sequence is not lower than the held one", Rollback, checkNotRollback},
	{7, "at the held sequence the list is the held list", SequenceConflict, checkSameSequence},
	{8, "every signer is a root key of the held list or of this list", UnknownSigner, ofANewList(checkAllSignersKnown)},
	{9, "every removals entry is a valid authorisation", RemovalInvalid, ofANewList(checkRemovals)},
	{10, "a change of the root keys has the signatures it needs", InsufficientSigners, ofANewList(checkSigners)},
	{11, "the clock is before expires_at", Expired, checkNotExpired},
}

// Checks returns the eleven checks in the order Verify runs them.
func Checks() []CheckInfo {
	out := make([]CheckInfo, len(checks))
	for i, c := range checks {
		out[i] = CheckInfo{N: c.n, Name: c.name, Reason: c.reason}
	}
	return out
}

// Verify runs the eleven checks of "How a host reads it" on a candidate, in their order, and stops
// at the first that fails. The signature is checked over cand.JSON as it is, before any member of
// it is read (checks 1 to 3), and nothing is written again. It never panics, whatever the bytes.
// A host that holds nothing it can trust (the zero Trust) refuses every candidate at check 2.
//
// Verify says nothing of the held list's expiry, which is a warning and not a refusal (see
// CheckHeld), and does not look at a CA bundle (see VerifyCABundle).
func Verify(cand Signed, t Trust, now time.Time) Verdict {
	s := &state{cand: cand, t: t, now: now}
	for _, c := range checks {
		if detail, ok := c.run(s); !ok {
			return Verdict{Reason: c.reason, Check: c.n, Detail: jsonset.Escape(detail)}
		}
	}
	return Verdict{Accepted: true, List: s.list, Again: s.again}
}

// CheckHeld returns the warnings of the list the host holds at now: WarningHeldExpired when its
// expires_at has passed. It is a warning and not a failure: the host keeps the list and goes on
// trusting its root keys (record 0006, rule 21). The result is empty for a host with no list.
func CheckHeld(h *Held, now time.Time) []string {
	if h == nil || h.List == nil || now.Before(h.List.ExpiresAt) {
		return nil
	}
	return []string{WarningHeldExpired}
}

func checkJWSForm(s *state) (string, bool) {
	if len(s.cand.JWS) > MaxBytes {
		return fmt.Sprintf("root-list.jws is longer than %d bytes", MaxBytes), false
	}
	g, err := jws.ParseGeneral(s.cand.JWS, listTyp)
	if err != nil {
		return err.Error(), false
	}
	s.sigs = g
	return "", true
}

func checkSomeSignerKnown(s *state) (string, bool) {
	trusted := s.t.trusted()
	for _, k := range s.kids() {
		if slices.Contains(trusted, k) {
			return "", true
		}
	}
	return "no signature is by a root key that the host trusts", false
}

func checkSignatures(s *state) (string, bool) {
	for i := range s.sigs.Signatures {
		sg := &s.sigs.Signatures[i]
		if err := sg.Verify(s.cand.JSON); err != nil {
			return fmt.Sprintf("the signature %d (kid %s) does not verify: %v", i, sg.Header.Kid, err), false
		}
	}
	return "", true
}

// checkVersion refuses a version that is an integer other than 1, and nothing else: a missing
// version, one that is not an integer and a document that is no JSON object are the business of
// check 5, which reads the document under all the rules and gives them the code malformed.
func checkVersion(s *state) (string, bool) {
	n, ok, err := strictjson.PeekInt(s.cand.JSON, "version", MaxBytes)
	if err == nil && ok && n != Version {
		return fmt.Sprintf("version %d is not known, this reader knows version %d", n, Version), false
	}
	return "", true
}

// checkMembers is check 5: the JSON rules, the members and the forms of ParseList, and the dates
// of the list against each other and against the host's clock. The clock is in the state that
// every check receives (state.now, which check 11 reads too), so the table of checks has no
// column for it. The two rules of the dates are of a candidate only: ParseList, which also reads
// the list the host holds, does not look at them, because the host accepted that list under the
// clock of its day.
func checkMembers(s *state) (string, bool) {
	l, err := ParseList(s.cand.JSON)
	if err != nil {
		return err.Error(), false
	}
	if want := ExpiresFor(l.SignedAt); !l.ExpiresAt.Equal(want) {
		return fmt.Sprintf("expires_at is not %d calendar months after signed_at (it should be %s)", ExpiryMonths, want.Format(TimeLayout)), false
	}
	if l.SignedAt.After(s.now) {
		return fmt.Sprintf("signed_at %s is later than the host's clock", l.SignedAt.Format(TimeLayout)), false
	}
	s.list = l
	return "", true
}

func checkNotRollback(s *state) (string, bool) {
	if h := s.t.held; h != nil && s.list.Sequence < h.List.Sequence {
		return fmt.Sprintf("the sequence %d is lower than the held list's %d", s.list.Sequence, h.List.Sequence), false
	}
	if s.t.held == nil && s.list.Sequence < s.t.minSequence {
		return fmt.Sprintf("the sequence %d is lower than the lowest sequence %d that the host accepts", s.list.Sequence, s.t.minSequence), false
	}
	return "", true
}

func checkSameSequence(s *state) (string, bool) {
	if h := s.t.held; h != nil && s.list.Sequence == h.List.Sequence {
		if !bytes.Equal(s.cand.JSON, h.JSON) {
			return fmt.Sprintf("another list at the sequence %d", s.list.Sequence), false
		}
		s.again = true
	}
	return "", true
}

// ofANewList makes a check apply to a new list only. Checks 8, 9 and 10 compare the candidate with
// the list the host holds: who signed a change, which keys left, which were added. They are in the
// table at their places, and the rule that the held list received again passes them lives here,
// in one place (page: "Receiving the current list again is not an error").
//
// Why that is enough. When again is set (check 7: the same sequence and the very bytes of the held
// root-list.json), the list is one that the host already accepted, so it changes nothing the host
// trusts: the host's state afterwards is the file it holds now. What the .jws may carry is still
// bounded by checks 1 to 3, which ran before: it is well formed, at least one signature is by a
// root key the host trusts now (check 2), and every signature verifies over those bytes (check 3).
// A signature by a key that is on no list, such as a retired root key signing its own retirement,
// is therefore checked but is not asked to be known: it cannot make the list acceptable alone
// (check 2 needs a trusted signer) and it cannot make an accepted list refused (check 8 does not
// run). An attacker who replays the held list with some valid signatures gains nothing: the bytes
// are the host's own, and the signatures only repeat what the host holds. The expiry (check 11)
// and the form of the members (check 5) still run, and the held list that has expired is
// refused here as it is anywhere else.
func ofANewList(run func(*state) (string, bool)) func(*state) (string, bool) {
	return func(s *state) (string, bool) {
		if s.again {
			return "", true
		}
		return run(s)
	}
}

func checkAllSignersKnown(s *state) (string, bool) {
	trusted := s.t.trusted()
	onList := s.list.Pins()
	for _, k := range s.kids() {
		if !slices.Contains(trusted, k) && !slices.Contains(onList, k) {
			return fmt.Sprintf("the signer %s is a root key of neither the held list nor this list", k), false
		}
	}
	return "", true
}

func checkRemovals(s *state) (string, bool) {
	trusted := s.t.trusted()
	for _, r := range s.list.Removals {
		if err := CheckRemoval(r, s.list, trusted); err != nil {
			return err.Error(), false
		}
	}
	return "", true
}

// checkSigners is check 10. The root keys of the two lists are the same when the held list has the
// same entries of roots (label, pin and fingerprint, in any order) or, against initial pins, the
// same pins. When they are not, every root key the host trusts has signed the list or has its
// authorisation in removals, and every root key the list adds has signed it.
func checkSigners(s *state) (string, bool) {
	trusted := s.t.trusted()
	if h := s.t.held; h != nil {
		if sameEntries(h.List.Roots, s.list.Roots) {
			return "", true
		}
	} else if samePins(trusted, s.list.Pins()) {
		return "", true
	}
	signed := s.kids()
	removed := make([]string, len(s.list.Removals))
	for i, r := range s.list.Removals {
		removed[i] = r.X509SPKISHA256
	}
	for _, p := range trusted {
		if !slices.Contains(signed, p) && !slices.Contains(removed, p) {
			return fmt.Sprintf("the root key %s of the held list neither signed this list nor has its authorisation in removals", p), false
		}
	}
	for _, p := range s.list.Pins() {
		if !slices.Contains(trusted, p) && !slices.Contains(signed, p) {
			return fmt.Sprintf("the root key %s that this list adds did not sign it", p), false
		}
	}
	return "", true
}

func checkNotExpired(s *state) (string, bool) {
	if !s.now.Before(s.list.ExpiresAt) {
		return fmt.Sprintf("the list expired at %s", s.list.ExpiresAt.Format(TimeLayout)), false
	}
	return "", true
}

// sameEntries reports whether two lists of roots hold the same entries, in any order. The labels
// and the pins are unique in a list that ParseList accepted, so equal length and every entry of one
// in the other is equality of sets.
func sameEntries(a, b []Root) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !slices.Contains(b, r) {
			return false
		}
	}
	return true
}

// samePins reports whether two lists of pins hold the same set.
func samePins(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, p := range a {
		if !slices.Contains(b, p) {
			return false
		}
	}
	return true
}
