package handoff

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
)

// Version is the version of the contract that this package reads: every JSON file has the member
// handoff, and this page is version 1 ("Versioning").
const Version = 1

// MaxFileSize is the largest file of a request that is read: 256 KiB, the limit that the contract gives
// a JSON file ("Messages and files") and the certificate request file ("The request"). The contract
// gives no size for the other files; this package holds them to the same number (proposed, built as the
// page says for a request and for a JSON file).
const MaxFileSize = 256 << 10

// Type is the type of a request, the member type of the proof file.
type Type string

// The three types of request ("What travels").
const (
	// TypeX509 is a PKCS#10 request for an X.509 intermediate.
	TypeX509 Type = "x509-intermediate"
	// TypeOpenPGP is a public subkey with its back-signatures.
	TypeOpenPGP Type = "openpgp-subkey"
	// TypeSSH is an SSH CA key with its SSH signature.
	TypeSSH Type = "ssh-ca-key"
)

// Store is where a key lives, the member store of the proof file.
type Store string

// The four key stores ("The proof file").
const (
	// StorePIV is a PIV applet, as on a YubiKey.
	StorePIV Store = "piv"
	// StoreOpenPGPCard is the OpenPGP applet of a card.
	StoreOpenPGPCard Store = "openpgp-card"
	// StoreKMS is an AWS KMS key.
	StoreKMS Store = "aws-kms"
	// StoreSoftware is a key in a file; it proves nothing about where the key lives.
	StoreSoftware Store = "software"
)

// Code is a reason code of the answer table ("The answer").
type Code string

// The reason codes. The checks of this package give every code of the table except declined, which is
// check 10's and the ceremony's.
const (
	// CodeVersionUnsupported is check 1: the contract version is not known.
	CodeVersionUnsupported Code = "version-unsupported"
	// CodeMalformed is check 2: a file does not parse, or has an unknown or repeated member, or the
	// request is not of the form of the page.
	CodeMalformed Code = "malformed"
	// CodeRequestMismatch is check 3: the proof is not for this request.
	CodeRequestMismatch Code = "request-mismatch"
	// CodeUnknownPrimary is check 3 for an openpgp-subkey: primaries is not the set of active primaries.
	CodeUnknownPrimary Code = "unknown-primary"
	// CodeAlgorithmUnsupported is check 4: the key is not ECDSA P-384.
	CodeAlgorithmUnsupported Code = "algorithm-unsupported"
	// CodePossessionInvalid is check 5: the signature of the request does not verify or is not the right kind.
	CodePossessionInvalid Code = "possession-invalid"
	// CodeStoreNotAllowed is check 6: the policy does not allow the key store.
	CodeStoreNotAllowed Code = "store-not-allowed"
	// CodeProofInvalid is check 7: the evidence does not verify.
	CodeProofInvalid Code = "proof-invalid"
	// CodeKeyMismatch is check 8: the evidence is for another key.
	CodeKeyMismatch Code = "key-mismatch"
	// CodePolicy is check 9: a rule of the certifier's policy refuses the request, or it asks for what
	// the page does not allow.
	CodePolicy Code = "policy"
	// CodeDeclined is check 10: the person at the ceremony did not confirm. No check of this package gives it.
	CodeDeclined Code = "declined"
)

// The errors that [Checker.Check] returns beside a verdict, when it cannot decide. Each is wrapped with
// words that say where; test with errors.Is.
var (
	// ErrTypeNotBuilt is returned for a request of type ssh-ca-key that passed the checks that are built
	// for it (1 to 3): the rest of the checks for that type is not built. A request of type openpgp-subkey
	// is judged by all nine checks and never gets this error.
	ErrTypeNotBuilt = errors.New("handoff: the checks 4 to 9 are not built for this type of request")
	// ErrNoVerifier is returned for a request whose store has no entry in [Config.Evidence]: check 7
	// could not run.
	ErrNoVerifier = errors.New("handoff: no evidence verifier for the store of this request")
	// ErrConfig is returned by [New] for a configuration that is not whole, and by [Checker.Check] for a
	// Checker that [New] did not make, a nil request and a nil context. A configuration is whole when it
	// has a policy (stores, a minimum firmware and the PIN policies that are allowed), a list of roots and
	// a clock, and every verifier in it is a verifier: a rule is never switched off by a field that was
	// left empty. A delegation may be left out, on purpose, and then the rules that belong to a
	// delegation are not run and are said so ([Config.Delegation]). It is also returned by [New] for
	// primaries that are given and a clock that cannot be read, or that reads a time that an OpenPGP time
	// field cannot hold, because a primary cannot then be held to the clock. [Checker.Check] returns it for a
	// request of type openpgp-subkey on a checker that holds no primaries ([ErrNoPrimaries], which wraps it),
	// and for such a request when a primary was created after the clock that this call read ([Config.Primaries]):
	// that request is neither accepted nor refused. It says nothing else about a request.
	ErrConfig = errors.New("handoff: invalid checker configuration")
	// ErrNoPrimaries is the one error for "the checker holds no primaries for this". It wraps [ErrConfig], so
	// errors.Is(err, ErrConfig) is true for it too. [Checker.Check] returns it for a request of type
	// openpgp-subkey on a checker with none, and [New] returns it for a delegation of type openpgp-subkey with
	// none. No other error of this package matches it: the error of a clock that cannot be read, or of a primary
	// created after the clock, wraps [ErrConfig] only.
	ErrNoPrimaries error = &primariesError{text: "the checker holds no primaries for this"}
	// ErrInternal is returned when two readers of one request disagree, or a verifier breaks its
	// contract: it returns no key for a store that has one, or an error that is neither a refusal of the
	// evidence nor a plain failure, or it panics. It is a fault of this package or of the verifier, never
	// of the request, and the checks that were not made are not-run.
	ErrInternal = errors.New("handoff: a reader or a verifier broke its contract")
)

// primariesError is the error of [ErrNoPrimaries]: the text of an [ErrConfig] with its own words, which
// matches [ErrNoPrimaries] and unwraps to [ErrConfig].
type primariesError struct{ text string }

func (e *primariesError) Error() string        { return ErrConfig.Error() + ": " + e.text }
func (e *primariesError) Unwrap() error        { return ErrConfig }
func (e *primariesError) Is(target error) bool { return target == ErrNoPrimaries }

// errNoPrimaries is an error that reads as text and matches [ErrNoPrimaries] and [ErrConfig].
func errNoPrimaries(text string) error { return &primariesError{text: text} }

// CodeError is an error that carries the code of a refusal. An [EvidenceVerifier] returns one for a
// refusal of the evidence.
type CodeError struct {
	// Code is the reason code of the refusal.
	Code Code
	// Detail says what was found, in fixed words; text that came from outside is escaped by the maker
	// of the error. It is for the ceremony's output and never for the answer file, which does not say
	// which part of a policy failed ("The answer").
	Detail string
}

// Error returns the code and the detail.
func (e *CodeError) Error() string {
	if e == nil {
		return "handoff: no refusal"
	}
	if e.Detail == "" {
		return "handoff: " + string(e.Code)
	}
	return "handoff: " + string(e.Code) + ": " + jsonset.Escape(e.Detail)
}

// PINPolicy is the PIN policy of a key in a PIV slot, from its attestation.
type PINPolicy string

// The three PIN policies of the attestation ("piv").
const (
	// PINNever asks for no PIN.
	PINNever PINPolicy = "never"
	// PINOnce asks for the PIN once per session.
	PINOnce PINPolicy = "once"
	// PINAlways asks for the PIN at every use.
	PINAlways PINPolicy = "always"
)

// Policy is the certifier's own policy, which is not part of the wire format ("Policy (check 9)"). It is
// the policy block of the bundle together with what a delegation does not hold. [New] refuses a policy
// in which a field is left empty: an empty field does not switch a rule off.
type Policy struct {
	// Stores are the key stores that the policy allows (check 6), at least one. A store that is not
	// listed is refused.
	Stores []Store
	// MinFirmware is the oldest firmware of a YubiKey that is accepted, three numbers separated by
	// periods ("5.7.0"). It is required, and the numbers are compared as numbers.
	MinFirmware string
	// PINPolicies are the PIN policies that are allowed, at least one. A PIV key with another policy is
	// refused.
	PINPolicies []PINPolicy
	// ValidityMonths is the certifier's own decision about the length of what it issues. It is not
	// checked on a request ("Validity is the one thing the request does not carry"), and it is not
	// negative.
	ValidityMonths int
}

// Delegation is the declared name under a root that a request is for, as the rules of check 9 need it.
// A checker may have one or none ([Config.Delegation]).
type Delegation struct {
	// Name is the declared name of the delegation.
	Name string
	// Type is the type of request the delegation is for; a request of another type is refused.
	Type Type
	// Root is the name of the root the delegation is under.
	Root string
	// PermittedURIHosts are the URI constraints a request's name constraints may hold, each a host or
	// a period and a domain. A permitted URI constraint is inside only when it equals an entry (record
	// 0006, rule 30; "Policy (check 9)").
	PermittedURIHosts []string
	// PermittedDNSNames are the DNS names a request's name constraints may hold. A permitted DNS name is
	// inside only when it equals an entry (record 0006, rule 30).
	PermittedDNSNames []string
	// Capability is the capability of an openpgp-subkey delegation, sign or authenticate. It is required for
	// that type and empty for any other ([New]); a request of that type must have exactly this one capability
	// (check 9).
	Capability string
	// Use is the use of an ssh-ca-key delegation, user or host. Not read here.
	Use string
	// KMSReadRoles maps an account id to the ARN of the read-only role to assume. It is read by the
	// aws-kms verifier, not by this package.
	KMSReadRoles map[string]string
}

// PrincipalKind is the kind of a principal of a KMS key policy statement.
type PrincipalKind string

// The kinds of a principal.
const (
	// PrincipalRole is an IAM role.
	PrincipalRole PrincipalKind = "role"
	// PrincipalUser is an IAM user.
	PrincipalUser PrincipalKind = "user"
	// PrincipalRoot is the root of an account.
	PrincipalRoot PrincipalKind = "root"
	// PrincipalWildcard is every principal.
	PrincipalWildcard PrincipalKind = "wildcard"
	// PrincipalOther is any other principal.
	PrincipalOther PrincipalKind = "other"
)

// Principal is one principal of a statement that allows kms:Sign.
type Principal struct {
	// ARN is the ARN of the principal as the policy names it.
	ARN string
	// Kind is its kind.
	Kind PrincipalKind
}

// Evidence is what a store's verifier read from the proof, in the form that checks 8 and 9 need.
type Evidence struct {
	// Key is the attested or read key. It is nil only for a software key.
	Key *ecdsa.PublicKey
	// Unprotected is true for a software key: it proves nothing about where the key lives.
	Unprotected bool
	// Firmware is the firmware of the token, "5.8.0". Empty when the store gives none.
	Firmware string
	// PINPolicy is the PIN policy of a PIV key. Empty for any other store.
	PINPolicy PINPolicy
	// TouchPolicy is recorded and never enforced by the reference policy.
	TouchPolicy string
	// SignPrincipals are the principals of every statement of a KMS key policy that allows kms:Sign.
	SignPrincipals []Principal
	// Details is what the ceremony record keeps; its members are fixed with each store.
	Details map[string]string
}

// EvidenceVerifier is check 7 for one key store.
type EvidenceVerifier interface {
	// Verify reads the evidence of the proof of a request at time now. A refusal of the evidence is a
	// *[CodeError] with the code proof-invalid, or malformed for a shape the verifier alone can see.
	// Any other error means that the verifier could not decide (a service that did not answer) and
	// is never taken for a refusal. A panic is caught by the checker and is an [ErrInternal], and the
	// request is not accepted. r and p are copies of the caller's, and the *Evidence that Verify returns
	// is copied at once.
	Verify(ctx context.Context, r *Request, p *Proof, now time.Time) (*Evidence, error)
}

// Config is what [New] needs to make a [Checker]. Every part but Evidence and Delegation is required: a rule
// that needs a value is never switched off by leaving the value out. The one exception is the delegation, whose
// absence is a statement and not an omission: the rules that need it are not run and are named as not run.
type Config struct {
	// Policy is the certifier's policy.
	Policy Policy
	// Delegation is the declared delegation the request is for. It may be nil. A checker with no delegation
	// runs every rule of check 9 that does not need one (the extensions, the evidence rules and the rule about
	// the roots) and does not run the two that do: the rule that a request is of the delegation's type
	// ("delegation-type") and the rule that its name constraints are inside the delegation's lists
	// ("name-constraints"). When every rule that ran passes, check 9 is not-run with those two rules named
	// in [CheckResult.NotRun], and the verdict is not accepted, not refused and not complete; when a rule
	// that ran refuses, check 9 failed with the code policy, as with a delegation. A nil delegation never
	// makes a request accepted.
	Delegation *Delegation
	// Roots are the roots of the bundle: the subject and the key of each, at least one. The rule that a
	// request is not for the key or the name of a root needs them. The list is the caller's to build from
	// the bundle, whole; it is read as package pki reads it.
	Roots []RootRef
	// Primaries are the active primaries of the root list, in the order of the list: the fingerprint, the
	// public key and the creation time of each (at most [MaxPrimaries]). A request of type openpgp-subkey
	// must list exactly these, in this order (check 3), and its back-signatures are checked over these keys
	// (check 5). They are required when Delegation is of type openpgp-subkey, and must be empty when it is
	// of any other type. With no Delegation they may be given or left out, and are checked when given. A
	// request of type openpgp-subkey on a checker that holds none is not judged: [Checker.Check] returns an
	// error that wraps [ErrConfig], with checks 1 and 2 passed and the rest not-run. Each entry is checked by
	// [New]: a key that is nil or not ECDSA on P-384, a creation time that is not whole seconds in the years
	// 1970 to 2106 or that is after the clock of the checker, a fingerprint that is not the one that the key
	// and the time give, and two entries with one fingerprint or one point are an [ErrConfig]. So is a
	// clock that cannot be read when [New] reads it, or that gives a time outside the years 1970 to 2106:
	// a primary cannot then be held to it. The creation time of every primary is held to the clock again
	// for each request of type openpgp-subkey (check 5), the one reading of that call: a primary created
	// after it ends the call with an error that wraps [ErrConfig] and names the primary by its fingerprint.
	// It is a checker that cannot decide, and never a refusal.
	Primaries []PrimaryRef
	// Evidence maps a store to the verifier of its evidence (check 7). A software key needs none, and a
	// verifier given for it is never called. A store with no verifier is not an error of the
	// configuration: a request of that store stops at check 7 with [ErrNoVerifier]. An entry that is nil,
	// or an interface that holds a nil pointer, map, function or slice, is an [ErrConfig].
	Evidence map[Store]EvidenceVerifier
	// Now is the clock, given to the verifiers. Required. It is called under the same protection as a
	// verifier: a clock that panics gives [ErrInternal] and no acceptance. [New] reads it once when
	// Primaries are given, to refuse a primary that was created after it, and refuses a configuration whose
	// clock cannot be read then.
	Now func() time.Time
}

// PrimaryRef is one active primary of the certifier's signed root list, as a request for an openpgp-subkey
// is checked against it: the fingerprint that the list holds and what a back-signature covers, which is the
// primary's public key and its creation time. The root list holds the fingerprint only, so where the key
// and the time come from is the caller's to decide.
type PrimaryRef struct {
	// Fingerprint is the openpgp_fingerprint of the root list: the version 4 fingerprint, 40 lower-case
	// hexadecimal digits. It must be the fingerprint that Key and Created give.
	Fingerprint string
	// Key is the public key of the primary, ECDSA on P-384.
	Key *ecdsa.PublicKey
	// Created is the creation time of the primary's key packet (openpgp_created of its root.json), in
	// whole seconds in the years 1970 to 2106.
	Created time.Time
}

// SubkeyInfo is what the ceremony records about the subkey of an accepted openpgp-subkey request.
type SubkeyInfo struct {
	// Fingerprint is the version 4 fingerprint of the subkey, 40 lower-case hexadecimal digits.
	Fingerprint string
	// Created is the creation time in the subkey packet, in UTC (for a KMS key it is the one that the
	// requester kept).
	Created time.Time
	// Capability is sign or authenticate, as the proof and the delegation agree.
	Capability string
}

// Checker runs the checks of the contract. It is made by [New], holds its own copy of everything in the
// [Config], and changes nothing afterwards, so a change that the caller makes to the Config or to what
// it holds has no effect on a call, and one Checker serves any number of calls at the same time. The
// zero value was not made by New and refuses every request with [ErrConfig].
type Checker struct {
	s *settings
}
