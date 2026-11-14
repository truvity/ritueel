package kms

import (
	"context"
	"errors"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
)

// The limits of this package. They are this package's own numbers: the contract gives none.
const (
	// PolicyName is the only key policy name that KMS has.
	PolicyName = "default"
	// MaxPolicyBytes is the longest key policy text that is read. AWS limits a key policy to 32768 characters
	// of the Latin-1 range and tab, line feed and carriage return (PutKeyPolicy, Policy: "Maximum length of
	// 32768", read 2026-11-14); a JSON text of such characters is at most two bytes for each, so the bound is
	// twice the quota. A longer text is refused unread.
	MaxPolicyBytes = 64 << 10
	// MaxStatements is the most statements of one policy.
	MaxStatements = 200
	// MaxPrincipals is the most principals over all the statements that allow kms:Sign, and the longest list
	// of principals in one statement.
	MaxPrincipals = 1000
	// MaxTextLength is the longest ARN, principal or Sid, in bytes.
	MaxTextLength = 2048
	// MaxActions is the most action patterns of one statement.
	MaxActions = 1000
	// MaxPatternLen is the longest action pattern, in bytes.
	MaxPatternLen = 256
	// MaxPublicKey is the most bytes of a DER public key from KMS. A P-384 key is 120 bytes.
	MaxPublicKey = 1024
	// DefaultTimeout is the time that one Verify has for all its calls together.
	DefaultTimeout = 30 * time.Second
)

// The two errors of a read that are not a refusal.
var (
	// ErrUndecided is wrapped by the error of a read that could not be made: the service could not be asked,
	// did not answer, answered with a fault of its own, or the context ended. It is never a refusal of the
	// evidence and never an acceptance.
	ErrUndecided = errors.New("kms: the key could not be read, so the evidence is undecided")
	// ErrConfig is wrapped by the error of a Verifier or a Config that is not whole, and of a call that the
	// caller made wrongly (no context, no proof, a proof of another store).
	ErrConfig = errors.New("kms: invalid verifier configuration or call")
)

// Fault says why a read refused.
type Fault string

// The faults of a read.
const (
	// FaultAccess is a refusal of access: the certifier, or the role it assumed, may not read the key.
	FaultAccess Fault = "access"
	// FaultNotFound is a key that the service does not know.
	FaultNotFound Fault = "not-found"
	// FaultARN is an ARN that the service does not take, or an ARN that the service reports differently.
	FaultARN Fault = "arn"
	// FaultState is a key that is not enabled, or whose state does not allow the call.
	FaultState Fault = "state"
	// FaultSpec is a key spec that is not ECC_NIST_P384, or a call the key does not support.
	FaultSpec Fault = "spec"
	// FaultUsage is a key usage that is not SIGN_VERIFY.
	FaultUsage Fault = "usage"
	// FaultOrigin is a key origin that is not AWS_KMS.
	FaultOrigin Fault = "origin"
	// FaultManager is a key manager that is not CUSTOMER.
	FaultManager Fault = "manager"
	// FaultKey is a public key that is not one P-384 key in its one spelling.
	FaultKey Fault = "key"
	// FaultPolicy is a key policy that cannot be read under the rules of this package.
	FaultPolicy Fault = "policy"
)

// Refusal is the error of a read whose answer shows that the key or its policy is not what the contract
// needs. Detail is fixed words and, where a value from the service is named, that value escaped and cut.
type Refusal struct {
	// Fault says which rule refused.
	Fault Fault
	// Detail says what was found.
	Detail string
}

// Error returns the detail.
func (r *Refusal) Error() string {
	if r == nil {
		return "kms: no refusal"
	}
	return r.Detail
}

// KeyDescription is what DescribeKey tells, in the members that the rules read. The AWS client fills it from
// the service's answer.
type KeyDescription struct {
	// ARN is the ARN that the service reports for the key.
	ARN string
	// KeyID is the key identifier.
	KeyID string
	// KeySpec is the key spec, "ECC_NIST_P384" for a key the contract accepts.
	KeySpec string
	// KeyUsage is the key usage, "SIGN_VERIFY".
	KeyUsage string
	// KeyState is the key state, "Enabled".
	KeyState string
	// Origin is where the key material is from, "AWS_KMS".
	Origin string
	// KeyManager is who manages the key, "CUSTOMER".
	KeyManager string
	// MultiRegion is true for a multi-Region key. It is recorded and is not a rule.
	MultiRegion bool
	// SigningAlgorithms are the algorithms the key signs with. Not a rule: the key spec fixes them.
	SigningAlgorithms []string
}

// PublicKeyAnswer is what GetPublicKey tells.
type PublicKeyAnswer struct {
	// KeyID is the key that the service answers for, as an ARN when the call was made with an ARN.
	KeyID string
	// KeySpec is the key spec.
	KeySpec string
	// PublicKey is the DER SubjectPublicKeyInfo.
	PublicKey []byte
}

// API makes the three read calls for one key. An implementation is for one role session, or for the
// certifier's own credentials, and is used by one Verify. Every call honours its context. An error that the
// service answered is an *[APIError]. A nil answer with a nil error is a fault of the implementation and is
// never read as an acceptance.
type API interface {
	// DescribeKey returns the description of the key.
	DescribeKey(ctx context.Context, keyARN string) (*KeyDescription, error)
	// GetPublicKey returns the public key of the key.
	GetPublicKey(ctx context.Context, keyARN string) (*PublicKeyAnswer, error)
	// GetKeyPolicy returns the text of the key policy, exactly as the service returns it.
	GetKeyPolicy(ctx context.Context, keyARN, policyName string) (policy string, err error)
}

// Connector opens the API that a read uses. roleARN "" means the certifier's own credentials; a role ARN
// means "assume this role and make every call as it". It never assumes a role that it was not given. A
// Connector is safe for concurrent use.
type Connector interface {
	// Open returns the API for roleARN.
	Open(ctx context.Context, roleARN string) (API, error)
}

// APIError is the error of a call that KMS or STS answered with a refusal or a fault. Code is the service's
// error code as text, "AccessDeniedException" for example. The AWS client maps every service error to one
// of these.
type APIError struct {
	// Code is the error code of the service.
	Code string
}

// Error returns the code, escaped and cut.
func (e *APIError) Error() string {
	if e == nil {
		return "kms: no service error"
	}
	return "kms: the service answered " + shown(e.Code)
}

// denied says, for each service error code, whether it refuses a request and with which fault and words.
// The codes that are not here leave the check undecided: a throttle, a timeout and a fault of the service
// are not a fact about the requester's key. It is the one place where the set is written.
var denied = map[string]struct {
	fault  Fault
	detail string
}{
	"AccessDeniedException":         {FaultAccess, "the key cannot be read"},
	"AccessDenied":                  {FaultAccess, "the key cannot be read"},
	"NotFoundException":             {FaultNotFound, "the key cannot be read"},
	"InvalidArnException":           {FaultARN, "the service does not take the ARN of the key"},
	"DisabledException":             {FaultState, "the key is disabled"},
	"KMSInvalidStateException":      {FaultState, "the state of the key does not allow the call"},
	"UnsupportedOperationException": {FaultSpec, "the key does not support the call"},
	"InvalidKeyUsageException":      {FaultUsage, "the usage of the key does not allow the call"},
}

// maxShown is the most characters of a value from outside that a refusal shows.
const maxShown = 120

// shown writes a text from outside for an error or a record: escaped one to one and cut to maxShown
// characters.
func shown(s string) string {
	e := jsonset.EscapeExact(s)
	if len(e) > maxShown {
		return e[:maxShown] + "..."
	}
	return e
}
