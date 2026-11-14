package kms

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/strictjson"
)

// The members of Evidence.Details that this package sets. The page leaves the members of the ceremony
// record for an aws-kms key to the store ("fixed with those key stores"), so the names are proposed; they
// are written here and nowhere else. The first eight are the names that kms-root.md already uses.
const (
	// DetailKeyARN is the ARN of the key.
	DetailKeyARN = "key_arn"
	// DetailAccount is the account of the key.
	DetailAccount = "account"
	// DetailReadRole is the role that the key was read through; absent for a read with the certifier's own
	// credentials.
	DetailReadRole = "read_role"
	// DetailSpec is the key spec.
	DetailSpec = "spec"
	// DetailUsage is the key usage.
	DetailUsage = "usage"
	// DetailOrigin is the key origin.
	DetailOrigin = "origin"
	// DetailManager is the key manager.
	DetailManager = "manager"
	// DetailState is the key state.
	DetailState = "state"
	// DetailMultiRegion is "true" or "false".
	DetailMultiRegion = "multi_region"
	// DetailPublicKeySHA256 is the SHA-256 of the DER public key that KMS gave, in lower-case hexadecimal.
	DetailPublicKeySHA256 = "public_key_sha256"
	// DetailPolicySHA256 is the SHA-256 of the key policy text as KMS returned it, in lower-case hexadecimal.
	DetailPolicySHA256 = "policy_sha256"
	// DetailCheckedAt is the time of the check, in UTC, as YYYY-MM-DDThh:mm:ssZ.
	DetailCheckedAt = "checked_at"
)

// Config is what [New] needs to make a [Verifier].
type Config struct {
	// Connector opens the API of a read. Required.
	Connector Connector
	// ReadRoles maps an account id to the ARN of the read-only role to assume for a key of that account: the
	// KMSReadRoles of the delegation, which the caller builds the checker from too, so that there is one
	// source. A key whose account is not listed is read with the certifier's own credentials. nil means no
	// role is known. The map is copied.
	ReadRoles map[string]string
	// Timeout is the time for one Verify, all its calls together. 0 is [DefaultTimeout]; a negative value is
	// refused.
	Timeout time.Duration
}

// Verifier is check 7 for aws-kms: package handoff's EvidenceVerifier. It is immutable after [New] and safe
// for concurrent use when its Connector is. The zero value refuses every call.
type Verifier struct {
	s *settings
}

type settings struct {
	connector Connector
	roles     map[string]string
	timeout   time.Duration
}

var _ handoff.EvidenceVerifier = (*Verifier)(nil)

// New makes a Verifier. A nil Connector (an interface that holds a nil pointer too), a negative Timeout, a
// ReadRoles key that is not twelve digits, a role that [ParseRoleARN] refuses, and a role whose account is
// not the account it is listed under (it would make the certifier read one account's key as another
// account's role) are errors that wrap [ErrConfig], and no Verifier is made.
func New(cfg Config) (*Verifier, error) {
	if isNil(cfg.Connector) {
		return nil, fmt.Errorf("%w: no connector", ErrConfig)
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("%w: the timeout is negative", ErrConfig)
	}
	for account, role := range cfg.ReadRoles {
		if !digits(account, 12) {
			return nil, fmt.Errorf("%w: a read role is listed under something that is not an account id", ErrConfig)
		}
		roleAccount, err := ParseRoleARN(role)
		if err != nil {
			return nil, fmt.Errorf("%w: the read role of account %s is not the ARN of a role", ErrConfig, account)
		}
		if roleAccount != account {
			return nil, fmt.Errorf("%w: the read role of account %s is a role of another account", ErrConfig, account)
		}
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Verifier{s: &settings{connector: cfg.Connector, roles: maps.Clone(cfg.ReadRoles), timeout: timeout}}, nil
}

// wireEvidence is the evidence of an aws-kms proof.
type wireEvidence struct {
	KeyARN    *string `json:"key_arn"`
	PublicKey *string `json:"public_key"`
}

// Verify is check 7 for an aws-kms proof. It reads the key from KMS, applies the rules of "Evidence for KMS
// (check 7)", and returns the key that KMS gave and the principals that may use kms:Sign. A refusal of the
// evidence is a *handoff.CodeError with the code proof-invalid, or malformed for a form that only this
// package can see; any other error means that the check could not be decided, and a call that the caller made
// wrongly wraps [ErrConfig]. No evidence is returned unless every rule ran and passed.
//
// The proof's own public_key is not compared with the key that KMS returned. That comparison is check 8, by
// the checker; a verifier that refused here would give the wrong code for a key that is not the request's.
//
// The role that a read goes through is taken from the Verifier's own list by the account of the key, and
// never from the request. The request is not read and may be nil.
func (v *Verifier) Verify(ctx context.Context, _ *handoff.Request, p *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
	// 1. The call is whole.
	if v == nil || v.s == nil {
		return nil, fmt.Errorf("%w: the verifier was not made by New", ErrConfig)
	}
	if ctx == nil || p == nil || p.Store != handoff.StoreKMS {
		return nil, fmt.Errorf("%w: Verify needs a context and a proof of the store aws-kms", ErrConfig)
	}

	// 2. The evidence has the page's shape.
	arnText, err := readEvidenceShape(p.Evidence)
	if err != nil {
		return nil, err
	}

	// 3. The ARN is read.
	arn, err := ParseKeyARN(arnText)
	if err != nil {
		return nil, &handoff.CodeError{Code: handoff.CodeMalformed, Detail: "the key_arn of the evidence is not the ARN of a KMS key"}
	}

	// 4. The role is chosen from the certifier's own list, never from the request.
	if err := ctx.Err(); err != nil {
		return nil, undecided("Open", err)
	}
	role := v.s.roles[arn.Account]
	ctx, cancel := context.WithTimeout(ctx, v.s.timeout)
	defer cancel()

	// 5. The key is read.
	api, err := v.s.connector.Open(ctx, role)
	if err != nil {
		return nil, refusalToCode(callError("Open", err))
	}
	if isNil(api) {
		return nil, fmt.Errorf("%w: Open answered no API", ErrUndecided)
	}
	reading, err := Read(ctx, api, arn)
	if err != nil {
		// 6. A refusal is mapped.
		return nil, refusalToCode(err)
	}

	// 7. The evidence is built.
	sum := sha256.Sum256(reading.PublicKeyDER)
	details := map[string]string{
		DetailKeyARN:          arn.String(),
		DetailAccount:         arn.Account,
		DetailSpec:            reading.Description.KeySpec,
		DetailUsage:           reading.Description.KeyUsage,
		DetailOrigin:          reading.Description.Origin,
		DetailManager:         reading.Description.KeyManager,
		DetailState:           reading.Description.KeyState,
		DetailMultiRegion:     strconv.FormatBool(reading.Description.MultiRegion),
		DetailPublicKeySHA256: hex.EncodeToString(sum[:]),
		DetailPolicySHA256:    reading.PolicySHA256,
		DetailCheckedAt:       now.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if role != "" {
		details[DetailReadRole] = role
	}
	// 8. The proof's public_key is not compared here: that is check 8.
	return &handoff.Evidence{
		Key:            reading.Key,
		SignPrincipals: slices.Clone(reading.SignPrincipals),
		Details:        details,
	}, nil
}

// readEvidenceShape reads the evidence of the proof into its two members and returns the key ARN. Both
// members are required, no other is allowed, and public_key is standard Base64 with padding in its one
// spelling and not empty. Its content is not compared with anything.
func readEvidenceShape(raw []byte) (keyARN string, err error) {
	shape := func(words string) error {
		return &handoff.CodeError{Code: handoff.CodeMalformed, Detail: words}
	}
	if len(raw) == 0 {
		return "", shape("the proof has no evidence")
	}
	var e wireEvidence
	if err := strictjson.Unmarshal(raw, &e, strictjson.Options{MaxBytes: handoff.MaxFileSize}); err != nil {
		return "", shape("the evidence is not an object with the members key_arn and public_key and no other")
	}
	if e.KeyARN == nil || e.PublicKey == nil {
		return "", shape("the evidence has not both key_arn and public_key")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(*e.PublicKey)
	if err != nil || len(b) == 0 || base64.StdEncoding.EncodeToString(b) != *e.PublicKey {
		return "", shape("the public_key of the evidence is not Base64 of a DER value")
	}
	return *e.KeyARN, nil
}

// refusalToCode maps a *Refusal to the refusal that the checker reads (proof-invalid); any other error is
// returned as it is.
func refusalToCode(err error) error {
	var r *Refusal
	if errors.As(err, &r) && r != nil {
		return &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: r.Detail}
	}
	return err
}
