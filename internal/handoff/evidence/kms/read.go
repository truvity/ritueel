package kms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"ritueel.id/ritueel/internal/handoff"
)

// The values that the contract asks of a key ("Evidence for KMS (check 7)").
const (
	wantState   = "Enabled"
	wantUsage   = "SIGN_VERIFY"
	wantSpec    = "ECC_NIST_P384"
	wantOrigin  = "AWS_KMS"
	wantManager = "CUSTOMER"
)

// Reading is what a read of one key found, in whole. A Reading is returned only when every rule ran and
// passed.
type Reading struct {
	// Description is the description that the service gave, copied.
	Description KeyDescription
	// Key is the public key, a P-384 key that KMS gave. It is a new value that shares nothing with the answer.
	Key *ecdsa.PublicKey
	// PublicKeyDER is the bytes that KMS gave, which the key writes back to.
	PublicKeyDER []byte
	// PolicySHA256 is the SHA-256 of the policy text exactly as KMS returned it, in lower-case hexadecimal.
	PolicySHA256 string
	// SignPrincipals are the principals of every statement that allows kms:Sign, in the order of the policy.
	SignPrincipals []handoff.Principal
}

// Read asks api for the description, the public key and the policy of the key, in that order, and applies the
// rules of check 7 to each answer before it asks the next, so a refusal stops the read and no later call is
// made. It returns a *[Refusal] at the first rule that fails (the service's own refusal, such as
// AccessDeniedException, is a Refusal too), and nothing else of the Reading. An error that is not a Refusal
// wraps [ErrUndecided], or [ErrConfig] for a call made with no context or no API.
//
// The rules: the ARN that the description reports is the ARN asked for, byte for byte; the key state is
// Enabled, its usage SIGN_VERIFY, its spec ECC_NIST_P384, its origin AWS_KMS and its manager CUSTOMER; the
// public key answer is for the same ARN and spec, and its bytes are one P-384 SubjectPublicKeyInfo that
// writes back to the same bytes; the policy is read by [SignPrincipals].
func Read(ctx context.Context, api API, arn KeyARN) (*Reading, error) {
	if ctx == nil || isNil(api) {
		return nil, fmt.Errorf("%w: a read needs a context and an API", ErrConfig)
	}
	text := arn.String()
	if _, err := ParseKeyARN(text); err != nil {
		return nil, &Refusal{Fault: FaultARN, Detail: "the ARN is not the ARN of a KMS key"}
	}

	if err := ctx.Err(); err != nil {
		return nil, undecided("DescribeKey", err)
	}
	desc, err := api.DescribeKey(ctx, text)
	if err != nil {
		return nil, callError("DescribeKey", err)
	}
	if desc == nil {
		return nil, fmt.Errorf("%w: DescribeKey answered nothing", ErrUndecided)
	}
	d := *desc
	d.SigningAlgorithms = slices.Clone(desc.SigningAlgorithms)
	if err := checkDescription(&d, text); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, undecided("GetPublicKey", err)
	}
	pk, err := api.GetPublicKey(ctx, text)
	if err != nil {
		return nil, callError("GetPublicKey", err)
	}
	if pk == nil {
		return nil, fmt.Errorf("%w: GetPublicKey answered nothing", ErrUndecided)
	}
	key, der, err := checkPublicKey(pk, text)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, undecided("GetKeyPolicy", err)
	}
	policy, err := api.GetKeyPolicy(ctx, text, PolicyName)
	if err != nil {
		return nil, callError("GetKeyPolicy", err)
	}
	if len(policy) > MaxPolicyBytes {
		return nil, policyFault("is longer than the limit")
	}
	sum := sha256.Sum256([]byte(policy))
	principals, err := SignPrincipals(policy)
	if err != nil {
		return nil, err
	}
	return &Reading{
		Description:    d,
		Key:            key,
		PublicKeyDER:   der,
		PolicySHA256:   hex.EncodeToString(sum[:]),
		SignPrincipals: principals,
	}, nil
}

// checkDescription applies the rules of the contract to a description. The comparison is exact, in upper and
// lower case.
func checkDescription(d *KeyDescription, arn string) error {
	rules := []struct {
		fault      Fault
		got, want  string
		what       string
		showsValue bool
	}{
		{FaultARN, d.ARN, arn, "the ARN that the service reports is not the ARN in the proof", false},
		{FaultState, d.KeyState, wantState, "the key state is not Enabled", true},
		{FaultUsage, d.KeyUsage, wantUsage, "the key usage is not SIGN_VERIFY", true},
		{FaultSpec, d.KeySpec, wantSpec, "the key spec is not ECC_NIST_P384", true},
		{FaultOrigin, d.Origin, wantOrigin, "the key origin is not AWS_KMS", true},
		{FaultManager, d.KeyManager, wantManager, "the key manager is not CUSTOMER", true},
	}
	for _, r := range rules {
		if r.got == r.want {
			continue
		}
		detail := r.what
		if r.showsValue {
			detail += " (it is " + shown(r.got) + ")"
		}
		return &Refusal{Fault: r.fault, Detail: detail}
	}
	return nil
}

// checkPublicKey applies the rules of the contract to the answer of GetPublicKey and returns the key and a
// copy of its bytes. The bytes must parse as one P-384 SubjectPublicKeyInfo and write back to themselves.
func checkPublicKey(a *PublicKeyAnswer, arn string) (*ecdsa.PublicKey, []byte, error) {
	if a.KeyID != arn {
		return nil, nil, &Refusal{Fault: FaultARN, Detail: "the public key answer is for another key"}
	}
	if a.KeySpec != wantSpec {
		return nil, nil, &Refusal{Fault: FaultSpec, Detail: "the key spec of the public key answer is not ECC_NIST_P384 (it is " + shown(a.KeySpec) + ")"}
	}
	if len(a.PublicKey) == 0 || len(a.PublicKey) > MaxPublicKey {
		return nil, nil, &Refusal{Fault: FaultKey, Detail: "the public key has no bytes, or more than the limit"}
	}
	der := bytes.Clone(a.PublicKey)
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, &Refusal{Fault: FaultKey, Detail: "the public key is not a SubjectPublicKeyInfo"}
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return nil, nil, &Refusal{Fault: FaultKey, Detail: "the public key is not an ECDSA key on P-384"}
	}
	back, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(back, der) {
		return nil, nil, &Refusal{Fault: FaultKey, Detail: "the public key is not written in its one spelling"}
	}
	return key, der, nil
}

// callError turns the error of a call into a refusal, when the service's code is one of the codes that refuse,
// and into an undecided error otherwise.
func callError(call string, err error) error {
	var ae *APIError
	if errors.As(err, &ae) && ae != nil {
		if d, ok := denied[ae.Code]; ok {
			return &Refusal{Fault: d.fault, Detail: d.detail}
		}
	}
	return undecided(call, err)
}

// undecided is the error of a call that could not be made or did not answer. It wraps ErrUndecided and, for an
// ended context, the context's error; it never wraps the error of the caller's API, so that no error type of
// the API can be taken for a refusal by a caller that unwraps it. Only the service's code is shown, escaped.
func undecided(call string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: %s: %w", ErrUndecided, call, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %s: %w", ErrUndecided, call, context.DeadlineExceeded)
	}
	var ae *APIError
	if errors.As(err, &ae) && ae != nil {
		return fmt.Errorf("%w: %s: the service answered %s", ErrUndecided, call, shown(ae.Code))
	}
	return fmt.Errorf("%w: %s failed", ErrUndecided, call)
}

// isNil reports whether v is nil or an interface that holds a nil pointer, map, function, slice or channel.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan, reflect.Interface, reflect.UnsafePointer:
		return rv.IsNil()
	}
	return false
}
