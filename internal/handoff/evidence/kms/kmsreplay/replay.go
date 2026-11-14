package kmsreplay

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"ritueel.id/ritueel/internal/handoff/evidence/kms"
	"ritueel.id/ritueel/internal/strictjson"
)

// maxStub is the largest stub file that Parse reads: 256 KiB, the limit of a JSON file of the contract.
const maxStub = 256 << 10

// maxCodeLen is the longest error code of a stub, in bytes.
const maxCodeLen = 128

// Error codes that the replay itself answers with.
const (
	codeAccessDenied = "AccessDenied"
	codeNotFound     = "NotFoundException"
)

// The wire form of the file: the shape of the vectors and nothing else.
type (
	wireStub struct {
		AssumeRole   *wireAssume   `json:"assume_role"`
		DescribeKey  *wireDescribe `json:"describe_key"`
		GetPublicKey *wirePublic   `json:"get_public_key"`
		GetKeyPolicy *wirePolicy   `json:"get_key_policy"`
	}
	wireAssume struct {
		RoleArn *string `json:"RoleArn"`
	}
	wireDescribe struct {
		KeyMetadata *wireMeta `json:"KeyMetadata"`
		Error       *string   `json:"error"`
	}
	wireMeta struct {
		Arn               *string  `json:"Arn"`
		KeyID             *string  `json:"KeyId"`
		KeySpec           *string  `json:"KeySpec"`
		KeyUsage          *string  `json:"KeyUsage"`
		KeyState          *string  `json:"KeyState"`
		Origin            *string  `json:"Origin"`
		KeyManager        *string  `json:"KeyManager"`
		MultiRegion       *bool    `json:"MultiRegion"`
		SigningAlgorithms []string `json:"SigningAlgorithms"`
	}
	wirePublic struct {
		KeyID     *string `json:"KeyId"`
		KeySpec   *string `json:"KeySpec"`
		PublicKey []byte  `json:"PublicKey"`
		Error     *string `json:"error"`
	}
	wirePolicy struct {
		PolicyName *string `json:"PolicyName"`
		Policy     *string `json:"Policy"`
		Error      *string `json:"error"`
	}
)

// Replay answers the three calls from one stub file, and records what was asked. It is a kms.Connector. It is
// safe for concurrent use.
type Replay struct {
	assumeRole    string // "" when the file has no assume_role: a direct read
	describe      *kms.KeyDescription
	describeErr   string
	publicKey     *kms.PublicKeyAnswer
	publicKeyErr  string
	policy        string
	policyErr     string
	arn           string // the key the value answers are for; "" when every answer is an error
	mu            sync.Mutex
	calls         []string
	policyPresent bool
}

var _ kms.Connector = (*Replay)(nil)

// errStub is wrapped by the error of Parse. Its words are fixed and never repeat the input.
var errStub = errors.New("kmsreplay: not a KMS stub of the form of the vectors")

func stubErr(reason string) error { return fmt.Errorf("%w: %s", errStub, reason) }

// Parse reads one stub file: one JSON object of the shape of the vectors and no other (no member twice, no
// member that the vectors do not have, no null, no float, at most 256 KiB). The three answers describe_key,
// get_public_key and get_key_policy are required, and each is a value or an "error" (the service's error
// code as text), never both. assume_role is optional. The answers of one key are for one ARN: the Arn of the
// description and the KeyId of the public key answer are the same text. The error holds fixed words.
func Parse(data []byte) (*Replay, error) {
	var w wireStub
	if err := strictjson.Unmarshal(data, &w, strictjson.Options{MaxBytes: maxStub}); err != nil {
		return nil, stubErr("not one JSON object with the members of the vectors, each once")
	}
	if w.DescribeKey == nil || w.GetPublicKey == nil || w.GetKeyPolicy == nil {
		return nil, stubErr("an answer is missing")
	}
	r := &Replay{}
	if w.AssumeRole != nil {
		if w.AssumeRole.RoleArn == nil {
			return nil, stubErr("assume_role has no RoleArn")
		}
		if _, err := kms.ParseRoleARN(*w.AssumeRole.RoleArn); err != nil {
			return nil, stubErr("the RoleArn is not the ARN of a role")
		}
		r.assumeRole = *w.AssumeRole.RoleArn
	}
	if err := r.readDescribe(w.DescribeKey); err != nil {
		return nil, err
	}
	if err := r.readPublic(w.GetPublicKey); err != nil {
		return nil, err
	}
	if err := r.readPolicy(w.GetKeyPolicy); err != nil {
		return nil, err
	}
	if r.describe != nil && r.publicKey != nil && r.describe.ARN != r.publicKey.KeyID {
		return nil, stubErr("the description and the public key answer are for two keys")
	}
	switch {
	case r.describe != nil:
		r.arn = r.describe.ARN
	case r.publicKey != nil:
		r.arn = r.publicKey.KeyID
	}
	return r, nil
}

// code checks the error code of an answer.
func code(c string) error {
	if c == "" || len(c) > maxCodeLen {
		return stubErr("an error code is empty or too long")
	}
	for i := 0; i < len(c); i++ {
		b := c[i]
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' && b != '.' && b != '-' {
			return stubErr("an error code holds a character other than letters, digits and _ . -")
		}
	}
	return nil
}

func (r *Replay) readDescribe(w *wireDescribe) error {
	if w.Error != nil {
		if w.KeyMetadata != nil {
			return stubErr("describe_key has both a value and an error")
		}
		if err := code(*w.Error); err != nil {
			return err
		}
		r.describeErr = *w.Error
		return nil
	}
	m := w.KeyMetadata
	if m == nil || m.Arn == nil || m.KeyID == nil || m.KeySpec == nil || m.KeyUsage == nil || m.KeyState == nil ||
		m.Origin == nil || m.KeyManager == nil || m.MultiRegion == nil || m.SigningAlgorithms == nil {
		return stubErr("describe_key has neither an error nor a whole KeyMetadata")
	}
	r.describe = &kms.KeyDescription{
		ARN: *m.Arn, KeyID: *m.KeyID, KeySpec: *m.KeySpec, KeyUsage: *m.KeyUsage, KeyState: *m.KeyState,
		Origin: *m.Origin, KeyManager: *m.KeyManager, MultiRegion: *m.MultiRegion,
		SigningAlgorithms: slices.Clone(m.SigningAlgorithms),
	}
	return nil
}

func (r *Replay) readPublic(w *wirePublic) error {
	if w.Error != nil {
		if w.KeyID != nil || w.KeySpec != nil || w.PublicKey != nil {
			return stubErr("get_public_key has both a value and an error")
		}
		if err := code(*w.Error); err != nil {
			return err
		}
		r.publicKeyErr = *w.Error
		return nil
	}
	if w.KeyID == nil || w.KeySpec == nil || w.PublicKey == nil {
		return stubErr("get_public_key has neither an error nor KeyId, KeySpec and PublicKey")
	}
	r.publicKey = &kms.PublicKeyAnswer{KeyID: *w.KeyID, KeySpec: *w.KeySpec, PublicKey: slices.Clone(w.PublicKey)}
	return nil
}

func (r *Replay) readPolicy(w *wirePolicy) error {
	if w.Error != nil {
		if w.PolicyName != nil || w.Policy != nil {
			return stubErr("get_key_policy has both a value and an error")
		}
		if err := code(*w.Error); err != nil {
			return err
		}
		r.policyErr = *w.Error
		return nil
	}
	if w.PolicyName == nil || w.Policy == nil {
		return stubErr("get_key_policy has neither an error nor PolicyName and Policy")
	}
	if *w.PolicyName != kms.PolicyName {
		return stubErr("the PolicyName is not default")
	}
	r.policy = *w.Policy
	r.policyPresent = true
	return nil
}

// Open is the kms.Connector of the replay. With assume_role in the file, roleARN must equal its RoleArn;
// without it, roleARN must be empty (the file holds what a direct read gets, and a role that the file does not
// know gets nothing). Any other roleARN is a *kms.APIError with the code AccessDenied. The call is recorded
// as "open:-" for a direct read and "open:" and the role otherwise, also when it is refused. An ended context
// is returned as it is and nothing is recorded.
func (r *Replay) Open(ctx context.Context, roleARN string) (kms.API, error) {
	if err := r.begin(ctx); err != nil {
		return nil, err
	}
	if roleARN == "" {
		r.record("open:-")
	} else {
		r.record("open:" + roleARN)
	}
	if roleARN != r.assumeRole {
		return nil, &kms.APIError{Code: codeAccessDenied}
	}
	return &session{r: r}, nil
}

// Calls returns the calls that were asked, in order, as "open:-", "open:<role>", "DescribeKey",
// "GetPublicKey" and "GetKeyPolicy:default" (the name that was asked follows the colon). The slice is a copy.
func (r *Replay) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *Replay) record(call string) {
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
}

// begin makes the check that every call starts with.
func (r *Replay) begin(ctx context.Context) error {
	if r == nil {
		return errors.New("kmsreplay: no replay")
	}
	if ctx == nil {
		return errors.New("kmsreplay: no context")
	}
	return ctx.Err()
}

// known reports whether a call for keyARN is for the key of the file: when no answer of the file is a value,
// every ARN is.
func (r *Replay) known(keyARN string) bool { return r.arn == "" || r.arn == keyARN }

// session is the API of one Open.
type session struct{ r *Replay }

var _ kms.API = (*session)(nil)

// DescribeKey answers from describe_key.
func (s *session) DescribeKey(ctx context.Context, keyARN string) (*kms.KeyDescription, error) {
	if err := s.r.begin(ctx); err != nil {
		return nil, err
	}
	s.r.record("DescribeKey")
	if !s.r.known(keyARN) {
		return nil, &kms.APIError{Code: codeNotFound}
	}
	if s.r.describe == nil {
		return nil, &kms.APIError{Code: s.r.describeErr}
	}
	d := *s.r.describe
	d.SigningAlgorithms = slices.Clone(d.SigningAlgorithms)
	return &d, nil
}

// GetPublicKey answers from get_public_key.
func (s *session) GetPublicKey(ctx context.Context, keyARN string) (*kms.PublicKeyAnswer, error) {
	if err := s.r.begin(ctx); err != nil {
		return nil, err
	}
	s.r.record("GetPublicKey")
	if !s.r.known(keyARN) {
		return nil, &kms.APIError{Code: codeNotFound}
	}
	if s.r.publicKey == nil {
		return nil, &kms.APIError{Code: s.r.publicKeyErr}
	}
	a := *s.r.publicKey
	a.PublicKey = slices.Clone(a.PublicKey)
	return &a, nil
}

// GetKeyPolicy answers from get_key_policy. A policy name other than "default" is NotFoundException.
func (s *session) GetKeyPolicy(ctx context.Context, keyARN, policyName string) (string, error) {
	if err := s.r.begin(ctx); err != nil {
		return "", err
	}
	s.r.record("GetKeyPolicy:" + policyName)
	if !s.r.known(keyARN) || policyName != kms.PolicyName {
		return "", &kms.APIError{Code: codeNotFound}
	}
	if !s.r.policyPresent {
		return "", &kms.APIError{Code: s.r.policyErr}
	}
	return s.r.policy, nil
}
