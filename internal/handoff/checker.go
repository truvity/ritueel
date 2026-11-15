package handoff

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/pki"
)

// RootRef is one root of the bundle: the DER of its subject and its public key (ECDSA on P-384). It is
// the form that package pki asks for.
type RootRef = pki.RootRef

// Check runs the checks of "What the certifier checks", 1 to 9, in order, on the files of one request,
// and stops at the first that fails: the checks before it are passed and the checks after it are
// not-run (when the version cannot be read, check 2 fails and check 1 is not-run, because the page gives
// that fault to check 2). A refusal is in the verdict ([Verdict.Code]); the error is non-nil only when the
// checker cannot decide (see the package comment): [ErrTypeNotBuilt] for an ssh-ca-key request that passed
// the checks that are built for it, [ErrNoPrimaries] (an [ErrConfig] too, beside checks 1 and 2 passed) for an
// openpgp-subkey request on a checker that holds no primaries, an [ErrConfig] (beside checks 1 to 4 passed)
// for an openpgp-subkey request when a primary was created after the clock that this call read, [ErrNoVerifier] for a store with no verifier,
// the error of a verifier that failed without refusing or that panicked, [ErrConfig] for a Checker that
// [New] did not make, and [ErrInternal]. The verdict is returned with every error, with the checks that
// did not run marked not-run.
//
// Only [Verdict.Accepted] on the verdict means that the request is accepted. An error always means that it
// is not, whatever the verdict beside it holds: a verdict that comes with an error is never accepted, and
// it is not refused either, so a caller that looks only at [Verdict.Refused] or [Verdict.Complete] reads it
// wrong. Test the error first, and then Accepted.
//
// The request is copied at the top of the call, so a change that the caller or a verifier makes to its
// files has no effect on the call, and the Checker holds its own copy of its configuration, so nothing
// the caller does to the [Config] after [New] reaches a call. ctx and the clock are given to the
// verifiers; the checks of this package make no call that waits. A verifier that panics, and a clock
// that panics, give an [ErrInternal] and never an acceptance.
func (c *Checker) Check(ctx context.Context, r *Request) (Verdict, error) {
	v := newVerdict()
	if c == nil || c.s == nil {
		return v, fmt.Errorf("%w: the checker was not made by New", ErrConfig)
	}
	if r == nil || ctx == nil {
		return v, fmt.Errorf("%w: no request or no context", ErrConfig)
	}
	req := copyRequest(r)

	// Check 1: the version, read before anything else of the proof file. A proof file whose version cannot
	// be read (no file, a file that is too long, not one JSON object, no member handoff, the member twice
	// or not an integer) is a fault of the form of the files: check 2, and check 1 is not-run.
	proofFile, ok := req.Files[FileProof]
	if !ok {
		v.fail(2, CodeMalformed, "the request has no proof file")
		return v, nil
	}
	if len(proofFile) > MaxFileSize {
		v.fail(2, CodeMalformed, fmt.Sprintf("the proof file is longer than %d bytes", MaxFileSize))
		return v, nil
	}
	version, err := peekVersion(proofFile)
	if err != nil {
		v.fail(2, CodeMalformed, err.Error())
		return v, nil
	}
	if version != Version {
		v.fail(1, CodeVersionUnsupported, fmt.Sprintf("the contract version is %d, and only %d is known", version, Version))
		return v, nil
	}
	v.pass(1)

	// Check 2: the proof file, and the files of the request.
	p, err := readProof(proofFile)
	if err != nil {
		var shape errShape
		if errors.As(err, &shape) {
			v.fail(2, CodeMalformed, shape.Error())
			return v, nil
		}
		return v, err
	}
	switch p.Type {
	case TypeX509:
		return c.s.checkX509(ctx, v, req, p)
	case TypeOpenPGP:
		return c.s.checkOpenPGP(ctx, v, req, p)
	default:
		return checkFileType(v, req, p, FileSSHKey, FileSSHSig)
	}
}

// checkFileType runs checks 2 and 3 for the one type of which only those are built (ssh-ca-key): the files
// of the page's table are there and within the limit, and request_sha256 is the digest of the one file that
// the page names. It then stops with ErrTypeNotBuilt.
func checkFileType(v Verdict, req *Request, p *Proof, files ...string) (Verdict, error) {
	for _, name := range files {
		f, ok := req.Files[name]
		if !ok {
			v.fail(2, CodeMalformed, "the request has no file "+name)
			return v, nil
		}
		if len(f) > MaxFileSize {
			v.fail(2, CodeMalformed, fmt.Sprintf("the file %s is longer than %d bytes", name, MaxFileSize))
			return v, nil
		}
	}
	v.pass(2)
	// The digest is of the bytes of the first file: the OpenSSH public key line.
	if sum := sha256.Sum256(req.Files[files[0]]); hex.EncodeToString(sum[:]) != p.RequestSHA256 {
		v.fail(3, CodeRequestMismatch, "request_sha256 is not the digest of the file "+files[0])
		return v, nil
	}
	v.pass(3)
	return v, fmt.Errorf("%w: type %s", ErrTypeNotBuilt, p.Type)
}

// checkX509 runs checks 2 to 9 for a request of type x509-intermediate.
func (s *settings) checkX509(ctx context.Context, v Verdict, req *Request, p *Proof) (Verdict, error) {
	// Check 2, the files. The file of the request is read by package pki once for its form, its key and
	// its possession, in the one call that its comment asks for first; the content waits for check 9.
	csr, ok := req.Files[FileCSR]
	if !ok {
		v.fail(2, CodeMalformed, "the request has no file "+FileCSR)
		return v, nil
	}
	if len(csr) > MaxFileSize {
		v.fail(2, CodeMalformed, fmt.Sprintf("the file %s is longer than %d bytes", FileCSR, MaxFileSize))
		return v, nil
	}
	key, keyErr := pki.RequestKeyFile(csr)
	var later error // a refusal of check 4 or 5, told when its turn comes
	if keyErr != nil {
		switch pki.CheckOf(keyErr) {
		case pki.CheckMalformed:
			v.fail(2, CodeMalformed, jsonset.Escape(keyErr.Error()))
			return v, nil
		case pki.CheckAlgorithm, pki.CheckPossession:
			later = keyErr
		default:
			return v, fmt.Errorf("%w: reading the request: %w", ErrInternal, keyErr)
		}
	}
	v.pass(2)

	// Check 3: the digest of the DER of the request. The file is one PEM block that package pki has
	// accepted (its form is check 2), so the DER is read out of it by the standard decoder.
	der, err := derOfFile(csr)
	if err != nil {
		return v, err
	}
	if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) != p.RequestSHA256 {
		v.fail(3, CodeRequestMismatch, "request_sha256 is not the digest of the request")
		return v, nil
	}
	v.pass(3)

	// Checks 4 and 5: the key and the signature, read with the form by package pki.
	if later != nil && pki.CheckOf(later) == pki.CheckAlgorithm {
		v.fail(4, CodeAlgorithmUnsupported, jsonset.Escape(later.Error()))
		return v, nil
	}
	v.pass(4)
	if later != nil {
		v.fail(5, CodePossessionInvalid, jsonset.Escape(later.Error()))
		return v, nil
	}
	v.pass(5)

	// The content of the request is read now, from the same bytes, and the two readings are compared
	// before the result of any of checks 6 to 8 is used (the comment of package pki asks for this order).
	// The refusal of the content is check 9's and is told there. A refusal with no request to compare
	// cannot become an acceptance, because check 9 then fails, so the results of checks 6 to 8 only decide
	// which refusal comes first.
	request, parseErr := pki.ParseRequestFile(csr)
	switch {
	case parseErr == nil:
		if request.PublicKey() == nil || !request.PublicKey().Equal(key) || !bytes.Equal(request.DER(), der) {
			return v, fmt.Errorf("%w: the two readings of the request are not of one request", ErrInternal)
		}
	case pki.CheckOf(parseErr) != pki.CheckPolicy:
		return v, fmt.Errorf("%w: reading the content of the request: %w", ErrInternal, parseErr)
	}

	// Checks 6 to 8: the store, the evidence, the key match.
	ev, err := s.checkStoreEvidenceKey(ctx, &v, req, p, key, s.clock)
	if err != nil || v.Refused() {
		return v, err
	}

	// Check 9: the content, then the policy.
	if parseErr != nil {
		v.fail(9, CodePolicy, jsonset.Escape(parseErr.Error()))
		return v, nil
	}
	if fault := s.policyRules(request, p, ev); fault != "" {
		v.fail(9, CodePolicy, fault)
		return v, nil
	}
	if !s.hasDelegation() {
		// Every rule that could run passed, and the rules that need a delegation did not run: the check is
		// not-run with them named, and the request is not accepted (a verdict that holds a not-run check is
		// never accepted).
		v.partial(9, notRunWithoutDelegation(p.Type))
		return v, nil
	}
	v.pass(9)
	v.accept(key, ev)
	return v, nil
}

// checkStoreEvidenceKey runs checks 6 to 8, which are the same for every type that is built: the store is
// allowed by the policy, the evidence is valid, and the key in the evidence (and the public_key of a KMS proof)
// is the key of the request. key is the key of the request; now gives the time that a verifier is called with.
// A refusal is in v, with the checks before it passed; the caller stops when it returns an error or v is
// refused, and goes on with the evidence it returns otherwise.
func (s *settings) checkStoreEvidenceKey(ctx context.Context, v *Verdict, req *Request, p *Proof, key *ecdsa.PublicKey, now func() (time.Time, error)) (*Evidence, error) {
	// Check 6: the store.
	if !slices.Contains(s.stores, p.Store) {
		v.fail(6, CodeStoreNotAllowed, fmt.Sprintf("the policy does not allow the store %s", p.Store))
		return nil, nil
	}
	v.pass(6)

	// Check 7: the evidence.
	ev, err := s.verifyEvidence(ctx, v, req, p, now)
	if err != nil || v.Refused() {
		return nil, err
	}
	v.pass(7)

	// Check 8: the key in the evidence, and the public_key of a KMS proof, are the key in the request. A
	// software key has no evidence key to compare.
	if fault, err := compareKeys(key, p, ev); err != nil {
		return nil, err
	} else if fault != "" {
		v.fail(8, CodeKeyMismatch, fault)
		return nil, nil
	}
	v.pass(8)
	return ev, nil
}

// compareKeys is check 8: every key that the proof and its evidence give is the key of the request. It
// returns the detail of the first that is not, or an error when the key of the request cannot be written.
// The evidence key is held to the request's as the bytes of an uncompressed point (so the curve is held
// too), and the public_key of a KMS proof is held to the one SubjectPublicKeyInfo that the request's key
// has, byte for byte: Base64 that is no key, or the key of another request, is a mismatch.
func compareKeys(key *ecdsa.PublicKey, p *Proof, ev *Evidence) (fault string, err error) {
	want, ok := pointOf(key)
	if !ok {
		return "", fmt.Errorf("%w: the key of the request cannot be written", ErrInternal)
	}
	if p.Store != StoreSoftware {
		if ev.Key == nil {
			return "the evidence holds no key that is the key of the request", nil
		}
		got, gok := pointOf(ev.Key)
		if !gok || !bytes.Equal(got, want) {
			return "the key in the evidence is not the key of the request", nil
		}
	}
	if p.Store == StoreKMS {
		spki, merr := x509.MarshalPKIXPublicKey(key)
		if merr != nil {
			return "", fmt.Errorf("%w: the key of the request cannot be written", ErrInternal)
		}
		if !bytes.Equal(p.kmsKey, spki) {
			return "the public_key of the proof is not the key of the request", nil
		}
	}
	return "", nil
}

// verifyEvidence is check 7. It returns a copy of the evidence; a refusal is in v (and the error is nil), a
// failure to decide is the error, and in both the check stays not-run unless it failed.
func (s *settings) verifyEvidence(ctx context.Context, v *Verdict, req *Request, p *Proof, clock func() (time.Time, error)) (*Evidence, error) {
	if p.Store == StoreSoftware {
		return &Evidence{Unprotected: true}, nil
	}
	verifier := s.verifiers[p.Store]
	if verifier == nil {
		return nil, fmt.Errorf("%w: store %s", ErrNoVerifier, p.Store)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("handoff: the check was stopped before the evidence was read: %w", err)
	}
	now, err := clock()
	if err != nil {
		return nil, err
	}
	ev, err := callVerifier(ctx, verifier, copyRequest(req), p.clone(), now, p.Store)
	if err != nil {
		var refusal *CodeError
		if errors.Is(err, ErrInternal) {
			return nil, err
		}
		if errors.As(err, &refusal) && refusal != nil {
			if refusal.Code == CodeProofInvalid || refusal.Code == CodeMalformed {
				v.fail(7, refusal.Code, jsonset.Escape(refusal.Detail))
				return nil, nil
			}
			return nil, fmt.Errorf("%w: the verifier of %s refused with the code %q, which is not a code of check 7", ErrInternal, p.Store, jsonset.Escape(string(refusal.Code)))
		}
		return nil, fmt.Errorf("handoff: the verifier of %s could not decide: %w", p.Store, err)
	}
	if ev == nil {
		return nil, fmt.Errorf("%w: the verifier of %s returned neither evidence nor an error", ErrInternal, p.Store)
	}
	if ev.Key == nil {
		return nil, fmt.Errorf("%w: the verifier of %s returned evidence with no key", ErrInternal, p.Store)
	}
	// The verifier's own pointers are copied at once, and the rest of the call reads the copy, so that a
	// write by the verifier after it returned changes nothing. A key that is not a P-384 point has no copy;
	// check 8 then finds it is not the key of the request.
	return copyEvidence(ev), nil
}

// clock reads the clock of the configuration under the same protection as a verifier: a clock that panics
// is an [ErrInternal] and never an acceptance.
func (s *settings) clock() (now time.Time, err error) {
	defer func() {
		if r := recover(); r != nil {
			now, err = time.Time{}, fmt.Errorf("%w: the clock panicked", ErrInternal)
		}
	}()
	return s.now().UTC(), nil
}

// callVerifier calls a verifier and turns its panic into an error: a verifier that panics is a verifier
// that broke its contract, and what it was working on is not an acceptance.
func callVerifier(ctx context.Context, verifier EvidenceVerifier, req *Request, p *Proof, now time.Time, store Store) (ev *Evidence, err error) {
	defer func() {
		if r := recover(); r != nil {
			ev, err = nil, fmt.Errorf("%w: the verifier of %s panicked", ErrInternal, store)
		}
	}()
	return verifier.Verify(ctx, req, p, now)
}

// derOfFile returns the DER inside a certificate request file that package pki has accepted as one PEM
// block of its strict form. The decoder of the standard library is not the judge of the file (package pki
// is); it only takes out the bytes that were hashed, which are the same bytes for a file of that form.
func derOfFile(file []byte) ([]byte, error) {
	block, _ := pem.Decode(file)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 {
		return nil, fmt.Errorf("%w: a request file that package pki accepted holds no request block", ErrInternal)
	}
	return block.Bytes, nil
}
