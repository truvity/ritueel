package handoff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/openpgp"
)

// codeSubkeyForm is the code of a subkey file that is not whole OpenPGP packets, whose first packet is not a
// Public-Subkey packet, or whose key packet is not in the form of the profile. The contract gives `malformed`
// for the files of the other types that are not of the form of the page and is silent for this one, so the
// code is proposed, and it is kept here, in one place.
const codeSubkeyForm = CodeMalformed

// codeSubkeyVersion is the code of a subkey whose key is not a version 4 ECDSA key on P-384. The page gives
// `algorithm-unsupported` for another algorithm and another curve; for a version other than 4 it says that
// version 6 waits for a later version of the contract and is silent on the code, so that part is proposed. It
// is kept here, in one place.
const codeSubkeyVersion = CodeAlgorithmUnsupported

// checkOpenPGP runs checks 2 to 9 for a request of type openpgp-subkey: the subkey file is read by package
// openpgp, which is also the reader of the ceremony's binding, so that the request that is checked is the
// request that is bound. The checks run in order and the first fault gives the code. The clock is read once,
// after check 4, and the one reading, cut to whole seconds, is the time of check 5 and of the verifier of
// check 7.
func (s *settings) checkOpenPGP(ctx context.Context, v Verdict, req *Request, p *Proof) (Verdict, error) {
	// Check 2: the file is whole packets of the profile. A key of another kind is kept for check 4, as an
	// x509-intermediate keeps its check 4 and 5 faults for their turn.
	file, ok := req.Files[FileSubkey]
	if !ok {
		v.fail(2, CodeMalformed, "the request has no file "+FileSubkey)
		return v, nil
	}
	if len(file) > MaxFileSize {
		v.fail(2, CodeMalformed, fmt.Sprintf("the file %s is longer than %d bytes", FileSubkey, MaxFileSize))
		return v, nil
	}
	first, sigs, err := openpgp.SplitSubkeyFile(file, MaxPrimaries)
	if err != nil {
		if errors.Is(err, openpgp.ErrForm) {
			v.fail(2, codeSubkeyForm, faultOf(err, openpgp.ErrForm))
			return v, nil
		}
		return v, fmt.Errorf("%w: reading the subkey file: %w", ErrInternal, err)
	}
	sub, subErr := openpgp.ReadSubkey(first)
	switch {
	case subErr == nil:
	case errors.Is(subErr, openpgp.ErrForm):
		v.fail(2, codeSubkeyForm, faultOf(subErr, openpgp.ErrForm))
		return v, nil
	case errors.Is(subErr, openpgp.ErrAlgorithm):
		// Told at check 4.
	default:
		return v, fmt.Errorf("%w: reading the subkey: %w", ErrInternal, subErr)
	}
	v.pass(2)

	// A checker that holds no primaries cannot judge this type: the request is neither accepted nor refused.
	if len(s.primaries) == 0 {
		return v, errNoPrimaries("the checker holds no primaries")
	}

	// Check 3: the digest of the bytes of the file, then the primaries.
	if sum := sha256.Sum256(file); hex.EncodeToString(sum[:]) != p.RequestSHA256 {
		v.fail(3, CodeRequestMismatch, "request_sha256 is not the digest of the file "+FileSubkey)
		return v, nil
	}
	if fault := primariesInListOrder(p.Primaries, s.primaries); fault != "" {
		v.fail(3, CodeUnknownPrimary, fault)
		return v, nil
	}
	v.pass(3)

	// Check 4: the key.
	if subErr != nil {
		v.fail(4, codeSubkeyVersion, faultOf(subErr, openpgp.ErrAlgorithm))
		return v, nil
	}
	v.pass(4)

	// Check 5: the clock is read once, and a time that an OpenPGP time field cannot hold is a fault of the
	// checker and not of the request.
	now, err := s.clock()
	if err != nil {
		return v, err
	}
	now = now.Truncate(time.Second)
	if !holdsTime(now) {
		return v, fmt.Errorf("%w: the clock is outside the years 1970 to 2106", ErrInternal)
	}
	// Every active primary is held to the clock of this call, as New held it to the clock that it read: a
	// clock that failed then, or has stepped back since, does not skip the guard. This is a checker that
	// cannot decide and not a refusal: no code of the contract names it.
	if fp, after := s.primaryAfter(now); after {
		return v, fmt.Errorf("%w: the primary %s was created after the clock that this check read", ErrConfig, fp)
	}
	if sub.Created().After(now) {
		v.fail(5, CodePossessionInvalid, "the subkey was created after the time of the check")
		return v, nil
	}
	if len(sigs) != len(s.primaries) {
		v.fail(5, CodePossessionInvalid, fmt.Sprintf("the number of packets after the subkey is %d and primaries lists %d", len(sigs), len(s.primaries)))
		return v, nil
	}
	for i, sig := range sigs {
		err := openpgp.VerifyBackSignature(sig, s.primaries[i].key, sub, now)
		switch {
		case err == nil:
		case errors.Is(err, openpgp.ErrBackSignature):
			v.fail(5, CodePossessionInvalid, fmt.Sprintf("back-signature %d: %s", i+1, faultOf(err, openpgp.ErrBackSignature)))
			return v, nil
		default:
			return v, fmt.Errorf("%w: checking back-signature %d: %w", ErrInternal, i+1, err)
		}
	}
	v.pass(5)

	// Checks 6 to 8, with the subkey's key as the key of the request and the one reading of the clock.
	key := sub.PublicKey()
	if key == nil {
		return v, fmt.Errorf("%w: the key of a subkey that package openpgp accepted cannot be written", ErrInternal)
	}
	ev, err := s.checkStoreEvidenceKey(ctx, &v, req, p, key, func() (time.Time, error) { return now, nil })
	if err != nil || v.Refused() {
		return v, err
	}

	// Check 9: the policy.
	if fault := s.openpgpPolicyRules(sub, p, ev); fault != "" {
		v.fail(9, CodePolicy, fault)
		return v, nil
	}
	if !s.hasDelegation() {
		// Every rule that could run passed, and the rules that need a delegation did not run: the check is
		// not-run with them named, and the request is not accepted.
		v.partial(9, notRunWithoutDelegation(p.Type))
		return v, nil
	}
	v.pass(9)
	v.accept(key, ev)
	v.Subkey = &SubkeyInfo{Fingerprint: sub.Fingerprint(), Created: sub.Created(), Capability: p.Capabilities[0]}
	return v, nil
}

// primariesInListOrder is the second half of check 3: primaries is exactly the list of fingerprints of the
// active primaries of the root list, entry by entry, in the order of the list. The contract says "in the
// order of that list" and the root list page says that its roots are "the order in which a hand-off request
// lists primaries". It returns the detail of the fault, or an empty string. The detail names counts and the
// first position that differs, and no byte of the request.
func primariesInListOrder(listed []string, held []preparedPrimary) string {
	if len(listed) != len(held) {
		return fmt.Sprintf("primaries lists %d fingerprints and the root list has %d active primaries", len(listed), len(held))
	}
	for i := range held {
		if listed[i] != held[i].fingerprint {
			return fmt.Sprintf("primaries is not the active primaries of the root list in the order of the list: position %d differs", i+1)
		}
	}
	return ""
}

// faultOf is the text of an error of package openpgp without the words of its kind, escaped: the detail of a
// refusal.
func faultOf(err, kind error) string {
	return jsonset.Escape(strings.TrimPrefix(err.Error(), kind.Error()+": "))
}
