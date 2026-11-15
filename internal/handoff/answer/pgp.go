package answer

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/openpgp"
)

// The codes of the faults that the contract's OpenPGP table does not name; each is kept here, in one place. A
// bound file that is not one subkey packet and one signature packet is a fault of the form of the file. A
// binding whose signature verified and whose subpackets are not the set of the page, or that is older than its
// subkey or its primary, is a binding that is not what was asked: both are proposed, and built as `profile`.
const (
	codeBoundFileShape = CodeMalformed
	codeBindingShape   = CodeProfile
	codeBindingAge     = CodeProfile
)

// checkOpenPGP judges an answer to an openpgp-subkey request by the eight checks of the full contract: the files
// are `<stem>.result.json` and `<stem>.bound.pgp`. The binding is read by package openpgp, the same package
// that writes it, so that an answer that BindSubkey writes is an answer that the requester accepts, and no other.
// The primary that is tried is taken from what the requester holds (its own request, its keyring and the signed
// list), never from the file: the file only says which one to look for.
func (r *run) checkOpenPGP() (Verdict, error) {
	r.begin(pgpNames[:])
	res, err := r.readResultFile()
	if err != nil || res == nil {
		return r.v, err
	}
	if res.outcome == outcomeRefused {
		return r.refusedAnswer(res, FileResult)
	}

	// Check 2, the files: result.json and the bound file, which is exactly two packets.
	if fault := r.onlyFiles(FileResult, FileBound); fault != "" {
		r.v.fail(2, CodeMalformed, fault)
		return r.v, nil
	}
	subkeyPacket, bindingPacket, err := openpgp.SplitBoundFile(r.files[FileBound])
	if err != nil {
		if errors.Is(err, openpgp.ErrBoundFile) {
			r.v.fail(2, codeBoundFileShape, "the bound file is not one Public-Subkey packet and one Signature packet")
			return r.v, nil
		}
		return r.v, fmt.Errorf("%w: reading the bound file: %w", ErrInternal, err)
	}
	r.v.pass(2)

	// Check 3: the answer is for this request.
	if !r.forThisRequest(res) {
		return r.v, nil
	}

	// Check 4: the first packet is the subkey of the request, byte for byte. A different header form of the same
	// key is another file, and is refused: BindSubkey returns the packet as it came.
	if !bytes.Equal(subkeyPacket, r.a.subkeyFirst) {
		r.v.fail(4, CodeKeyMismatch, "the first packet of the bound file is not the subkey of the request")
		return r.v, nil
	}
	r.v.pass(4)

	// Check 5: the binding verifies, and the primary is one that the requester named.
	binding, shapeErr, idx, prim, err := r.verifiesToPrimary(res, bindingPacket)
	if err != nil || r.v.Code != "" {
		return r.v, err
	}
	r.v.pass(5)

	// Check 6: the profile.
	if code, fault := r.pgpProfileFault(binding, shapeErr, idx, prim); fault != "" {
		r.v.fail(6, code, fault)
		return r.v, nil
	}
	r.v.pass(6)

	// Check 7: the validity.
	if fault := r.pgpValidityFault(binding); fault != "" {
		r.v.fail(7, CodeValidity, fault)
		return r.v, nil
	}
	r.v.pass(7)

	// Check 8: the digests and the dates of result.json match the file. The issuer was compared at check 5.
	if fault := r.digestsFault(res, FileBound); fault != "" {
		r.v.fail(8, CodeMalformed, fault)
		return r.v, nil
	}
	if !res.validFrom.Equal(binding.Created()) || !res.validUntil.Equal(binding.Ends()) {
		r.v.fail(8, CodeMalformed, "valid_from or valid_until is not the validity of the binding")
		return r.v, nil
	}
	r.v.pass(8)
	r.v.accept(Info{
		Type:          handoff.TypeOpenPGP,
		Stem:          r.stem,
		ValidFrom:     binding.Created(),
		ValidUntil:    binding.Ends(),
		Issuer:        binding.IssuerFingerprint(),
		TrustSequence: res.trustSequence,
	})
	return r.v, nil
}

// verifiesToPrimary is check 5, in this order: trust_sequence is at most the sequence of the held list (the
// OpenPGP table of the contract has no such row, and "The answer" says it for every type); issuer is the issuer
// that the binding names; that fingerprint is one of the primaries that the request named and the
// openpgp_fingerprint of a root of the held list (a primary that was retired, and is still in the keyring, is
// refused: the certifier binds only with an active primary); the requester holds the key of that primary, and
// when it does not the checker cannot decide ([ErrNoPrimaryKey], check 5 and the checks after it are not-run);
// and the binding verifies with that key over the primary and the subkey. A binding whose signature verified and
// whose subpackets are not the set of the page passes this check, and is returned as shapeErr, for check 6.
//
// When a check fails the verdict says so and the other results are zero. The error is non-nil only when the
// checker cannot decide.
func (r *run) verifiesToPrimary(res *result, bindingPacket []byte) (b *openpgp.Binding, shapeErr error, idx int, prim preparedPrimary, err error) {
	fail := func(detail string) {
		r.v.fail(5, CodeIssuer, detail)
	}
	if res.trustSequence > r.s.held.sequence {
		fail(fmt.Sprintf("the answer needs trust sequence %d, and the root list that the requester holds is %d", res.trustSequence, r.s.held.sequence))
		return nil, nil, 0, prim, nil
	}
	fp, ierr := openpgp.BindingIssuer(bindingPacket)
	if ierr != nil {
		if !errors.Is(ierr, openpgp.ErrBinding) {
			return nil, nil, 0, prim, fmt.Errorf("%w: reading the issuer of the binding: %w", ErrInternal, ierr)
		}
		fail("the binding names no issuer fingerprint of version 4")
		return nil, nil, 0, prim, nil
	}
	if res.issuer != fp {
		fail("issuer is not the fingerprint of the primary that made the binding")
		return nil, nil, 0, prim, nil
	}
	idx = slices.Index(r.a.primaries, fp)
	if idx < 0 {
		fail("the primary that made the binding is not one that the request named")
		return nil, nil, 0, prim, nil
	}
	if !slices.Contains(r.s.held.pgp, fp) {
		fail("the primary that made the binding is not on the root list that the requester holds")
		return nil, nil, 0, prim, nil
	}
	prim, ok := r.s.primary(fp)
	if !ok {
		r.v.skipFrom(5, reasonNoKey)
		return nil, nil, 0, prim, fmt.Errorf("%w: the primary %s is named by the request and is on the held list", ErrNoPrimaryKey, fp)
	}
	b, verr := openpgp.VerifyBinding(bindingPacket, prim.key, r.a.sub)
	switch {
	case verr == nil:
		return b, nil, idx, prim, nil
	case errors.Is(verr, openpgp.ErrBindingShape):
		return nil, verr, idx, prim, nil
	case errors.Is(verr, openpgp.ErrBinding):
		fail("the binding does not verify with the key of the primary")
		return nil, nil, 0, prim, nil
	}
	return nil, nil, 0, prim, fmt.Errorf("%w: verifying the binding: %w", ErrInternal, verr)
}

// pgpProfileFault is check 6: the subpackets of the binding are the set of the page (one critical subpacket
// only), and the binding is not older than its subkey or its primary; the key flags are exactly the capability
// that was asked; and the embedded signature is the back-signature that the request holds for the primary that
// made the binding, byte for byte. It returns the code and the fault in fixed words, or an empty fault.
func (r *run) pgpProfileFault(b *openpgp.Binding, shapeErr error, idx int, prim preparedPrimary) (Code, string) {
	if shapeErr != nil {
		return codeBindingShape, codeBindingShapeText(shapeErr)
	}
	if b.Created().Before(r.a.sub.Created()) {
		return codeBindingAge, "the binding was made before its subkey was created"
	}
	if b.Created().Before(prim.key.Created()) {
		return codeBindingAge, "the binding was made before its primary was created"
	}
	if b.Capability() != r.a.capability {
		return CodeProfile, "the key flags of the binding are not the capability that was asked"
	}
	if !b.Embeds(r.a.backSigs[idx]) {
		return CodeProfile, "the embedded signature is not the back-signature of the request for this primary"
	}
	return "", ""
}

// codeBindingShapeText is the detail of a binding whose subpackets are not the set of the page: the words of
// package openpgp for the fault, escaped.
func codeBindingShapeText(err error) string {
	return jsonset.Escape(strings.TrimPrefix(err.Error(), openpgp.ErrBindingShape.Error()+": "))
}

// pgpValidityFault is check 7: the binding was made at or before the time of the check, the subkey has not
// ended (it ends at the instant Ends, so it has ended when the clock is not before it), and the length from the
// creation time of the binding to the end of the subkey is between Min and Max calendar months.
func (r *run) pgpValidityFault(b *openpgp.Binding) string {
	created, ends := b.Created(), b.Ends()
	if created.After(r.now) {
		return "the binding was made after the time of the check"
	}
	if !r.now.Before(ends) {
		return "the subkey has ended"
	}
	return r.s.lengthFault(created, ends, "the subkey")
}
