package trustset

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/rootlist"
)

// Signed is what one signature leaves behind, for the journal of signatures. It holds no secret.
type Signed struct {
	// Label is the label of the signing root key.
	Label string
	// Kid is the pin of the signing key.
	Kid string
	// TBSSHA256 is the SHA-256 of the signing input, in 64 lower-case hexadecimal digits: the
	// tbs_sha256 that Draft.SigningInputSHA256 names before the signing.
	TBSSHA256 string
	// SignatureSHA256 is the SHA-256 of the 96 bytes of the signature (r and s), in 64 lower-case
	// hexadecimal digits: the SHA-256 of the signature made (record page, "The journal of
	// signatures").
	SignatureSHA256 string
}

// chosen is one signer that passed the check of the signers.
type chosen struct {
	signer Signer
	info   signerInfo
}

// Sign asks the signers, once each, in the order of their labels, and returns the set. It checks the
// signers against Required and OneOf before any key is used (ErrSigners), and the length of
// root-list.jws, which is known before the first key is asked, against MaxBytes (ErrParams). Each
// signature must be 96 bytes and must verify with the key of the signer's certificate before the
// next signer is asked (ErrSign). after, when it is not nil, is called once after each signature has
// been made and verified; when it returns an error, or panics, Sign stops with ErrSign, asks no more
// signers and returns no set (the line of the caller's journal is the caller's). At the end the
// builder asks the reader of the page about its own output, as a host does (see selfCheck), and
// the set is returned only when the reader accepts it (ErrSelf otherwise). For a list that pins
// OpenPGP primaries the keyring file is part of what the readers judge.
func (d *Draft) Sign(signers []Signer, after func(Signed) error) (*Set, error) {
	if !d.valid() {
		return nil, fail(ErrParams, "the draft is empty")
	}
	picked, err := d.checkSigners(signers)
	if err != nil {
		return nil, err
	}
	inputs := make([][]byte, len(picked))
	headers := make([]string, len(picked))
	dummy := make([]fileSignature, len(picked))
	for i, c := range picked {
		headers[i], err = protectedText(c.info, rootlist.ListTyp)
		if err != nil {
			return nil, err
		}
		inputs[i] = jws.SigningInput(headers[i], d.listJSON)
		dummy[i] = fileSignature{protected: headers[i], sig: make([]byte, jws.SignatureSize)}
	}
	// A signature has a fixed length, so the whole file has its length before a key is asked: a
	// file over MaxBytes is refused here.
	if _, err := marshalGeneral(dummy); err != nil {
		return nil, err
	}
	sigs := make([]fileSignature, 0, len(picked))
	labels := make([]string, 0, len(picked))
	for i, c := range picked {
		sig, err := ask(c.signer, c.info, inputs[i])
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, fileSignature{protected: headers[i], sig: sig})
		labels = append(labels, c.info.label)
		if err := callAfter(after, Signed{
			Label:           c.info.label,
			Kid:             c.info.pin,
			TBSSHA256:       hexSHA256(inputs[i]),
			SignatureSHA256: hexSHA256(sig),
		}); err != nil {
			return nil, err
		}
	}
	file, err := marshalGeneral(sigs)
	if err != nil {
		return nil, err
	}
	if err := d.selfCheck(file); err != nil {
		return nil, err
	}
	return &Set{
		sequence: d.sequence,
		signers:  labels,
		listJSON: slices.Clone(d.listJSON),
		listJWS:  file,
		caBundle: slices.Clone(d.caBundle),
		keyring:  slices.Clone(d.keyring),
	}, nil
}

// callAfter calls the function that the caller gave to Sign, if there is one. An error or a panic
// of it is ErrSign. The error is shown through failWith: its text is taken once and the error is
// never called again.
func callAfter(after func(Signed) error, s Signed) (err error) {
	if after == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = fail(ErrSign, "the function after the signature of %s panicked", s.Label)
		}
	}()
	if cause := after(s); cause != nil {
		return failWith(ErrSign, "the function after the signature of "+s.Label+" failed", cause)
	}
	return nil
}

// checkSigners checks the signers against the draft before any key is used and returns them in the
// order of their labels. The labels are unique; each is a label that may sign (a key of the new list,
// or a retired key or a revoked key without an authorisation of the previous list); a revoked key
// whose authorisation stands for its signature is not a signer; the pin of each certificate is the
// pin of its label; and the labels are the labels of Required plus exactly one of OneOf when OneOf
// is not empty. Every fault is ErrSigners, except a signer that panics when it is read, which is
// ErrSign. No SignES384 is called.
func (d *Draft) checkSigners(signers []Signer) ([]chosen, error) {
	if len(signers) > MaxRoots {
		return nil, fail(ErrSigners, "there are %d signers, at most %d", len(signers), MaxRoots)
	}
	picked := make([]chosen, 0, len(signers))
	seen := make(map[string]bool, len(signers))
	for i, s := range signers {
		info, err := inspect(s)
		if err != nil {
			if errors.Is(err, ErrSign) {
				return nil, err
			}
			return nil, fail(ErrSigners, "signer %d: %s", i, strings.TrimPrefix(err.Error(), ErrParams.Error()+": "))
		}
		if seen[info.label] {
			return nil, fail(ErrSigners, "two signers have the label %s", info.label)
		}
		seen[info.label] = true
		if _, silent := d.silent[info.label]; silent {
			return nil, fail(ErrSigners, "root key %s is revoked and its stored authorisation stands for its signature: it is not asked to sign", info.label)
		}
		pin, ok := d.signers[info.label]
		if !ok {
			return nil, fail(ErrSigners, "root key %s is not a root key that may sign this list", info.label)
		}
		if info.pin != pin {
			return nil, fail(ErrSigners, "the certificate of the signer %s holds another key than the root key %s of the list", info.label, info.label)
		}
		picked = append(picked, chosen{signer: s, info: info})
	}
	for _, label := range d.required {
		if !seen[label] {
			return nil, fail(ErrSigners, "root key %s must sign this list and has no signer", label)
		}
	}
	if len(d.oneOf) > 0 {
		n := 0
		for _, label := range d.oneOf {
			if seen[label] {
				n++
			}
		}
		if n != 1 {
			return nil, fail(ErrSigners, "this list is signed by exactly one root key, and %d signers are given", n)
		}
	}
	for _, c := range picked {
		if !slices.Contains(d.required, c.info.label) && !slices.Contains(d.oneOf, c.info.label) {
			return nil, fail(ErrSigners, "root key %s is not asked to sign this list", c.info.label)
		}
	}
	slices.SortFunc(picked, func(a, b chosen) int { return strings.Compare(a.info.label, b.info.label) })
	return picked, nil
}

// selfCheck asks the reader of the page about the files that the builder made, as a host asks it:
// rootlist.Verify with the previous list as the held list, or with the pins of the list as initial
// pins for a first list, and with the signing time as the clock, so that the checks of the clock
// (signed_at not after it, expires_at after it) are asked at the moment of the ceremony. The verdict
// must be Accepted, not Again and not Wayback (the sequence is the previous one plus one, so the
// way back never applies to a list that this package writes). The CA bundle is judged by
// rootlist.VerifyCABundle against the list that the reader accepted. The keyring file is judged by
// openpgp.ReadKeyring with the entries of that same list (the entries that have a fingerprint, in
// the order of the list), not with the entries of the input: a list that pins no primary has no
// keyring file, and a list that pins primaries has one that the reader accepts and whose primaries
// carry the test mark of the X.509 roots. Any other answer is
// ErrSelf, with the reason code and the number of the check. The builder asks the readers and does
// not read its own files again.
func (d *Draft) selfCheck(jwsFile []byte) error {
	var trust rootlist.Trust
	var err error
	if d.kind == KindFirst {
		trust, err = rootlist.PinTrust(d.pins)
	} else {
		var held *rootlist.Held
		held, err = rootlist.ParseHeld(d.previous)
		trust = rootlist.HeldTrust(held)
	}
	if err != nil {
		return failWith(ErrSelf, "the trust of the self-check cannot be made", err)
	}
	v := rootlist.Verify(rootlist.Signed{JSON: slices.Clone(d.listJSON), JWS: slices.Clone(jwsFile)}, trust, d.signedAt)
	if !v.Accepted || v.Again || v.Wayback {
		return failWith(ErrSelf, "the reader of the page refuses the list that was signed: reason "+string(v.Reason)+", check "+strconv.Itoa(v.Check), textError(v.Detail))
	}
	if cv := rootlist.VerifyCABundle(slices.Clone(d.caBundle), v.List); !cv.Accepted {
		return failWith(ErrSelf, "the reader of the page refuses the CA bundle", textError(cv.Detail))
	}
	return d.selfCheckKeyring(v.List)
}

// selfCheckKeyring asks openpgp.ReadKeyring about the keyring file with the entries of the list that
// the reader of the page accepted. A keyring file with a list that pins no primary, a list that pins
// primaries and no file, a file that the reader refuses, and a file whose primaries do not carry the
// test mark of the X.509 roots of the CA bundle are each an ErrSelf.
func (d *Draft) selfCheckKeyring(list *rootlist.List) error {
	var entries []openpgp.KeyringEntry
	for _, r := range list.Roots {
		if r.OpenPGPFingerprint != "" {
			entries = append(entries, openpgp.KeyringEntry{Label: r.Label, Fingerprint: r.OpenPGPFingerprint})
		}
	}
	switch {
	case len(entries) == 0 && d.keyring == nil:
		return nil
	case len(entries) == 0:
		return fail(ErrSelf, "the draft holds a keyring file and the list that was signed pins no OpenPGP primary")
	case d.keyring == nil:
		return fail(ErrSelf, "the list that was signed pins OpenPGP primaries and the draft holds no keyring file")
	}
	primaries, err := openpgp.ReadKeyring(slices.Clone(d.keyring), entries)
	if err != nil {
		return failWith(ErrSelf, "the reader of the keyring file refuses the keyring file", err)
	}
	if text := markDifference(d.testRoots, primaries[0].TestMark()); text != "" {
		return fail(ErrSelf, "the keyring file does not fit the CA bundle: %s", text)
	}
	return nil
}
