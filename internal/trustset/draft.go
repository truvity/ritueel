package trustset

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"slices"
	"time"

	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/rootlist"
)

// Input is what NewDraft needs. Nothing in it is read from the clock, a file or the environment.
type Input struct {
	// Sequence is the sequence of the new list: 1 to MaxEarlier + 1, the number of the list before
	// it plus one.
	Sequence int64
	// SignedAt is the ceremony time, in whole seconds.
	SignedAt time.Time
	// Roots are the entries of the new list, in any order; the list sorts them.
	Roots []Root
	// Certificates holds, for the label of each root of the new list, the DER of the current
	// certificate of the root key. It holds no other label.
	Certificates map[string][]byte
	// OpenPGPCertificates holds, for the label of each root of the new list that has an
	// OpenPGPFingerprint, the public certificate of its OpenPGP primary: the binary packets that
	// openpgp.NewPrimary returned, with every later certification added (the first form of the
	// keyring file). It holds exactly the labels of those roots and no other label. For a list
	// whose roots have no fingerprint it is nil or empty, and the set then has no keyring file.
	OpenPGPCertificates map[string][]byte
	// LastRecordSHA256 is the end of the history when the plan was made; empty only for sequence 1.
	LastRecordSHA256 string
	// Previous is the bytes of the previous root-list.json; nil only for sequence 1.
	Previous []byte
	// Earlier is every root list of the bundle before this one, in the order of the hash chain
	// with the previous one last. The builder does not order them and never reads a name for an
	// order: the order is the caller's, from the history. A partial or a disordered Earlier is the
	// fault that record 0006, rule 54 exists to catch, so the builder counts it (see checkHistory).
	Earlier []history.RootList
	// Departures has one entry for every root key of the previous list that is not in Roots.
	Departures []Departure
}

// Draft is a list that has been checked and can be signed. It holds the bytes of root-list.json and
// of ca-bundle.pem, which depend on nothing a signer makes, so a plan can name their digests before
// any key is touched. It holds no signature and no key. A Draft is immutable, its methods are safe
// for several goroutines, and every accessor returns copies. A zero Draft refuses everything.
type Draft struct {
	kind     Kind
	sequence int64
	signedAt time.Time

	listJSON, caBundle []byte
	listSHA, caSHA     string

	// keyring is the keyring file in its first form: the certificates of the primaries that the
	// list pins, joined in the order of the list. It is nil, with no digest, for a list that pins
	// none.
	keyring    []byte
	keyringSHA string

	// previous is the previous root-list.json; nil for a first list.
	previous []byte
	// pins are the pins of the roots of the new list.
	pins []string

	required, oneOf, unnamed []string
	// signers maps the label of each key that may be asked to sign to its pin; silent maps the
	// label of each revoked key whose authorisation stands for its signature to its pin.
	signers, silent map[string]string
}

// NewDraft checks everything that can be checked without a key and returns the list and the CA
// bundle, ready to be signed. The checks run in this order and the first fault gives the error:
// the bounds of every input, the sequence and the time, the count and the end of the history, the
// entries, the shape of the change and so who signs, the keys that came back, the labels that are
// never reused (a key that left and comes back under another label is told as a return first:
// record 0006, rule 54), the certificates, the stored authorisations, and last the list and the bundle, which
// the reader of the page must accept, and, for a list that pins OpenPGP primaries, the keyring file,
// which openpgp.ReadKeyring must accept with the entries of the list. No key is used. Every error wraps ErrParams, ErrReturns or
// ErrSelf, and no Draft comes with an error.
func NewDraft(in Input) (*Draft, error) {
	// The bytes that are read are the bytes that are kept: the copy is made first, so a caller
	// that changes Previous later changes neither.
	in.Previous = slices.Clone(in.Previous)
	if len(in.Roots) > MaxRoots || len(in.Certificates) > MaxRoots {
		return nil, fail(ErrParams, "a list holds at most %d root keys and %d certificates are given for at most that many", MaxRoots, MaxRoots)
	}
	if len(in.OpenPGPCertificates) > MaxRoots {
		return nil, fail(ErrParams, "a list holds at most %d root keys and %d OpenPGP certificates are given for at most that many", MaxRoots, MaxRoots)
	}
	if err := checkSequence(in.Sequence); err != nil {
		return nil, err
	}
	signed, _, err := listTimes(in.SignedAt)
	if err != nil {
		return nil, err
	}
	if err := checkAnchor(in.Sequence, in.LastRecordSHA256); err != nil {
		return nil, err
	}
	if err := checkDepartures(in.Departures); err != nil {
		return nil, err
	}
	if err := checkRoots(in.Roots); err != nil {
		return nil, err
	}
	prev, err := checkHistory(in)
	if err != nil {
		return nil, err
	}
	if signedNotBeforePrevious && prev != nil && signed.Before(prev.SignedAt) {
		return nil, fail(ErrParams, "signed_at is earlier than signed_at of the previous list")
	}
	roots := sortRoots(in.Roots)
	pl, err := classify(prev, roots, in.Departures)
	if err != nil {
		return nil, err
	}
	if err := checkReturns(in.Earlier, roots); err != nil {
		return nil, err
	}
	if err := checkLabelsNeverReused(in.Earlier, roots, pl.removals); err != nil {
		return nil, err
	}
	ders, err := certificatesOf(roots, in.Certificates)
	if err != nil {
		return nil, err
	}
	if err := checkAuthorisations(prev, roots, pl.removals); err != nil {
		return nil, err
	}
	d := &Draft{
		kind:     pl.kind,
		sequence: in.Sequence,
		signedAt: signed,
		required: pl.required,
		oneOf:    pl.oneOf,
		unnamed:  pl.unnamed,
		signers:  pl.signers,
		silent:   pl.silent,
		previous: in.Previous,
	}
	for _, r := range roots {
		d.pins = append(d.pins, r.X509SPKISHA256)
	}
	d.listJSON, err = MarshalList(ListSpec{
		Sequence:         in.Sequence,
		SignedAt:         signed,
		Roots:            roots,
		LastRecordSHA256: in.LastRecordSHA256,
		Removals:         pl.removals,
	})
	if err != nil {
		return nil, err
	}
	d.caBundle, err = MarshalCABundle(in.Sequence, roots, ders)
	if err != nil {
		return nil, err
	}
	list, err := rootlist.ParseList(d.listJSON)
	if err != nil {
		return nil, failWith(ErrSelf, "the reader of the page refuses the list that was written", err)
	}
	if v := rootlist.VerifyCABundle(d.caBundle, list); !v.Accepted {
		return nil, failWith(ErrSelf, "the reader of the page refuses the CA bundle that was written", textError(v.Detail))
	}
	d.listSHA, d.caSHA = hexSHA256(d.listJSON), hexSHA256(d.caBundle)
	if d.keyring, err = keyringOf(roots, in.OpenPGPCertificates); err != nil {
		return nil, err
	}
	if d.keyring != nil {
		d.keyringSHA = hexSHA256(d.keyring)
	}
	return d, nil
}

// pinnedEntries returns the entries of roots that have an OpenPGP fingerprint, as the reader of the
// keyring file takes them, in the order of roots.
func pinnedEntries(roots []Root) []openpgp.KeyringEntry {
	var entries []openpgp.KeyringEntry
	for _, r := range roots {
		if r.OpenPGPFingerprint != "" {
			entries = append(entries, openpgp.KeyringEntry{Label: r.Label, Fingerprint: r.OpenPGPFingerprint})
		}
	}
	return entries
}

// keyringOf makes the keyring file of the first form from the certificates that the caller gave: the
// certificates of the roots that have a fingerprint, joined in the order of roots (label order, as
// the list is written), and nothing else. The result is nil for a list that pins no primary, and a
// map of certificates for such a list is refused. The file is then asked of openpgp.ReadKeyring with
// the entries of roots, and its refusal is an ErrParams that carries the sentence of the reader
// (record 0005, rule 12: the bytes are judged by the reader before any key is touched). The roots are
// sorted and hold a fingerprint in all entries or in none (checkRoots).
func keyringOf(roots []Root, certs map[string][]byte) ([]byte, error) {
	entries := pinnedEntries(roots)
	if len(entries) == 0 {
		if len(certs) != 0 {
			return nil, fail(ErrParams, "%d OpenPGP certificates are given and no root has an OpenPGP fingerprint", len(certs))
		}
		return nil, nil
	}
	if len(certs) != len(entries) {
		return nil, fail(ErrParams, "there are %d OpenPGP certificates for %d roots that have an OpenPGP fingerprint", len(certs), len(entries))
	}
	parts := make([][]byte, 0, len(entries))
	for _, e := range entries {
		cert, ok := certs[e.Label]
		if !ok {
			return nil, fail(ErrParams, "there is no OpenPGP certificate for root %s", e.Label)
		}
		if len(cert) == 0 {
			return nil, fail(ErrParams, "the OpenPGP certificate of root %s is empty", e.Label)
		}
		if len(cert) > MaxBytes {
			return nil, fail(ErrParams, "the OpenPGP certificate of root %s is longer than %d bytes", e.Label, MaxBytes)
		}
		parts = append(parts, cert)
	}
	file := slices.Concat(parts...)
	if _, err := openpgp.ReadKeyring(file, entries); err != nil {
		return nil, failWith(ErrParams, "the reader of the keyring file refuses the OpenPGP certificates", err)
	}
	return file, nil
}

// certificatesOf returns the DER certificates of the roots, in the order of roots. The map holds
// one certificate for each root and none for any other label.
func certificatesOf(roots []Root, certs map[string][]byte) ([][]byte, error) {
	if len(certs) != len(roots) {
		return nil, fail(ErrParams, "there are %d certificates for %d roots", len(certs), len(roots))
	}
	out := make([][]byte, len(roots))
	for i, r := range roots {
		der, ok := certs[r.Label]
		if !ok {
			return nil, fail(ErrParams, "there is no certificate for root %s", r.Label)
		}
		out[i] = der
	}
	return out, nil
}

// checkAuthorisations judges every stored authorisation that the list will carry with
// rootlist.CheckRemoval, as a host does at check 9: before anything is signed, so that a lost or
// a wrong authorisation is told before a card is touched. prev is the list before the new one.
func checkAuthorisations(prev *rootlist.List, roots []Root, removals []Removal) error {
	if len(removals) == 0 {
		return nil
	}
	cand := &rootlist.List{Version: rootlist.Version, Roots: make([]rootlist.Root, len(roots))}
	for i, r := range roots {
		cand.Roots[i] = rootlist.Root(r)
	}
	held := prev.Pins()
	for _, rm := range removals {
		if err := rootlist.CheckRemoval(rootlist.Removal(rm), cand, held); err != nil {
			return failWith(ErrParams, "the stored authorisation of root key "+rm.Label+" is not valid", err)
		}
	}
	return nil
}

// valid reports whether d was made by NewDraft.
func (d *Draft) valid() bool {
	return d != nil && d.kind >= KindFirst && d.kind <= KindRevoke && len(d.listJSON) > 0 && len(d.caBundle) > 0
}

// Kind returns what the list does to the root keys; 0 for a zero or nil Draft.
func (d *Draft) Kind() Kind {
	if !d.valid() {
		return 0
	}
	return d.kind
}

// SetName returns the name of the folder of the trust set that this draft makes: its sequence, a
// hyphen and the first eight characters of the SHA-256 of root-list.json, the result of SetName for
// them. It is the empty text for a zero or nil Draft.
func (d *Draft) SetName() string {
	if !d.valid() {
		return ""
	}
	name, err := SetName(d.sequence, d.listSHA)
	if err != nil {
		return ""
	}
	return name
}

// Sequence returns the sequence of the list; 0 for a zero or nil Draft.
func (d *Draft) Sequence() int64 {
	if !d.valid() {
		return 0
	}
	return d.sequence
}

// ListJSON returns a copy of the bytes of root-list.json.
func (d *Draft) ListJSON() []byte {
	if !d.valid() {
		return nil
	}
	return slices.Clone(d.listJSON)
}

// CABundle returns a copy of the bytes of ca-bundle.pem.
func (d *Draft) CABundle() []byte {
	if !d.valid() {
		return nil
	}
	return slices.Clone(d.caBundle)
}

// ListSHA256 returns the SHA-256 of root-list.json in 64 lower-case hexadecimal digits.
func (d *Draft) ListSHA256() string {
	if !d.valid() {
		return ""
	}
	return d.listSHA
}

// CABundleSHA256 returns the SHA-256 of ca-bundle.pem in 64 lower-case hexadecimal digits.
func (d *Draft) CABundleSHA256() string {
	if !d.valid() {
		return ""
	}
	return d.caSHA
}

// Keyring returns a copy of the bytes of the keyring file: the certificates of the primaries that the
// list pins, in the order of the list. It is nil for a list that pins no primary, and for a zero or
// nil Draft.
func (d *Draft) Keyring() []byte {
	if !d.valid() || d.keyring == nil {
		return nil
	}
	return slices.Clone(d.keyring)
}

// KeyringSHA256 returns the SHA-256 of the keyring file in 64 lower-case hexadecimal digits, for the
// caller's journal once the certificates exist. It is empty for a list that pins no primary, and for
// a zero or nil Draft. The plan names no digest for the file: a primary that is born in the ceremony
// has a self-certification that no one can fix before its key exists, and the ceremony record lists
// the file with the digest of the bytes that were read back.
func (d *Draft) KeyringSHA256() string {
	if !d.valid() || d.keyring == nil {
		return ""
	}
	return d.keyringSHA
}

// Required returns the labels that must sign, in label order. It is empty for KindFirst and
// KindRenewal. A revoked key whose stored authorisation is given is not in it: the authorisation
// stands for its signature.
func (d *Draft) Required() []string {
	if !d.valid() {
		return nil
	}
	return slices.Clone(d.required)
}

// OneOf returns, for KindFirst and KindRenewal, the labels of which exactly one signs, in label
// order. It is empty for the other kinds.
func (d *Draft) OneOf() []string {
	if !d.valid() {
		return nil
	}
	return slices.Clone(d.oneOf)
}

// Unnamed returns the labels of the revoked keys whose stored authorisation is lost, in label order:
// the list carries no entry for them, so a host that took a thief's list will not take it. The
// caller warns; this package prints nothing.
func (d *Draft) Unnamed() []string {
	if !d.valid() {
		return nil
	}
	return slices.Clone(d.unnamed)
}

// SigningInputSHA256 is the SHA-256 of the JWS signing input that a signer with this certificate
// would sign, in 64 lower-case hexadecimal digits: the tbs_sha256 of a plan. It reads the
// certificate for its key and its bytes only and needs no key. The certificate is checked as
// Sign checks one (not nil, at most MaxBytes, ECDSA on P-384); it need not be the certificate of a
// root key of this list.
func (d *Draft) SigningInputSHA256(cert *x509.Certificate) (string, error) {
	if !d.valid() {
		return "", fail(ErrParams, "the draft is empty")
	}
	own, pub, err := ownCertificate(cert)
	if err != nil {
		return "", err
	}
	input, err := d.signingInput(signerInfo{cert: own, pub: pub, pin: jws.Pin(own)})
	if err != nil {
		return "", err
	}
	return hexSHA256(input), nil
}

// signingInput returns the bytes that the signer described by info signs: the protected header and
// the list, as the page says.
func (d *Draft) signingInput(info signerInfo) ([]byte, error) {
	protected, err := protectedText(info, rootlist.ListTyp)
	if err != nil {
		return nil, err
	}
	return jws.SigningInput(protected, d.listJSON), nil
}

// hexSHA256 returns the SHA-256 of b in 64 lower-case hexadecimal digits.
func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
