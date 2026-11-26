package ceremony

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/trustset"
	"ritueel.id/ritueel/internal/wanted"
)

// x509Kind is the X.509 root of a software test root: two keys by default, a self-signed root
// certificate and a removal authorisation for each, a root.json for each, and the first trust set
// (record 0005, rules 10 to 12 and 20; docs/reference/bundle.md, "The root certificate").
type x509Kind struct{}

// Make runs the births, the signatures and the checks of one X.509 test root. See [MakeRoots].
func (x509Kind) Make(ctx context.Context, in MakeIn) (made *Made, err error) {
	m := &x509Maker{in: in}
	defer m.closeKeys()
	return m.run(ctx)
}

// x509Maker is one run of [x509Kind.Make].
type x509Maker struct {
	in     MakeIn
	plan   *PlanOut
	labels []string
	tap    *tapTrace

	keys    []keystore.Key
	pubs    map[string]*ecdsa.PublicKey
	pins    map[string]string
	certs   map[string][]byte
	removal map[string]string
	signers map[string]trustset.Signer
	born    []BornKey
	made    []MadeSignature
	set     *trustset.Set
}

// closeKeys closes every key that the store gave, whatever happened.
func (m *x509Maker) closeKeys() {
	for _, k := range m.keys {
		if !isNilValue(k) {
			_ = guard("key", k.Close)
		}
	}
}

// run is the whole of Make: the input, the refusals that need no key, the births, the fingerprints,
// the signatures and the checks.
func (m *x509Maker) run(ctx context.Context) (*Made, error) {
	if err := m.checkInput(ctx); err != nil {
		return nil, err
	}
	// Every refusal that needs no key comes before the first key (the key directory, key files
	// that exist already), even when the caller ran it before the confirmation.
	if err := guard("key store", func() error { return m.in.Store.Refuse(ctx) }); err != nil {
		return nil, err
	}
	// The key store is started here when the run did not start it before the attempt: a second start with the
	// same labels does nothing, and a store that is started makes no key.
	if err := guard("key store", func() error { return m.in.Store.Start(ctx, m.labels) }); err != nil {
		return nil, err
	}
	m.pubs, m.pins = map[string]*ecdsa.PublicKey{}, map[string]string{}
	m.certs, m.removal = map[string][]byte{}, map[string]string{}
	m.signers = map[string]trustset.Signer{}
	if err := m.birth(ctx); err != nil {
		return nil, err
	}
	m.show()
	if err := m.shownFault(); err != nil {
		return nil, err
	}
	if err := m.sign(ctx); err != nil {
		return nil, err
	}
	return m.check(ctx)
}

// checkInput refuses everything that is wrong before the first key is made. The plan is read again
// from its bytes with [ReadPlanOut], and every value used afterwards is taken from that reading.
func (m *x509Maker) checkInput(ctx context.Context) error {
	bad := func(format string, args ...any) error { return makeErr("input", nil, format, args...) }
	in := m.in
	if ctx == nil {
		return bad("there is no context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if isNilValue(in.Store) {
		return bad("there is no key store")
	}
	if in.Plan == nil || len(in.Plan.JSON) == 0 {
		return bad("there is no plan")
	}
	own, err := ReadPlanOut(in.Plan.JSON)
	if err != nil {
		return makeErr("input", err, "the plan is refused by its reader")
	}
	if own.SHA256 != in.Plan.SHA256 {
		return bad("the digest of the plan is not the digest of its bytes")
	}
	m.plan = own
	if in.Settings == nil || !in.Settings.Valid() || in.Settings.Personal || in.Settings.Name == "" {
		return bad("ritueel.yaml was not read by its reader, or is not that of a company bundle")
	}
	if in.Root == nil || !in.Root.Valid() || in.Root.Kind != wanted.RootX509 || !in.Root.Test || in.Root.Name != own.RootName {
		return bad("the wanted root file is not the X.509 test root that the plan names")
	}
	// The name in a certificate comes from ritueel.yaml, and the check of the certificate reads it
	// from the same place, so the settings and the root file are held to the plan that the person
	// confirmed: their paths and digests are exactly the two entries of its list of wanted files.
	given := []files.FileRef{
		{Path: in.Settings.File.Path, SHA256: in.Settings.File.SHA256},
		{Path: in.Root.File.Path, SHA256: in.Root.File.SHA256},
	}
	slices.SortFunc(given, func(a, b files.FileRef) int { return strings.Compare(a.Path, b.Path) })
	if !slices.Equal(given, own.Wanted) {
		return bad("ritueel.yaml and the wanted root file are not the two files of the confirmed plan, by path and digest")
	}
	if _, err := in.Env.now(); err != nil {
		return err
	}
	if !consoleMade(in.Env.Out) {
		return bad("there is no console to show the fingerprints on, and a person must see every key before any key signs")
	}
	var kind keystore.Kind
	var copyable bool
	if err := guard("key store", func() error { kind, copyable = in.Store.Kind(), in.Store.Copyable(); return nil }); err != nil {
		return err
	}
	if own.Plan == nil || own.Plan.Root == nil || own.Plan.Root.Copyable != copyable {
		return bad("the plan says another thing than the store about whether a key can be copied")
	}
	for _, b := range own.Births {
		var place string
		if err := guard("key store", func() error { place = in.Store.Place(b.Label); return nil }); err != nil {
			return err
		}
		if b.Store != string(kind) || b.Purpose != purposeX509Root || b.Place != place {
			return bad("the birth of the key %s names another store, purpose or place than the store gives", b.Label)
		}
		m.labels = append(m.labels, b.Label)
	}
	tap, err := newTap(in.Trace)
	if err != nil {
		return makeErr("input", err, "the journals are not usable")
	}
	m.tap = tap
	return nil
}

// consoleMade reports whether c was made by NewConsole.
func consoleMade(c *Console) bool {
	if c == nil {
		return false
	}
	_, err := c.Transcript()
	return !errors.Is(err, ErrNoConsole)
}

// publicOf returns the public key of a key of the store and its pin, or an error for a key that is not
// an ECDSA key on P-384.
func publicOf(k keystore.Key) (*ecdsa.PublicKey, string, error) {
	var pub any
	if err := guard("key", func() error { pub = k.Public(); return nil }); err != nil {
		return nil, "", err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key == nil || key.Curve != elliptic.P384() {
		return nil, "", errors.New("the key is not an ECDSA key on P-384")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, "", errors.New("the public key cannot be written")
	}
	return key, pinOfSPKI(der), nil
}

// birth asks the store for each key, in the order of the plan, and writes the line of the birth
// journal only after Birth returned (record 0005, rule 10).
func (m *x509Maker) birth(ctx context.Context) error {
	for _, b := range m.plan.Births {
		if err := ctx.Err(); err != nil {
			return err
		}
		var key keystore.Key
		if err := guard("key store", func() (e error) { key, e = m.in.Store.Birth(ctx, b.Label); return e }); err != nil {
			// A store that returns a key with an error has broken its contract; the key is closed.
			if !isNilValue(key) {
				_ = guard("key", key.Close)
			}
			return wrapKeyFault(err, "births", "the key %s was not born", b.Label)
		}
		if isNilValue(key) {
			return makeErr("births", nil, "the store gave no key for %s", b.Label)
		}
		m.keys = append(m.keys, key)
		pub, pin, err := publicOf(key)
		if err != nil {
			return makeErr("births", err, "the key %s is refused", b.Label)
		}
		var kind keystore.Kind
		var copyable bool
		if err := guard("key", func() error { kind, copyable = key.Kind(), key.Copyable(); return nil }); err != nil {
			return err
		}
		if string(kind) != b.Store || copyable != m.plan.Plan.Root.Copyable {
			return makeErr("births", nil, "the key %s is not of the store, or not as copyable, as the plan says", b.Label)
		}
		var place string
		if err := guard("key store", func() error { place = m.in.Store.Place(b.Label); return nil }); err != nil {
			return err
		}
		m.pubs[b.Label], m.pins[b.Label] = pub, pin
		m.born = append(m.born, BornKey{Label: b.Label, Store: string(kind), Place: place, Pin: pin})
		at, err := m.in.Env.now()
		if err != nil {
			return err
		}
		line := files.BirthLine{At: timeText(at), Label: b.Label, Purpose: b.Purpose, Store: b.Store, Place: b.Place, PublicKeySHA256: pin}
		raw, err := line.Canonical()
		if err != nil {
			return makeErr("births", err, "the birth line of %s cannot be written", b.Label)
		}
		if err := m.tap.births.Append(raw); err != nil {
			return makeErr("births", err, "the birth line of %s was not written", b.Label)
		}
	}
	return nil
}

// wrapKeyFault returns a refusal of the key store as it is, so that the command maps its exit code,
// and any other fault as a MakeError.
func wrapKeyFault(err error, step, format string, args ...any) error {
	var be *BackendError
	if errors.As(err, &be) {
		return err
	}
	return makeErr(step, err, format, args...)
}

// show prints the fingerprint of each key, after the last birth and before the first signature, so
// that a person sees every new key before any key signs for it (record 0005, rule 11).
func (m *x509Maker) show() {
	for _, l := range m.labels {
		m.in.Env.Out.Err("root key %s: x509 pin %s", l, m.pins[l])
	}
}

// shownFault asks the console for its fault after the fingerprints are printed. A console that could
// not print a line, or that kept too much, has not shown them, and the run stops before the first
// signature (record 0005, rule 11). The keys are born and saved by then, and the error says so and
// names what is on disk.
func (m *x509Maker) shownFault() error {
	if _, err := m.in.Env.Out.Transcript(); err != nil {
		places := make([]string, 0, len(m.born))
		for _, b := range m.born {
			places = append(places, b.Place)
		}
		return makeErr("fingerprints", err, "the fingerprints could not be shown, so no key signs: the keys are born and nothing is signed; the key store holds %s and the births journal holds %d lines",
			strings.Join(places, " and "), len(m.tap.births.read().Lines))
	}
	return nil
}

// signatureLine writes the line of the journal of signatures for the signature n of the plan, after
// the signature exists.
func (m *x509Maker) signatureLine(n int64, keyPin, signatureSHA256 string) error {
	s := m.plan.Signatures[n-1]
	at, err := m.in.Env.now()
	if err != nil {
		return err
	}
	line := files.SignatureLine{At: timeText(at), N: n, Kind: s.Kind, Key: keyPin, SignatureSHA256: signatureSHA256}
	raw, err := line.Canonical()
	if err != nil {
		return makeErr("signatures", err, "the line of the signature %d cannot be written", n)
	}
	if err := m.tap.signatures.Append(raw); err != nil {
		return makeErr("signatures", err, "the line of the signature %d was not written", n)
	}
	m.made = append(m.made, MadeSignature{N: n, Kind: s.Kind, Subject: s.Subject, Key: keyPin, SignatureSHA256: signatureSHA256})
	return nil
}

// sha256Hex is the SHA-256 of b in lower-case hexadecimal.
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sign makes, in the order of the plan, the root certificate and the removal authorisation of each
// key, then the first list, and writes one line of the journal of signatures after each.
func (m *x509Maker) sign(ctx context.Context) error {
	for i, label := range m.labels {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := m.keys[i]
		if err := m.signCertificate(ctx, i, label, key); err != nil {
			return err
		}
		if err := m.signRemoval(ctx, i, label, key); err != nil {
			return err
		}
	}
	return m.signList(ctx)
}

// signCertificate makes the root certificate of a label: the body from the parameters, the signature
// of the key itself, and the certificate put together and verified by internal/pki.
func (m *x509Maker) signCertificate(ctx context.Context, i int, label string, key keystore.Key) error {
	s := m.plan.Signatures[2*i]
	serial, ok := new(big.Int).SetString(s.Serial, 16)
	if !ok {
		return makeErr("signatures", nil, "the serial of the certificate %s is not a number", label)
	}
	params := pki.RootParams{Name: m.in.Settings.Name, Label: label, Test: true, CeremonyTime: m.plan.Time, Key: m.pubs[label], Serial: serial}
	var der, sig []byte
	err := guard("key", func() error {
		tbs, err := pki.RootTBS(params)
		if err != nil {
			return err
		}
		if sig, err = pki.SignRoot(nil, key, params, tbs); err != nil {
			return err
		}
		der, err = pki.Assemble(tbs, sig, m.pubs[label])
		return err
	})
	if err != nil {
		cause, ended := signFault(ctx, err)
		if ended {
			return cause
		}
		return makeErr("signatures", cause, "the root certificate of %s was not made", label)
	}
	m.certs[label] = der
	return m.signatureLine(s.N, m.pins[label], sha256Hex(sig))
}

// signFault is what a fault of a signing says when the context has ended. A key store that signs in a
// process or on a device sees the end of the context while it signs. When the fault itself is the end of
// the context (a cancel or a deadline), the run says that the context ended, as it does when it sees it
// between two steps: the cause is the error of the context and ended is true. When the fault is something
// else (a key that changed, a signature that did not verify, a refusal of the store), the cause stays the
// reason of the stop, and the end of the context is named beside it, so that the line of the stop names the
// cause that matters; ended is false. When the context has not ended the cause is the fault. The decision is
// made on the typed errors only (errors.Is with the two errors of the context package): the key port's
// client maps its Connect codes for a cancel and a deadline to them (port.Key.Sign), the signers of
// trustset keep that one fact of their cause, and the text of an error is never read for it, so a refusal
// that quotes the words of a cancel is a refusal.
func signFault(ctx context.Context, err error) (cause error, ended bool) {
	cerr := ctx.Err()
	if cerr == nil {
		return err, false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return cerr, true
	}
	return fmt.Errorf("%w; the context also ended: %w", err, cerr), false
}

// signRemoval makes the removal authorisation of a label, stores it next to the key, and only then
// writes its line.
func (m *x509Maker) signRemoval(ctx context.Context, i int, label string, key keystore.Key) error {
	s := m.plan.Signatures[2*i+1]
	cert, err := x509.ParseCertificate(m.certs[label])
	if err != nil {
		return makeErr("signatures", err, "the certificate of %s does not parse", label)
	}
	var signer trustset.Signer
	var text string
	err = guard("key", func() (e error) {
		if signer, e = trustset.NewKeySigner(label, cert, key); e != nil {
			return e
		}
		text, e = trustset.NewRemoval(signer)
		return e
	})
	if err != nil {
		cause, ended := signFault(ctx, err)
		if ended {
			return cause
		}
		return makeErr("signatures", cause, "the removal authorisation of %s was not made", label)
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return makeErr("signatures", nil, "the removal authorisation of %s is not three parts", label)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return makeErr("signatures", err, "the signature of the removal authorisation of %s is not Base64url", label)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := guard("key store", func() error { return m.in.Store.SaveRemoval(label, []byte(text)) }); err != nil {
		return wrapKeyFault(err, "signatures", "the removal authorisation of %s was not stored", label)
	}
	m.signers[label] = signer
	m.removal[label] = text
	return m.signatureLine(s.N, m.pins[label], sha256Hex(sig))
}

// signList makes the first trust set: the draft of the list and the CA bundle, which needs no key,
// and the signature of the key with the lowest label, with the line of the journal written in the
// callback of the signature.
func (m *x509Maker) signList(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	last := len(m.plan.Signatures)
	listSig := m.plan.Signatures[last-1]
	signer, ok := m.signers[listSig.Subject]
	if !ok {
		return makeErr("list", nil, "the key that signs the list, %s, has no signer", listSig.Subject)
	}
	roots := make([]trustset.Root, 0, len(m.labels))
	for _, l := range m.labels {
		roots = append(roots, trustset.Root{Label: l, X509SPKISHA256: m.pins[l]})
	}
	var set *trustset.Set
	err := guard("signer", func() error {
		d, err := trustset.NewDraft(trustset.Input{Sequence: firstTrustSequence, SignedAt: m.plan.Time, Roots: roots, Certificates: m.certs})
		if err != nil {
			return err
		}
		set, err = d.Sign([]trustset.Signer{signer}, func(s trustset.Signed) error {
			if s.Label != listSig.Subject || s.Kid != m.pins[listSig.Subject] {
				return errors.New("the signature is not by the key that the plan names")
			}
			return m.signatureLine(int64(last), s.Kid, s.SignatureSHA256)
		})
		return err
	})
	if err != nil {
		return makeErr("list", err, "the first trust set was not made")
	}
	m.set = set
	return nil
}

// check judges every artifact with the checks of artifacts.go, by readers that did not make them,
// and returns the artifacts. A fault stops here and returns nothing: no file was written by this
// function, and the attempt stays open for the caller to say so.
func (m *x509Maker) check(ctx context.Context) (*Made, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := m.plan
	// The plan against the born keys comes first: every later step reads the list of born keys by
	// the position of a label, and a list that is shorter than the plan's is an error, not a panic.
	if err := CheckPlanAgainstKeys(p, m.born, m.made); err != nil {
		return nil, err
	}
	var certs [][]byte
	var pins []string
	for i, l := range m.labels {
		s := p.Signatures[2*i]
		want := RootCertWant{Name: m.in.Settings.Name, Label: l, Pin: m.pins[l], Serial: s.Serial, NotBefore: p.Time}
		na, err := parseTime(s.NotAfter)
		if err != nil {
			return nil, makeErr("checks", err, "not_after of the certificate %s is not a time", l)
		}
		want.NotAfter = na
		if err := CheckRootCertificate(m.certs[l], want); err != nil {
			return nil, err
		}
		certs = append(certs, m.certs[l])
		pins = append(pins, m.pins[l])
	}
	for _, l := range m.labels {
		var stored []byte
		if err := guard("key store", func() (e error) { stored, e = m.in.Store.ReadRemoval(ctx, l); return e }); err != nil {
			return nil, wrapKeyFault(err, "checks", "the removal authorisation of %s cannot be read back", l)
		}
		if err := CheckRemovalAuthorisation(l, m.pins[l], m.certs[l], m.removal[l], stored); err != nil {
			return nil, err
		}
	}
	signer := p.Signatures[len(p.Signatures)-1].Subject
	want := RootListWant{Labels: m.labels, Pins: pins, Certificates: certs, SignedAt: p.Time, Signer: signer}
	list, err := CheckRootList(m.set, want)
	if err != nil {
		return nil, err
	}
	if err := CheckCABundle(m.set.CABundle(), list, want); err != nil {
		return nil, err
	}
	made := &Made{Set: m.set}
	for i, l := range m.labels {
		removalSHA := files.Digest([]byte(m.removal[l]))
		doc := files.RootJSON{
			Version: files.FormatVersion, Label: l, Store: storeSoftware, Test: true, CreatedAt: timeText(p.Time),
			X509SPKISHA256: m.pins[l], RemovalSHA256: removalSHA,
		}
		b, err := doc.Canonical()
		if err != nil {
			return nil, makeErr("checks", err, "the root.json of %s cannot be written", l)
		}
		if err := CheckRootJSON(b, RootJSONWant{Label: l, Pin: m.pins[l], CreatedAt: p.Time, RemovalSHA256: removalSHA}); err != nil {
			return nil, err
		}
		made.Roots = append(made.Roots, MadeRoot{
			Label: l, Pin: m.pins[l], Place: m.born[i].Place, Certificate: certs[i], RemovalSHA256: removalSHA,
			RootJSONPath: rootJSONPath(l), RootJSON: b,
		})
	}
	// The journals are judged as the lines that the journals accepted, against the pins of the born
	// keys and against the signatures that the artifacts hold.
	births, signatures := m.tap.births.read(), m.tap.signatures.read()
	if err := CheckJournals(p, m.pins, births, signatures); err != nil {
		return nil, err
	}
	if err := CheckSignatureDigests(p, m.certs, m.removal, m.set, signatures); err != nil {
		return nil, err
	}
	// The record's root is the plan's root, with the X.509 fingerprint of the key that was born for
	// its label; a fingerprint that the plan gives is kept as it is, and must be that key's.
	root := *p.Plan.Root
	pin, ok := m.pins[root.Label]
	if !ok || (root.X509 != "" && root.X509 != pin) {
		return nil, makeErr("checks", nil, "the root of the plan names a key that was not born, or an X.509 fingerprint that is not the pin of the key born for %s", root.Label)
	}
	root.X509 = pin
	made.Record = root
	// The words are the checks that passed, in the fixed order of the list, whatever the order that
	// they ran in: the plan against the keys ran first.
	made.Checked = []string{CheckedRootCertificate, CheckedRemovalAuthorisation, CheckedRootList, CheckedCABundle, CheckedRootJSON, CheckedPlan, CheckedJournals}
	return made, nil
}
