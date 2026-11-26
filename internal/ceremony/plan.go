package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/trustset"
	"ritueel.id/ritueel/internal/wanted"
)

// The values of the plan of the first apply (docs/reference/ceremony-record.md, "The plan").
const (
	// storeSoftware is the key store of a software test root.
	storeSoftware = "software"
	// purposeX509Root is the purpose of the birth of an X.509 root key (Proposed on the page).
	purposeX509Root = "x509-root"
	// kindRootCertificate, kindRootRemoval and kindRootList are the kinds of the signatures of the
	// first apply (the page lists them).
	kindRootCertificate = "root-certificate"
	kindRootRemoval     = "root-removal"
	kindRootList        = "root-list"
	// rootValidityMonths is the validity of a root certificate: 36 calendar months (docs/reference/
	// bundle.md, "The root certificate").
	rootValidityMonths = 36
	// firstTrustSequence is the trust sequence of the first trust set: the base sequence (none, 0)
	// plus one (record 0006, rule 14).
	firstTrustSequence = 1
	// maxKeys is the most keys one plan makes: the most root keys that one list holds.
	maxKeys = trustset.MaxRoots
	// legacyKeyFileSuffix ended the place of an X.509 key in the plans that earlier versions of ritueel made,
	// after its label: the place was the name of a key file. It is read only to say that such a plan is old.
	legacyKeyFileSuffix = ".x509.key.pem"
	// maxVersionBytes is the most bytes of the version of the program in a plan.
	maxVersionBytes = 128
)

// PlanBirth is one key to be born, as the member births of the plan lists it: the label, the
// purpose, the key store and the place. The place of a key is the purpose that names it in the key port,
// x509-root- and the label in lower case, the same for every store and never a path. An X.509 key has
// no creation time, so the page's fifth member is left out (Proposed).
type PlanBirth struct {
	Label   string `json:"label"`
	Purpose string `json:"purpose"`
	Store   string `json:"store"`
	Place   string `json:"place"`
}

// PlanSignature is one signature of the plan, as the member signatures lists it. Every signature of
// the first apply covers a key born in the ceremony, so each has Derived true, no key and no digest of
// the bytes to sign: they cannot be fixed before the key exists (docs/reference/ceremony-record.md, "A
// key that is born in the ceremony is the exception"). The serial and the two times are for a
// certificate only.
type PlanSignature struct {
	N         int64  `json:"n"`
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	Serial    string `json:"serial,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	Derived   bool   `json:"derived,omitempty"`
}

// planDoc is the plan of the first apply as a typed value: exactly the members that [MakePlan] writes
// and [ReadPlanOut] accepts, no others. It is the one typed reading of the file.
type planDoc struct {
	Version       int64              `json:"version"`
	Ceremony      string             `json:"ceremony"`
	Command       string             `json:"command"`
	MadeAt        string             `json:"made_at"`
	Ritueel       *buildinfo.Program `json:"ritueel"`
	CeremonyTime  string             `json:"ceremony_time"`
	Wanted        []files.FileRef    `json:"wanted"`
	Applies       []Change           `json:"applies"`
	LeavesOut     []LeftOut          `json:"leaves_out,omitempty"`
	Root          *files.PlanRoot    `json:"root"`
	Signatures    []PlanSignature    `json:"signatures"`
	Births        []PlanBirth        `json:"births"`
	TrustSequence int64              `json:"trust_sequence"`
}

// PlanOut is a plan, its bytes and its digest, and the typed values that the words and the run use.
// The bytes are the canonical form of RFC 8785 with no trailing newline; the digest is the SHA-256 of
// the bytes. The typed values come from one reading of the bytes ([ReadPlanOut]), so what a person
// confirms and what the run executes are one thing. A zero PlanOut holds nothing and has no words.
type PlanOut struct {
	// Name is the name of the ceremony: its time and the command, 20261120T100000Z-apply.
	Name string
	// Plan is the plan as the strict reader of the files package reads it.
	Plan *files.Plan
	// JSON is the bytes of plan.json.
	JSON []byte
	// SHA256 is the plan digest: 64 lower-case hexadecimal digits.
	SHA256 string
	// Prefix is the first eight characters of SHA256, which a person types to confirm.
	Prefix string
	// Time is the ceremony time: whole seconds, UTC.
	Time time.Time
	// Program is the copy of ritueel that made the plan.
	Program buildinfo.Program
	// RootName is the name of the wanted root file, without ".yaml".
	RootName string
	// Wanted are the wanted files that the plan used, in path order, with their digests.
	Wanted []files.FileRef
	// Applies are the changes the plan applies, in order.
	Applies []Change
	// LeavesOut are the changes the plan leaves out, with the reason.
	LeavesOut []LeftOut
	// Births are the keys to be born, in the order of their labels.
	Births []PlanBirth
	// Signatures are the signatures of the ceremony, in the order of n.
	Signatures []PlanSignature
}

// MakePlan builds the plan of a Found for the first apply: it reads the clock once, asks the program
// for its description, draws the serials from Env.Rand, writes the plan in the canonical form, and
// reads it back with [ReadPlanOut], which is the reader that the run uses. The plan holds public
// information only and needs no key. A zero or invalid Found, a nil clock, a program that cannot be
// described and a source of serials that fails are errors, and no plan is returned with an error. It
// writes nothing.
//
// The plan has no last_record_sha256, no base_sequence, no touches and no inputs: the first apply
// has no history, and a software key has no touch. The first list is signed by the key with the
// lowest label.
func MakePlan(f *Found, env Env) (*PlanOut, error) {
	labels, err := checkFound(f)
	if err != nil {
		return nil, err
	}
	t, err := env.now()
	if err != nil {
		return nil, err
	}
	program, err := env.program()
	if err != nil {
		return nil, fmt.Errorf("the digest of the program cannot be computed, so no plan is made: %w", err)
	}
	notAfter, err := pki.AddMonths(t, rootValidityMonths)
	if err != nil {
		return nil, fmt.Errorf("the end of the validity of a root certificate cannot be computed: %w", err)
	}
	doc := &planDoc{
		Version:       files.FormatVersion,
		Ceremony:      ceremonyName(t),
		Command:       files.CommandApply,
		MadeAt:        timeText(t),
		Ritueel:       &program,
		CeremonyTime:  timeText(t),
		Applies:       slices.Clone(f.Applies),
		LeavesOut:     slices.Clone(f.LeavesOut),
		Root:          &files.PlanRoot{Label: labels[0], Store: storeSoftware, Test: true, Copyable: true},
		TrustSequence: firstTrustSequence,
	}
	for _, w := range f.Wanted {
		doc.Wanted = append(doc.Wanted, files.FileRef{Path: w.Path, SHA256: files.Digest(w.Data)})
	}
	slices.SortFunc(doc.Wanted, func(a, b files.FileRef) int { return strings.Compare(a.Path, b.Path) })
	var n int64
	seen := make(map[string]bool, len(labels))
	for _, l := range labels {
		serial, err := pki.NewSerial(env.Rand)
		if err != nil {
			return nil, fmt.Errorf("a serial number for the root certificate %s cannot be drawn: %w", l, err)
		}
		text := serial.Text(16)
		if seen[text] {
			return nil, errors.New("the source of random numbers gave one serial number twice, so no plan is made")
		}
		seen[text] = true
		doc.Births = append(doc.Births, PlanBirth{Label: l, Purpose: purposeX509Root, Store: storeSoftware, Place: purposeOf(l)})
		doc.Signatures = append(doc.Signatures,
			PlanSignature{N: n + 1, Kind: kindRootCertificate, Subject: l, Serial: text, NotBefore: timeText(t), NotAfter: timeText(notAfter), Derived: true},
			PlanSignature{N: n + 2, Kind: kindRootRemoval, Subject: l, Derived: true},
		)
		n += 2
	}
	doc.Signatures = append(doc.Signatures, PlanSignature{N: n + 1, Kind: kindRootList, Subject: labels[0], Derived: true})
	b, err := canonjson.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("the plan cannot be written: %w", err)
	}
	return ReadPlanOut(b)
}

// checkFound judges the Found that MakePlan is given and returns the labels of the keys, in order.
// A Found that Find did not make, or that holds more or less than the first apply of a test root, is
// refused: the plan is built from nothing that was not checked.
func checkFound(f *Found) ([]string, error) {
	if f.Nothing() {
		return nil, errors.New("there is nothing to apply, so there is no plan")
	}
	if !f.Settings.Valid() || !f.Root.Valid() {
		return nil, errors.New("the wanted files were not read by their readers, so no plan is made")
	}
	if f.Root.Kind != wanted.RootX509 || !f.Root.Test || f.Settings.Personal {
		return nil, fmt.Errorf("%w: the plan of this version is for one X.509 test root of a company bundle", ErrNotBuilt)
	}
	if len(f.Applies) > maxKeys {
		return nil, fmt.Errorf("a plan makes at most %d keys, and %d were found", maxKeys, len(f.Applies))
	}
	labels := make([]string, len(f.Applies))
	for i, c := range f.Applies {
		labels[i] = labelOf(i)
		if c.Change != changeCreate || c.Object != f.Root.Name+"/"+labels[i] {
			return nil, errors.New("a change is not the creation of the next key of the root, so no plan is made")
		}
	}
	if len(f.Wanted) != 2 {
		return nil, errors.New("the plan uses ritueel.yaml and the root file, and the wanted files are not those two")
	}
	// The plan lists the digests of the bytes of Found.Wanted, so those bytes must be the bytes that
	// Settings and Root hold, not only files of the same paths: one file of each, no other.
	haveSettings, haveRoot := false, false
	for _, w := range f.Wanted {
		switch {
		case w.Path == f.Settings.File.Path && !haveSettings && bytes.Equal(w.Data, f.Settings.File.Data):
			haveSettings = true
		case w.Path == f.Root.File.Path && !haveRoot && bytes.Equal(w.Data, f.Root.File.Data):
			haveRoot = true
		default:
			return nil, errors.New("the wanted files of the plan are not the bytes of ritueel.yaml and of the root file that were read")
		}
	}
	if !haveSettings || !haveRoot {
		return nil, errors.New("the wanted files of the plan are not the bytes of ritueel.yaml and of the root file that were read")
	}
	for _, w := range f.Wanted {
		if err := files.CheckPath(w.Path); err != nil {
			return nil, fmt.Errorf("the wanted path %s %w", jsonset.EscapeExact(w.Path), err)
		}
	}
	return labels, nil
}

// ReadPlanOut is the one way a saved plan is taken: it reads the bytes with files.ReadPlan, then reads
// the whole file again into the typed values of this package by a strict reader that accepts exactly
// the shape [MakePlan] writes, writes the typed value again in the canonical form and requires the same
// bytes. So the words that a person confirms and the values that the run executes come from one typed
// value of one reading of the file. A member that is missing, twice, of another type, in another order
// or extra, a label out of the order of the next free letters, a serial that is not of the form of
// pki.NewSerial, a not_after that is not 36 calendar months after not_before, a signature that is not
// derived or that has a tbs_sha256 or a key, a name of the ceremony that is not its time and the
// command, and a file that is not canonical are errors. An error returns no PlanOut. The bytes are
// copied.
func ReadPlanOut(b []byte) (*PlanOut, error) {
	if len(b) == 0 || len(b) > strictjson.DefaultMaxBytes {
		return nil, fmt.Errorf("the plan is empty or longer than %d bytes", strictjson.DefaultMaxBytes)
	}
	own := bytes.Clone(b)
	fp, err := files.ReadPlan(own)
	if err != nil {
		return nil, fmt.Errorf("the plan is refused by its reader: %w", err)
	}
	ok, err := canonjson.IsCanonical(own)
	if err != nil || !ok {
		return nil, errors.New("the plan is not in the canonical form of RFC 8785")
	}
	var doc planDoc
	if err := strictjson.Unmarshal(own, &doc, strictjson.Options{MaxBytes: strictjson.DefaultMaxBytes}); err != nil {
		return nil, fmt.Errorf("the plan has a member that this version does not make, or a member of the wrong form: %w", err)
	}
	out, err := doc.check()
	if err != nil {
		return nil, err
	}
	again, err := canonjson.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("the plan cannot be written again: %w", err)
	}
	if !bytes.Equal(again, own) {
		return nil, errors.New("the plan is not the plan that this version writes for what it holds")
	}
	sum := files.Digest(own)
	out.Plan = fp
	out.JSON = own
	out.SHA256 = sum
	out.Prefix = sum[:8]
	return out, nil
}

// check judges the typed plan against the shape of the first apply and returns the PlanOut without the
// bytes and the digest.
func (d *planDoc) check() (*PlanOut, error) {
	bad := func(format string, args ...any) (*PlanOut, error) {
		return nil, fmt.Errorf("the plan is not the plan of a first apply: "+format, args...)
	}
	if d.Version != files.FormatVersion || d.Command != files.CommandApply || d.TrustSequence != firstTrustSequence {
		return bad("version, command or trust_sequence")
	}
	if d.Ritueel == nil || d.Root == nil {
		return bad("a member is missing")
	}
	if d.MadeAt != d.CeremonyTime {
		return bad("made_at and ceremony_time are not one instant")
	}
	if err := files.CheckTime(d.CeremonyTime); err != nil {
		return bad("ceremony_time %s", err)
	}
	t, err := time.Parse(time.RFC3339, d.CeremonyTime)
	if err != nil || t.Year() < 1 {
		return bad("ceremony_time is not a time of the years 1 to 9999")
	}
	t = t.UTC()
	if d.Ceremony != ceremonyName(t) {
		return bad("ceremony is not the time of the ceremony and the command")
	}
	if err := checkProgram(*d.Ritueel); err != nil {
		return bad("ritueel: %v", err)
	}
	notAfter, err := pki.AddMonths(t, rootValidityMonths)
	if err != nil {
		return bad("the end of the validity is outside the years 1 to 9999")
	}
	rootName, err := d.checkWanted()
	if err != nil {
		return nil, err
	}
	labels, err := d.checkKeys(rootName)
	if err != nil {
		return nil, err
	}
	if *d.Root != (files.PlanRoot{Label: labels[0], Store: storeSoftware, Test: true, Copyable: true}) {
		return bad("root is not the first key, a software key of a test root that can be copied, with no fingerprint yet")
	}
	if err := d.checkSignatures(labels, t, notAfter); err != nil {
		return nil, err
	}
	if err := d.checkLeavesOut(); err != nil {
		return nil, err
	}
	return &PlanOut{
		Name:       d.Ceremony,
		Time:       t,
		Program:    *d.Ritueel,
		RootName:   rootName,
		Wanted:     slices.Clone(d.Wanted),
		Applies:    slices.Clone(d.Applies),
		LeavesOut:  slices.Clone(d.LeavesOut),
		Births:     slices.Clone(d.Births),
		Signatures: slices.Clone(d.Signatures),
	}, nil
}

// checkProgram judges the member ritueel: a version of plain characters, a system and architecture
// and a digest.
func checkProgram(p buildinfo.Program) error {
	if p.Version == "" || len(p.Version) > maxVersionBytes {
		return errors.New("the version is empty or too long")
	}
	for i := 0; i < len(p.Version); i++ {
		c := p.Version[i]
		plain := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-' || c == '_' || c == '+'
		if !plain {
			return errors.New("the version has a character beyond letters, digits and . - _ +")
		}
	}
	system, arch, ok := strings.Cut(p.OSArch, "/")
	if !ok || !lowerWord(system) || !lowerWord(arch) {
		return errors.New("os_arch is not <system>/<architecture>")
	}
	if !files.IsDigest(p.SHA256) {
		return errors.New("sha256 is not a SHA-256 digest")
	}
	return nil
}

// lowerWord reports whether s is 1 to 32 lower-case letters and digits.
func lowerWord(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// checkWanted judges the list of wanted files and returns the name of the root file: ritueel.yaml
// and want/roots/NAME.yaml, in path order, each with a digest.
func (d *planDoc) checkWanted() (string, error) {
	if len(d.Wanted) != 2 || d.Wanted[0].Path != wanted.SettingsPath {
		return "", errors.New("the plan is not the plan of a first apply: wanted lists ritueel.yaml and the root file, in path order")
	}
	name, ok := strings.CutPrefix(d.Wanted[1].Path, wanted.RootsDir+"/")
	if ok {
		name, ok = strings.CutSuffix(name, ".yaml")
	}
	if !ok || wanted.ValidName(name) != nil {
		return "", errors.New("the plan is not the plan of a first apply: the second wanted file is not want/roots/NAME.yaml")
	}
	return name, nil
}

// checkKeys judges applies and births against the name of the root file and returns the labels: the
// next free letters from A, one key each, 1 to the most keys of a list.
func (d *planDoc) checkKeys(rootName string) ([]string, error) {
	n := len(d.Applies)
	if n < 1 || n > maxKeys || len(d.Births) != n {
		return nil, fmt.Errorf("the plan is not the plan of a first apply: it makes from 1 to %d keys, and applies and births list the same ones", maxKeys)
	}
	labels := make([]string, n)
	for i := range n {
		l := labelOf(i)
		labels[i] = l
		if d.Applies[i] != (Change{Change: changeCreate, Object: rootName + "/" + l}) {
			return nil, errors.New("the plan is not the plan of a first apply: applies is not the creation of the keys A, B, ... of the root, in order")
		}
		if d.Births[i] != (PlanBirth{Label: l, Purpose: purposeX509Root, Store: storeSoftware, Place: purposeOf(l)}) {
			if d.Births[i] == (PlanBirth{Label: l, Purpose: purposeX509Root, Store: storeSoftware, Place: l + legacyKeyFileSuffix}) {
				return nil, errors.New("the plan is not the plan of a first apply of this version: it names each key by the name of a key file, as an earlier ritueel did, and this version names it by its purpose, " +
					purposeOf(l) + "; make the plan again with apply --plan-only, and nothing was written")
			}
			return nil, errors.New("the plan is not the plan of a first apply: births is not the keys A, B, ... in a software store, in order")
		}
	}
	return labels, nil
}

// checkSignatures judges the list of signatures: for each label in order a root certificate and a
// removal authorisation, then one root list signed by the first key; each derived, with no key and no
// digest of the bytes; a serial that fits the profile, once; the validity of 36 calendar months.
func (d *planDoc) checkSignatures(labels []string, t, notAfter time.Time) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("the plan is not the plan of a first apply: signatures: "+format, args...)
	}
	if len(d.Signatures) != 2*len(labels)+1 {
		return bad("there are %d for %d keys, and the plan has two for each and one for the list", len(d.Signatures), len(labels))
	}
	serials := make(map[string]bool, len(labels))
	at := 0 // the index of the signature being judged; its n is at+1
	take := func() (PlanSignature, int64) {
		s := d.Signatures[at]
		at++
		return s, int64(at)
	}
	for _, l := range labels {
		cert, n := take()
		serial, ok := new(big.Int).SetString(cert.Serial, 16)
		if !ok || serial.Text(16) != cert.Serial || pki.CheckSerial(serial) != nil {
			return bad("the serial of the certificate %s is not a serial of the profile in lower-case hexadecimal", l)
		}
		if serials[cert.Serial] {
			return bad("two certificates have one serial")
		}
		serials[cert.Serial] = true
		if cert != (PlanSignature{N: n, Kind: kindRootCertificate, Subject: l, Serial: cert.Serial, NotBefore: timeText(t), NotAfter: timeText(notAfter), Derived: true}) {
			return bad("the certificate of %s is not made at the ceremony time for 36 calendar months, derived", l)
		}
		removal, n := take()
		if removal != (PlanSignature{N: n, Kind: kindRootRemoval, Subject: l, Derived: true}) {
			return bad("the removal authorisation of %s is not the second signature of the key, derived", l)
		}
	}
	list, n := take()
	if list != (PlanSignature{N: n, Kind: kindRootList, Subject: labels[0], Derived: true}) {
		return bad("the last is not the root list, signed by the first key, derived")
	}
	return nil
}

// checkLeavesOut judges leaves_out: one entry for each request, in the order of the names, with the
// one reason of the first apply.
func (d *planDoc) checkLeavesOut() error {
	if len(d.LeavesOut) > maxRequestNames {
		return fmt.Errorf("the plan is not the plan of a first apply: leaves_out lists more than %d requests", maxRequestNames)
	}
	prev := ""
	for i, l := range d.LeavesOut {
		name, ok := strings.CutPrefix(l.Object, "requests/")
		if !ok || fsx.CheckName(name) != nil || l.Reason != leftOutReason {
			return fmt.Errorf("the plan is not the plan of a first apply: leaves_out[%d] is not a request with the reason of the first apply", i)
		}
		if i > 0 && name <= prev {
			return errors.New("the plan is not the plan of a first apply: leaves_out is not in the order of the names")
		}
		prev = name
	}
	return nil
}
