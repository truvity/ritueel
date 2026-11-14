package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/wanted"
)

// The folders of a bundle that this package reads (record 0006, rule 37).
const (
	// RequestsDir is the folder of the requests, one folder for each stem.
	RequestsDir = "requests"
	// TrustDir is the folder of the trust sets.
	TrustDir = "trust"
)

// ErrNoSettings is wrapped by the error of [Open] for a folder that holds no ritueel.yaml: it is not a
// bundle on a workstation (the copy on a stick has no wanted files, record 0005, rule 30).
var ErrNoSettings = errors.New("bundle: no ritueel.yaml: this is not a bundle on a workstation")

// ErrNoTrustSet is wrapped by the error of [Bundle.Roots] for a bundle with no trust set: the first apply makes one.
var ErrNoTrustSet = errors.New("bundle: the bundle has no trust set yet; the first apply makes one")

// ErrBundle is returned by every call on a nil, closed or hand-made Bundle: only [Open] makes a usable one.
var ErrBundle = errors.New("bundle: not a bundle that Open made")

// Bundle is an opened bundle folder with its settings. Only [Open] makes a usable one, and a zero Bundle
// refuses every call with [ErrBundle].
type Bundle struct {
	fsys     fsx.FS
	settings *wanted.Settings
}

// Open opens the folder dir without following a link as its last element, and reads ritueel.yaml in it. A folder
// with no ritueel.yaml gives an error that wraps [ErrNoSettings], and a ritueel.yaml that fails the strict reader
// gives its error. Nothing else of the folder is read. The caller closes the Bundle.
func Open(dir string) (*Bundle, error) {
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		return nil, err
	}
	s, err := wanted.LoadSettings(fsys)
	if err != nil {
		_ = fsys.Close()
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", ErrNoSettings, err)
		}
		return nil, err
	}
	return &Bundle{fsys: fsys, settings: s}, nil
}

// usable reports whether b is a Bundle that Open made, with settings that the strict reader made.
func (b *Bundle) usable() error {
	if b == nil || b.fsys == nil || !b.settings.Valid() {
		return ErrBundle
	}
	return nil
}

// Close releases the folder. It is safe on a nil Bundle and on a second call.
func (b *Bundle) Close() error {
	if b == nil || b.fsys == nil {
		return nil
	}
	err := b.fsys.Close()
	b.fsys = nil
	return err
}

// Settings returns the settings that Open read, or nil for a Bundle that Open did not make. The value is shared
// with the Bundle, and the caller changes nothing in it.
func (b *Bundle) Settings() *wanted.Settings {
	if b == nil {
		return nil
	}
	return b.settings
}

// Request loads the files of requests/STEM: the proof file and the files of the request, by suffix, without
// following a link. A stem that is not a stem of the contract, a missing proof file and an unreadable file
// are the errors of [handoff.LoadRequest]. Answer files are not read.
func (b *Bundle) Request(stem string) (*handoff.Request, error) {
	if err := b.usable(); err != nil {
		return nil, err
	}
	if !handoff.ValidStem(stem) {
		return nil, fmt.Errorf("%w: the stem is not 1 to 63 lower-case letters, digits and hyphens, starting with a letter or a digit", handoff.ErrLoad)
	}
	return handoff.LoadRequest(b.fsys, RequestsDir+"/"+stem, stem)
}

// Checker makes the [handoff.Checker] of the bundle: the policy of ritueel.yaml, the roots of the newest trust
// set ([Bundle.Roots]) and the delegation named. A name of "" is no delegation: the checker then does not run
// the rules that belong to one, and says so in its verdict. A name is read from want/delegations with the
// wanted root file that it names, which must exist and be of the kind its type needs. The evidence verifiers
// and the clock are the caller's; no OpenPGP primaries are set. It returns the delegation too (nil for none).
// It reads no other wanted file.
func (b *Bundle) Checker(name string, now func() time.Time, evidence map[handoff.Store]handoff.EvidenceVerifier) (*handoff.Checker, *wanted.Delegation, error) {
	if err := b.usable(); err != nil {
		return nil, nil, err
	}
	var d *wanted.Delegation
	if name != "" {
		var err error
		if d, err = wanted.LoadDelegation(b.fsys, name, b.settings); err != nil {
			return nil, nil, err
		}
	}
	roots, _, err := b.Roots()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := configOf(b.settings, d, roots, now, evidence)
	if err != nil {
		return nil, nil, err
	}
	c, err := handoff.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	return c, d, nil
}

// configOf maps the wanted files to the configuration of the checks: the fields of the policy go over
// unchanged, and so does everything of the delegation that the checks read. A settings or a delegation that
// its parser did not make is refused. d may be nil.
func configOf(s *wanted.Settings, d *wanted.Delegation, roots []handoff.RootRef, now func() time.Time, evidence map[handoff.Store]handoff.EvidenceVerifier) (handoff.Config, error) {
	if !s.Valid() {
		return handoff.Config{}, errors.New("bundle: the settings were not made by the reader of ritueel.yaml")
	}
	if d != nil && !d.Valid() {
		return handoff.Config{}, errors.New("bundle: the delegation was not made by the reader of a delegation file")
	}
	cfg := handoff.Config{
		Policy: handoff.Policy{
			MinFirmware:    s.Policy.MinFirmware,
			ValidityMonths: s.Policy.ValidityMonths,
		},
		Roots:    roots,
		Evidence: evidence,
		Now:      now,
	}
	for _, st := range s.Policy.Stores {
		cfg.Policy.Stores = append(cfg.Policy.Stores, handoff.Store(st))
	}
	for _, p := range s.Policy.PINPolicy {
		cfg.Policy.PINPolicies = append(cfg.Policy.PINPolicies, handoff.PINPolicy(p))
	}
	if d != nil {
		hd := &handoff.Delegation{
			Name:       d.Name,
			Type:       handoff.Type(d.Type),
			Root:       d.Root,
			Capability: d.Capability,
			Use:        d.Use,
		}
		hd.PermittedURIHosts = append(hd.PermittedURIHosts, d.PermittedURIHosts...)
		hd.PermittedDNSNames = append(hd.PermittedDNSNames, d.PermittedDNSNames...)
		if d.KMSReadRoles != nil {
			hd.KMSReadRoles = make(map[string]string, len(d.KMSReadRoles))
			for k, v := range d.KMSReadRoles {
				hd.KMSReadRoles[k] = v
			}
		}
		cfg.Delegation = hd
	}
	return cfg, nil
}
