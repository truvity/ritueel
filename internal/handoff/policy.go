package handoff

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/pki"
)

// settings is the configuration of a checker, validated and copied once by [New] in the form that the rules
// use. Nothing in it is shared with the caller, and nothing in it changes after New.
type settings struct {
	stores      []Store
	minFirmware [3]uint32
	pinPolicies []PINPolicy
	delegation  Delegation
	roots       []preparedRoot
	verifiers   map[Store]EvidenceVerifier
	now         func() time.Time
}

// preparedRoot is a root of the bundle: its subject as DER and its key as the bytes of its point.
type preparedRoot struct {
	subject []byte
	point   []byte
}

// New makes a Checker from a configuration, or refuses it with an [ErrConfig]: a policy without stores, a
// minimum firmware or PIN policies (or with a store, a firmware or a PIN policy that is not one of the
// page's), no delegation (or one of a type that is not one of the page's), no roots (or roots that are
// not ECDSA P-384 keys with a name), no clock, or a verifier that is nil. Everything the Checker holds is a
// copy.
func New(cfg Config) (*Checker, error) {
	s := &settings{}
	if err := s.takePolicy(cfg.Policy); err != nil {
		return nil, err
	}
	if cfg.Delegation == nil {
		return nil, fmt.Errorf("%w: no delegation", ErrConfig)
	}
	switch cfg.Delegation.Type {
	case TypeX509, TypeOpenPGP, TypeSSH:
	default:
		return nil, fmt.Errorf("%w: the type of the delegation is not one of x509-intermediate, openpgp-subkey and ssh-ca-key", ErrConfig)
	}
	d := *cfg.Delegation
	d.PermittedURIHosts = slices.Clone(d.PermittedURIHosts)
	d.PermittedDNSNames = slices.Clone(d.PermittedDNSNames)
	d.KMSReadRoles = maps.Clone(d.KMSReadRoles)
	s.delegation = d
	if len(cfg.Roots) == 0 {
		return nil, fmt.Errorf("%w: no roots", ErrConfig)
	}
	for i, root := range cfg.Roots {
		key, ok := root.Key.(*ecdsa.PublicKey)
		if !ok || key == nil || key.Curve != elliptic.P384() {
			return nil, fmt.Errorf("%w: the key of root %d is not an ECDSA key on P-384", ErrConfig, i)
		}
		point, ok := pointOf(key)
		if !ok {
			return nil, fmt.Errorf("%w: the key of root %d is not a point of the curve", ErrConfig, i)
		}
		if same, err := pki.SameName(root.Subject, root.Subject); err != nil || !same {
			return nil, fmt.Errorf("%w: the subject of root %d is not a name", ErrConfig, i)
		}
		s.roots = append(s.roots, preparedRoot{subject: slices.Clone(root.Subject), point: point})
	}
	if cfg.Now == nil {
		return nil, fmt.Errorf("%w: no clock", ErrConfig)
	}
	s.now = cfg.Now
	s.verifiers = make(map[Store]EvidenceVerifier, len(cfg.Evidence))
	for store, verifier := range cfg.Evidence {
		if !knownStore(store) {
			return nil, fmt.Errorf("%w: a verifier for a store that is not one of piv, openpgp-card, aws-kms and software", ErrConfig)
		}
		if isNil(verifier) {
			return nil, fmt.Errorf("%w: the verifier of the store %s is nil", ErrConfig, store)
		}
		s.verifiers[store] = verifier
	}
	return &Checker{s: s}, nil
}

// takePolicy reads the policy: every field is required, and nothing that it lists is unknown.
func (s *settings) takePolicy(p Policy) error {
	if len(p.Stores) == 0 {
		return fmt.Errorf("%w: the policy allows no store", ErrConfig)
	}
	for _, st := range p.Stores {
		if !knownStore(st) {
			return fmt.Errorf("%w: the policy lists a store that is not one of piv, openpgp-card, aws-kms and software", ErrConfig)
		}
	}
	fw, ok := parseFirmware(p.MinFirmware)
	if !ok {
		return fmt.Errorf("%w: the minimum firmware is not three numbers separated by periods", ErrConfig)
	}
	if len(p.PINPolicies) == 0 {
		return fmt.Errorf("%w: the policy allows no PIN policy", ErrConfig)
	}
	for _, pp := range p.PINPolicies {
		if pp != PINNever && pp != PINOnce && pp != PINAlways {
			return fmt.Errorf("%w: the policy lists a PIN policy that is not one of never, once and always", ErrConfig)
		}
	}
	if p.ValidityMonths < 0 {
		return fmt.Errorf("%w: the validity is negative", ErrConfig)
	}
	s.stores = slices.Clone(p.Stores)
	s.minFirmware = fw
	s.pinPolicies = slices.Clone(p.PINPolicies)
	return nil
}

// knownStore reports whether s is one of the four stores of the page.
func knownStore(s Store) bool {
	switch s {
	case StorePIV, StoreOpenPGPCard, StoreKMS, StoreSoftware:
		return true
	}
	return false
}

// isNil reports whether v is nil, or holds a nil pointer, map, slice, function or channel.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface, reflect.UnsafePointer:
		return rv.IsNil()
	}
	return false
}

// parseFirmware reads "5.7.0": three numbers of decimal digits, separated by periods.
func parseFirmware(s string) ([3]uint32, bool) {
	var out [3]uint32
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, part := range parts {
		if part == "" || len(part) > 9 {
			return out, false
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return out, false
		}
		out[i] = uint32(n)
	}
	return out, true
}

// firmwareBefore reports whether a is older than b: the three numbers are compared as numbers, from the
// left ("5.10.0" is newer than "5.7.0").
func firmwareBefore(a, b [3]uint32) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// policyRules is the policy part of check 9 for an x509-intermediate whose content package pki has
// accepted: the rules of "Policy (check 9)" and "The request" that the request, the evidence and the
// checker's configuration decide. Every rule runs, and none can be left out: the first that refuses gives
// the detail, and an empty detail means every rule ran and passed.
func (s *settings) policyRules(req *pki.Request, p *Proof, ev *Evidence) string {
	// The delegation: a request whose type is not the delegation's type is refused.
	if s.delegation.Type != p.Type {
		return "the type of the request is not the type of the delegation"
	}
	// The evidence: firmware, PIN policy, the KMS key policy.
	if f := s.evidenceRules(p.Store, ev); f != "" {
		return f
	}
	// The name constraints are inside the lists of the delegation.
	if f := s.nameRules(req); f != "" {
		return f
	}
	// The key and the name of the request are not those of a root of the bundle.
	return s.rootRules(req)
}

// evidenceRules are the rules of check 9 that read the evidence: firmware, PIN policy and the policy of
// a KMS key. Touch policy and form factor are recorded and not enforced. A store that gives no value is
// held to the rule only where the page makes the value part of its evidence: a PIV key always has a
// firmware and a PIN policy (the attestation of "piv", check 7), so for that store an empty value is a
// fault of the evidence and refuses; an OpenPGP card gives none yet ("OpenPGP card" in the contract, and
// record 0003), and a KMS key has none, so for them an empty value is not held to the rule.
func (s *settings) evidenceRules(store Store, ev *Evidence) string {
	switch {
	case ev.Firmware != "":
		got, ok := parseFirmware(ev.Firmware)
		if !ok {
			return "the firmware in the evidence is not three numbers"
		}
		if firmwareBefore(got, s.minFirmware) {
			return "the firmware is older than the policy's minimum"
		}
	case store == StorePIV:
		return "the evidence of a PIV key holds no firmware"
	}
	switch {
	case ev.PINPolicy != "":
		if !slices.Contains(s.pinPolicies, ev.PINPolicy) {
			return "the PIN policy of the key is not one that the policy allows"
		}
	case store == StorePIV:
		return "the evidence of a PIV key holds no PIN policy"
	}
	if store == StoreKMS {
		return kmsRules(ev.SignPrincipals)
	}
	return ""
}

// kmsRules is the rule for a KMS key: every statement that allows kms:Sign names the same single
// principal, a role or a user, and there is at least one. The principals are counted by the pair of their
// ARN and their kind, so a principal that is listed twice is one, and one that is listed with two kinds
// is two.
func kmsRules(list []Principal) string {
	var distinct []Principal
	for _, pr := range list {
		if !slices.Contains(distinct, pr) {
			distinct = append(distinct, pr)
		}
	}
	switch {
	case len(distinct) == 0:
		return "no statement of the key policy allows kms:Sign"
	case len(distinct) > 1:
		return "the key policy allows kms:Sign to more than one principal"
	}
	if k := distinct[0].Kind; k != PrincipalRole && k != PrincipalUser {
		return "the principal that may use kms:Sign is not a role or a user"
	}
	return ""
}

// nameRules holds every permitted subtree of the request's name constraints to the delegation's lists:
// a permitted URI constraint is inside only when it equals an entry of PermittedURIHosts, and a
// permitted DNS name only when it equals an entry of PermittedDNSNames. A host with a period at its start
// is an entry of its own; a subdomain of an entry is not inside it. There must be at least one permitted
// subtree.
func (s *settings) nameRules(req *pki.Request) string {
	nc := req.NameConstraints()
	if len(nc.PermittedURI)+len(nc.PermittedDNS) == 0 {
		return "the name constraints have no permitted subtree"
	}
	for _, host := range nc.PermittedURI {
		if !slices.Contains(s.delegation.PermittedURIHosts, host) {
			return "a permitted URI constraint is not an entry of the delegation: " + jsonset.Escape(host)
		}
	}
	for _, name := range nc.PermittedDNS {
		if !slices.Contains(s.delegation.PermittedDNSNames, name) {
			return "a permitted DNS name is not an entry of the delegation: " + jsonset.Escape(name)
		}
	}
	return ""
}

// rootRules is the rule that the key of the request is not the key of any root of the bundle, and its
// subject is not the name of any root as OpenSSL compares names ("The request").
func (s *settings) rootRules(req *pki.Request) string {
	key, ok := pointOf(req.PublicKey())
	if !ok {
		return "the key of the request cannot be written"
	}
	subject := req.Subject()
	for _, root := range s.roots {
		if bytes.Equal(key, root.point) {
			return "the key of the request is the key of a root of the bundle"
		}
		same, err := pki.SameName(subject, root.subject)
		if err != nil || same {
			return "the subject of the request is the name of a root of the bundle"
		}
	}
	return ""
}
