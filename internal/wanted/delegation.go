package wanted

import (
	"errors"
	"strconv"

	"go.yaml.in/yaml/v3"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/pki"
)

// The types of a delegation, which are the types of a request ("What travels" in the hand-off contract).
const (
	// TypeX509Intermediate is an X.509 intermediate under an X.509 root.
	TypeX509Intermediate = "x509-intermediate"
	// TypeOpenPGPSubkey is an OpenPGP subkey under an OpenPGP root.
	TypeOpenPGPSubkey = "openpgp-subkey"
	// TypeSSHCAKey is an SSH CA key under an SSH CA root.
	TypeSSHCAKey = "ssh-ca-key"
)

// delegationMembers is the table of the members of a delegation file, in the order of docs/reference/bundle.md.
// Which of capability, use and the two lists is allowed depends on the type and is checked by the code.
var delegationMembers = []member{
	{name: "version", required: true},
	{name: "type", required: true, enum: typeEnum},
	{name: "root", required: true},
	{name: "capability", enum: capabilityEnum},
	{name: "use", enum: useEnum},
	{name: "permitted_uri_hosts"},
	{name: "permitted_dns_names"},
	{name: "kms_read_roles"},
	{name: "card"},
}

// Delegation is a delegation file as it was read: a declared name under a root, with its limits. Only
// [ParseDelegation] and [LoadDelegation] make a usable one: see [Delegation.Valid].
type Delegation struct {
	// File is the file as stored, with its bytes and digest.
	File File
	// Name is the name of the delegation, the file name without ".yaml".
	Name string
	// Type is x509-intermediate, openpgp-subkey or ssh-ca-key.
	Type string
	// Root is the name of the root the delegation is under.
	Root string
	// PermittedURIHosts are the URI constraints a request may hold (x509-intermediate), each a host or a
	// period and a host, in the form of the hand-off contract. None twice.
	PermittedURIHosts []string
	// PermittedDNSNames are the DNS names a request may hold (x509-intermediate), in the form of the
	// hand-off contract. None twice.
	PermittedDNSNames []string
	// Capability is sign or authenticate (openpgp-subkey), and empty for the other types.
	Capability string
	// Use is user or host (ssh-ca-key), and empty for the other types.
	Use string
	// Card is the name of the card file (want/cards/NAME.yaml) of the card that holds the subkey of an
	// openpgp-subkey delegation of a personal bundle: the one card and the one capability of the one key. It is
	// empty for every other delegation, which may not have the member.
	Card string
	// KMSReadRoles maps a 12-digit account id to the ARN of a role in that account. It may be empty, for any type.
	KMSReadRoles map[string]string

	made bool
}

// Valid reports whether d was made by [ParseDelegation] or [LoadDelegation]. It is false for a nil
// Delegation and for the zero value.
func (d *Delegation) Valid() bool { return d != nil && d.made }

// delegationPath is the path of the file of a delegation of a name that is valid.
func delegationPath(name string) string { return DelegationsDir + "/" + name + ".yaml" }

// rootKindOf is the kind of root that a type of delegation needs.
func rootKindOf(delegationType string) RootKind {
	switch delegationType {
	case TypeX509Intermediate:
		return RootX509
	case TypeOpenPGPSubkey:
		return RootOpenPGP
	default:
		return RootSSH
	}
}

// LoadDelegation reads want/delegations/NAME.yaml through package fsx, parses it with the settings of the
// bundle, and then reads the wanted root file that it names: the root must exist, pass its own check and
// be of the kind that the type needs. A file that does not exist gives an error that wraps fs.ErrNotExist.
func LoadDelegation(fsys fsx.FS, name string, s *Settings) (*Delegation, error) {
	if why := delegationNameProblem(name); why != "" {
		return nil, errorf(delegationPath(name), 0, why)
	}
	data, err := readFile(fsys, delegationPath(name))
	if err != nil {
		return nil, err
	}
	d, err := ParseDelegation(name, data, s)
	if err != nil {
		return nil, err
	}
	root, err := LoadRoot(fsys, d.Root)
	if err != nil {
		return nil, wrapRootFault(d, err)
	}
	if want := rootKindOf(d.Type); root.Kind != want {
		return nil, errorf(d.File.Path, 0, "the root "+d.Root+" is of the kind "+string(root.Kind)+", and a delegation of the type "+d.Type+" needs the kind "+string(want))
	}
	return d, nil
}

// wrapRootFault tells which delegation named the root whose file failed.
func wrapRootFault(d *Delegation, err error) error {
	var e *Error
	if errors.As(err, &e) {
		out := errorf(e.Path, e.Line, e.Msg+" (the root of the delegation "+d.Name+")")
		out.cause = e.cause
		return out
	}
	return err
}

// ParseDelegation reads the bytes of the delegation file NAME under the rules of the package and the shape of
// docs/reference/bundle.md, "A delegation file". The settings are needed for the rule that an x509-intermediate
// has a permitted name when the policy requires name constraints, so a Settings that is not [Settings.Valid]
// is an error. It reads no other file: [LoadDelegation] also reads the root.
func ParseDelegation(name string, data []byte, s *Settings) (*Delegation, error) {
	path := delegationPath(name)
	if why := delegationNameProblem(name); why != "" {
		return nil, errorf(path, 0, why)
	}
	if !s.Valid() {
		return nil, errorf(path, 0, "the settings of the bundle are needed to read a delegation, and these were not made by the reader")
	}
	d, err := read(path, data)
	if err != nil {
		return nil, err
	}
	top, err := d.mappingOf(d.root, "", delegationMembers)
	if err != nil {
		return nil, err
	}
	out := &Delegation{File: d.file, Name: name}
	if _, err := top.version(); err != nil {
		return nil, err
	}
	if out.Type, err = top.enumStr("type", typeEnum); err != nil {
		return nil, err
	}
	if out.Root, err = top.str("root"); err != nil {
		return nil, err
	}
	if rerr := ValidName(out.Root); rerr != nil {
		return nil, top.fail("root", "root: "+rerr.Error())
	}
	if err := out.takeByType(top, s); err != nil {
		return nil, err
	}
	if top.has("kms_read_roles") {
		if out.KMSReadRoles, err = top.roles(); err != nil {
			return nil, err
		}
	}
	out.made = true
	return out, nil
}

// takeByType reads the members that belong to the type, and refuses the members that do not.
func (out *Delegation) takeByType(top *mapping, s *Settings) error {
	forbid := func(names ...string) error {
		for _, n := range names {
			if top.has(n) {
				return top.fail(n, n+" is not a member of a delegation of the type "+out.Type)
			}
		}
		return nil
	}
	var err error
	switch out.Type {
	case TypeX509Intermediate:
		if err = forbid("capability", "use", "card"); err != nil {
			return err
		}
		if top.has("permitted_uri_hosts") {
			if out.PermittedURIHosts, err = top.hosts("permitted_uri_hosts", pki.ValidURIHost); err != nil {
				return err
			}
		}
		if top.has("permitted_dns_names") {
			if out.PermittedDNSNames, err = top.hosts("permitted_dns_names", pki.ValidDNSName); err != nil {
				return err
			}
		}
		if s.Policy.RequireNameConstraints && len(out.PermittedURIHosts)+len(out.PermittedDNSNames) == 0 {
			return top.d.fail(top.node, "an x509-intermediate delegation has an entry in permitted_uri_hosts or in permitted_dns_names, because the policy requires name constraints")
		}
	case TypeOpenPGPSubkey:
		if err = forbid("permitted_uri_hosts", "permitted_dns_names", "use"); err != nil {
			return err
		}
		if !top.has("capability") {
			return top.d.fail(top.node, "an openpgp-subkey delegation needs the member capability")
		}
		if out.Capability, err = top.enumStr("capability", capabilityEnum); err != nil {
			return err
		}
		return out.takeCard(top, s)
	default:
		if err = forbid("permitted_uri_hosts", "permitted_dns_names", "capability", "card"); err != nil {
			return err
		}
		if !top.has("use") {
			return top.d.fail(top.node, "an ssh-ca-key delegation needs the member use")
		}
		out.Use, err = top.enumStr("use", useEnum)
		return err
	}
	return nil
}

// takeCard reads the member card of an openpgp-subkey delegation: required in a personal bundle, which holds one
// key for one card and one capability, and refused in a company bundle.
func (out *Delegation) takeCard(top *mapping, s *Settings) error {
	if !s.Personal {
		if top.has("card") {
			return top.fail("card", "card is a member of an openpgp-subkey delegation of a personal bundle only")
		}
		return nil
	}
	if !top.has("card") {
		return top.d.fail(top.node, "an openpgp-subkey delegation of a personal bundle needs the member card: the name of the card file of the card that holds the key")
	}
	var err error
	if out.Card, err = top.str("card"); err != nil {
		return err
	}
	if rerr := ValidName(out.Card); rerr != nil {
		return top.fail("card", "card: "+rerr.Error())
	}
	return nil
}

// hosts reads a list of names, each in the form that valid accepts. The error names the list and the position
// of the entry, never the entry.
func (m *mapping) hosts(name string, valid func(string) bool) ([]string, error) {
	list, err := m.strings(name, 0, nil)
	if err != nil {
		return nil, err
	}
	for i, e := range list {
		if !valid(e) {
			return nil, m.d.fail(m.val[name].Content[i], name+" entry "+strconv.Itoa(i+1)+" is not a name in the form of the hand-off contract (lower-case labels of letters, digits and hyphens joined by periods, no wildcard, no period at the end)")
		}
	}
	return list, nil
}

// roles reads kms_read_roles: a mapping from a quoted 12-digit account id to the ARN of a role in that account.
func (m *mapping) roles() (map[string]string, error) {
	v := m.val["kms_read_roles"]
	if v.Kind != yaml.MappingNode {
		return nil, m.d.fail(v, "kms_read_roles must be a mapping from an account id to a role ARN")
	}
	out := map[string]string{}
	for i := 0; i+1 < len(v.Content); i += 2 {
		k, val := v.Content[i], v.Content[i+1]
		if !accountPattern.MatchString(k.Value) {
			return nil, m.d.fail(k, "an account id of kms_read_roles is 12 digits written in quotes")
		}
		if val.Tag != "!!str" {
			return nil, m.d.fail(val, "a role of kms_read_roles must be a string: the ARN of a role")
		}
		acct, ok := roleAccount(val.Value)
		if !ok {
			return nil, m.d.fail(val, "a role of kms_read_roles is a role ARN, such as arn:aws:iam::111122223333:role/example-certifier-read")
		}
		if acct != k.Value {
			return nil, m.d.fail(val, "a role of kms_read_roles is a role in the account it is listed under")
		}
		out[k.Value] = val.Value
	}
	return out, nil
}
