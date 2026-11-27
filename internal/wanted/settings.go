package wanted

import (
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
	"ritueel.id/ritueel/internal/fsx"
)

// The path of ritueel.yaml and the folders of the wanted files in a bundle, with "/" as the separator.
const (
	// SettingsPath is the path of ritueel.yaml, the settings of a bundle.
	SettingsPath = "ritueel.yaml"
	// RootsDir is the folder of the wanted root files, one NAME.yaml for each root.
	RootsDir = "want/roots"
	// DelegationsDir is the folder of the delegation files, one NAME.yaml for each delegation.
	DelegationsDir = "want/delegations"
	// CardsDir is the folder of the wanted card files, one NAME.yaml for each card.
	CardsDir = "want/cards"
)

// Version is the one version of every wanted file: each has "version: 1".
const Version = 1

// MaxNameLen is the longest "name" of ritueel.yaml: 45 characters, so that the common name of a root key
// (the name, " Root " and the label, and " (TEST ONLY)" for a test root) stays within the 64 characters
// of RFC 5280.
const MaxNameLen = 45

// MaxFiles is the most entries of want/roots, want/delegations or want/cards that the listers of this
// package accept, not counting leftover temporary names, which they skip (record 0006, rule 45): a
// folder with more is an error.
const MaxFiles = 1000

// The tables of members of ritueel.yaml, in the order of docs/reference/bundle.md.
var (
	settingsMembers = []member{
		{name: "version", required: true},
		{name: "kind", enum: kindEnum},
		{name: "person"},
		{name: "name"},
		{name: "release_address"},
		{name: "policy", required: true},
		{name: "keyring"},
		{name: "aws_kms"},
	}
	personMembers = []member{
		{name: "name", required: true},
		{name: "address", required: true},
	}
	policyMembers = []member{
		{name: "stores", required: true, enum: storeEnum},
		{name: "min_firmware", required: true},
		{name: "pin_policy", required: true, enum: pinPolicyEnum},
		{name: "require_name_constraints", required: true},
		{name: "validity_months", required: true},
	}
	keyringMembers = []member{
		{name: "license"},
	}
	awsKMSMembers = []member{
		{name: "account", required: true},
		{name: "region", required: true},
		{name: "replica_region", required: true},
		{name: "admin_role", required: true},
		{name: "ceremony_role", required: true},
	}
)

// Policy is the policy block of ritueel.yaml: the rules every request is checked against (the reference
// policy of the hand-off contract). All five members are there in a Settings that a parser made.
type Policy struct {
	// Stores are the key stores the policy allows: piv, openpgp-card, aws-kms and software. At least one, none twice.
	Stores []string
	// MinFirmware is the oldest firmware of a YubiKey that is accepted: three numbers of up to nine digits,
	// joined by periods.
	MinFirmware string
	// PINPolicy are the PIN policies that are allowed: never, once and always. At least one, none twice.
	PINPolicy []string
	// RequireNameConstraints is always true: a policy cannot switch the rule off.
	RequireNameConstraints bool
	// ValidityMonths is the validity that the certifier gives what it issues, at least 1.
	ValidityMonths int
}

// The example person that the starter of a personal bundle holds. A personal bundle that still has it is
// refused by name: a person who writes only a real fingerprint would ask for this name and address on a real key.
const (
	ExamplePersonName    = "Ada Example"
	ExamplePersonAddress = "ada@example.com"
)

// Person is the person of a personal bundle.
type Person struct {
	// Name is 1 to 64 characters of ASCII letters, digits, spaces, periods, apostrophes and hyphens, starting
	// with a letter or a digit, with no space at the end and no two spaces in a row.
	Name string
	// Address is one bare e-mail address in printable ASCII.
	Address string
}

// KMS is the aws_kms block of ritueel.yaml: the account, the two Regions and the two roles of the KMS root
// key store. Nothing reads it in this version; it is checked so that a later reader reads a checked value.
type KMS struct {
	// Account is the 12-digit account id of the root account.
	Account string
	// Region and ReplicaRegion are two different Regions.
	Region, ReplicaRegion string
	// AdminRole and CeremonyRole are role ARNs in Account.
	AdminRole, CeremonyRole string
}

// Settings is ritueel.yaml as it was read. Only [ParseSettings] and [LoadSettings] make a usable one: see
// [Settings.Valid].
type Settings struct {
	// File is the file as stored, with its bytes and digest.
	File File
	// Version is 1.
	Version int
	// Personal is true for a personal bundle (kind: personal), which has Person and neither Name nor
	// ReleaseAddress.
	Personal bool
	// Name is the name of a company bundle, which is in its root keys' names: 1 to [MaxNameLen] ASCII letters,
	// digits, single spaces and hyphens, with no space at the start or the end. Empty for a personal bundle.
	Name string
	// ReleaseAddress is the release address of a company bundle: one bare address in printable ASCII. Empty
	// for a personal bundle.
	ReleaseAddress string
	// Person is the person of a personal bundle, and nil for a company bundle.
	Person *Person
	// Policy is the policy block.
	Policy Policy
	// KeyringLicense is keyring.license, or empty when the member is not there. Nothing reads it yet.
	KeyringLicense string
	// KMS is the aws_kms block, or nil when it is not there.
	KMS *KMS

	made bool
}

// Valid reports whether s was made by [ParseSettings] or [LoadSettings]. It is false for a nil Settings and
// for the zero value, and a package that takes a Settings refuses one that is not Valid.
func (s *Settings) Valid() bool { return s != nil && s.made }

// LoadSettings reads ritueel.yaml from the root folder of a bundle through package fsx, which follows no
// link, and parses it. A file that does not exist gives an error that wraps fs.ErrNotExist.
func LoadSettings(fsys fsx.FS) (*Settings, error) {
	data, err := readFile(fsys, SettingsPath)
	if err != nil {
		return nil, err
	}
	return ParseSettings(SettingsPath, data)
}

// ParseSettings reads the bytes of a ritueel.yaml under the rules of the package and the shape of
// docs/reference/bundle.md, "ritueel.yaml". path is the path that the errors and the File carry. It
// returns a value or an error, never both.
func ParseSettings(path string, data []byte) (*Settings, error) {
	d, err := read(path, data)
	if err != nil {
		return nil, err
	}
	s, err := d.settings()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// settings fills the type from the nodes of the document.
func (d *document) settings() (*Settings, error) {
	top, err := d.mappingOf(d.root, "", settingsMembers)
	if err != nil {
		return nil, err
	}
	s := &Settings{File: d.file}
	if s.Version, err = top.version(); err != nil {
		return nil, err
	}
	if top.has("kind") {
		if _, err = top.enumStr("kind", kindEnum); err != nil {
			return nil, err
		}
		s.Personal = true
	}
	if err := s.takeWho(top); err != nil {
		return nil, err
	}
	pol, err := top.object("policy", policyMembers)
	if err != nil {
		return nil, err
	}
	if s.Policy, err = pol.policy(); err != nil {
		return nil, err
	}
	if s.Personal {
		for _, store := range s.Policy.Stores {
			switch {
			case store == "piv":
				return nil, pol.fail("stores", "policy.stores holds piv, which is reserved for stage two (the new primaries on the root cards of a person), which is not built yet: a personal bundle has the stores "+strings.Join(personalStoreEnum, " and ")+" now")
			case !slices.Contains(personalStoreEnum, store):
				return nil, pol.fail("stores", "policy.stores holds "+store+", which a person's key cannot use: a personal bundle has the stores "+strings.Join(personalStoreEnum, " and "))
			}
		}
	}
	if top.has("keyring") {
		if s.KeyringLicense, err = top.keyring(); err != nil {
			return nil, err
		}
	}
	if top.has("aws_kms") {
		if s.KMS, err = top.kms(); err != nil {
			return nil, err
		}
	}
	s.made = true
	return s, nil
}

// version reads the member version: the integer 1.
func (m *mapping) version() (int, error) {
	n, err := m.integer("version")
	if err != nil {
		return 0, err
	}
	if n != Version {
		return 0, m.fail("version", "version must be 1")
	}
	return n, nil
}

// takeWho reads the members that differ between a company bundle and a personal one.
func (s *Settings) takeWho(top *mapping) error {
	if s.Personal {
		for _, name := range []string{"name", "release_address"} {
			if top.has(name) {
				return top.fail(name, name+" is not allowed in a personal bundle: it has person instead")
			}
		}
		for _, name := range []string{"aws_kms", "keyring"} {
			if top.has(name) {
				return top.fail(name, name+" is not allowed in a personal bundle: it is a setting of a company bundle, and a person's key is a software key that the person adopts")
			}
		}
		if !top.has("person") {
			return top.d.fail(top.node, "a personal bundle (kind: personal) needs the member person")
		}
		return s.takePerson(top)
	}
	if top.has("person") {
		return top.fail("person", "person is only allowed with kind: personal")
	}
	for _, name := range []string{"name", "release_address"} {
		if !top.has(name) {
			return top.d.fail(top.node, "the member "+name+" is required in a company bundle")
		}
	}
	var err error
	if s.Name, err = top.str("name"); err != nil {
		return err
	}
	if why := nameProblem(s.Name); why != "" {
		return top.fail("name", "name "+why)
	}
	if s.ReleaseAddress, err = top.str("release_address"); err != nil {
		return err
	}
	if why := addressProblem(s.ReleaseAddress); why != "" {
		return top.fail("release_address", "release_address "+why)
	}
	return nil
}

// takePerson reads the member person of a personal bundle.
func (s *Settings) takePerson(top *mapping) error {
	pm, err := top.object("person", personMembers)
	if err != nil {
		return err
	}
	p := &Person{}
	if p.Name, err = pm.str("name"); err != nil {
		return err
	}
	if why := personNameProblem(p.Name); why != "" {
		return pm.fail("name", "person.name "+why)
	}
	if p.Address, err = pm.str("address"); err != nil {
		return err
	}
	if why := addressProblem(p.Address); why != "" {
		return pm.fail("address", "person.address "+why)
	}
	if strings.EqualFold(p.Name, ExamplePersonName) && strings.EqualFold(p.Address, ExamplePersonAddress) {
		return pm.fail("name", "person is the example person of the starter: replace the example person with your name and address")
	}
	s.Person = p
	return nil
}

// personNamePattern is the form of person.name.
var personNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .'-]{0,63}$`)

// personNameProblem is what is wrong with a name of a person (person.name, and the name of a user ID), or ""
// when nothing is: 1 to 64 characters of ASCII letters, digits, spaces, periods, apostrophes and hyphens,
// starting with a letter or a digit, with no space at the end and no two spaces in a row.
func personNameProblem(s string) string {
	switch {
	case !personNamePattern.MatchString(s):
		return "has 1 to 64 characters: ASCII letters, digits, spaces, periods, apostrophes and hyphens, starting with a letter or a digit"
	case strings.HasSuffix(s, " "):
		return "has no space at the end"
	case strings.Contains(s, "  "):
		return "has no two spaces in a row"
	}
	return ""
}

// nameProblem is what is wrong with a name of a company bundle, or "" when nothing is: 1 to 45 ASCII
// letters, digits, single spaces and hyphens, with no space at the start or the end.
func nameProblem(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != ' ' {
			return "has only the ASCII letters A to Z and a to z, digits, single spaces and hyphens"
		}
	}
	switch {
	case s == "" || len(s) > MaxNameLen:
		return fmt.Sprintf("has 1 to %d characters", MaxNameLen)
	case s[0] == ' ' || s[len(s)-1] == ' ':
		return "has no space at the start or the end"
	case strings.Contains(s, "  "):
		return "has no two spaces in a row"
	}
	return ""
}

// addressProblem is what is wrong with an address, or "" when nothing is: one bare address of printable ASCII
// with no space, at most 254 bytes, exactly one "@" and no "<", ">", "[" or "]" (a domain literal), which net/mail
// reads as the whole of the text. It is the one rule of every address: the release address, the address of a
// person and the address of a further user ID.
func addressProblem(s string) string {
	if s == "" || len(s) > 254 {
		return "has 1 to 254 characters"
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return "is printable ASCII with no space"
		}
	}
	const bare = "is one bare address, such as release@example.org"
	if strings.ContainsAny(s, "<>[]") || strings.Count(s, "@") != 1 {
		return bare
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return bare
	}
	return ""
}

// policy reads the policy block.
func (m *mapping) policy() (Policy, error) {
	var p Policy
	var err error
	if p.Stores, err = m.strings("stores", 1, storeEnum); err != nil {
		return Policy{}, err
	}
	if p.MinFirmware, err = m.str("min_firmware"); err != nil {
		return Policy{}, err
	}
	if !firmwarePattern.MatchString(p.MinFirmware) {
		return Policy{}, m.fail("min_firmware", "policy.min_firmware is three numbers of up to nine digits joined by periods, such as 5.7.0")
	}
	if p.PINPolicy, err = m.strings("pin_policy", 1, pinPolicyEnum); err != nil {
		return Policy{}, err
	}
	if p.RequireNameConstraints, err = m.boolean("require_name_constraints"); err != nil {
		return Policy{}, err
	}
	if !p.RequireNameConstraints {
		return Policy{}, m.fail("require_name_constraints", "policy.require_name_constraints must be true: a policy cannot switch the name constraints rule off")
	}
	if p.ValidityMonths, err = m.integer("validity_months"); err != nil {
		return Policy{}, err
	}
	if p.ValidityMonths < 1 {
		return Policy{}, m.fail("validity_months", "policy.validity_months must be at least 1")
	}
	return p, nil
}

// firmwarePattern is the form of min_firmware.
var firmwarePattern = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}$`)

// keyring reads the block keyring: one member, license, a non-empty string of printable ASCII.
func (m *mapping) keyring() (string, error) {
	km, err := m.object("keyring", keyringMembers)
	if err != nil {
		return "", err
	}
	if !km.has("license") {
		return "", nil
	}
	lic, err := km.str("license")
	if err != nil {
		return "", err
	}
	if lic == "" || len(lic) > 128 || strings.ContainsFunc(lic, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return "", km.fail("license", "keyring.license is 1 to 128 characters of printable ASCII")
	}
	return lic, nil
}

// rolePattern is the form of a role ARN: the partition, an account of 12 digits and a role path and name.
var rolePattern = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):role/[!-~]+$`)

// accountPattern is the form of an account id.
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

// maxARN is the longest role ARN that is accepted: the limit of an ARN in IAM, 2048 characters.
const maxARN = 2048

// roleAccount returns the account of a role ARN, and false when s is not a role ARN of the form.
func roleAccount(s string) (string, bool) {
	if len(s) > maxARN {
		return "", false
	}
	m := rolePattern.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// kms reads the block aws_kms.
func (m *mapping) kms() (*KMS, error) {
	km, err := m.object("aws_kms", awsKMSMembers)
	if err != nil {
		return nil, err
	}
	k := &KMS{}
	if v := km.val["account"]; v.Kind == yaml.ScalarNode && v.Tag != "!!str" {
		return nil, km.fail("account", "aws_kms.account must be quoted, so that a leading zero is kept: \"000000000000\"")
	}
	if k.Account, err = km.str("account"); err != nil {
		return nil, err
	}
	if !accountPattern.MatchString(k.Account) {
		return nil, km.fail("account", "aws_kms.account is 12 digits")
	}
	for _, f := range []struct {
		name string
		to   *string
	}{{"region", &k.Region}, {"replica_region", &k.ReplicaRegion}} {
		if *f.to, err = km.str(f.name); err != nil {
			return nil, err
		}
		if v := *f.to; v == "" || len(v) > 64 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
			return nil, km.fail(f.name, "aws_kms."+f.name+" is 1 to 64 characters of printable ASCII with no space")
		}
	}
	if k.Region == k.ReplicaRegion {
		return nil, km.fail("replica_region", "aws_kms.replica_region differs from aws_kms.region")
	}
	for _, f := range []struct {
		name string
		to   *string
	}{{"admin_role", &k.AdminRole}, {"ceremony_role", &k.CeremonyRole}} {
		if *f.to, err = km.str(f.name); err != nil {
			return nil, err
		}
		acct, ok := roleAccount(*f.to)
		if !ok {
			return nil, km.fail(f.name, "aws_kms."+f.name+" is a role ARN, such as arn:aws:iam::111122223333:role/example-admin")
		}
		if acct != k.Account {
			return nil, km.fail(f.name, "aws_kms."+f.name+" is a role in the account aws_kms.account")
		}
	}
	return k, nil
}
