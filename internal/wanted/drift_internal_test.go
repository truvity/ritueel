package wanted

import (
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

// The two JSON Schema blocks of docs/reference/bundle.md are the shape of ritueel.yaml and of a delegation file
// (record 0006, rule 5). The code states the same shape in its tables of members. This test reads
// the blocks and compares the member names, the required members, the enum values and "additionalProperties:
// false" with the tables, so that a member in one and not the other fails. The rules that the schemas cannot
// state (the kind-dependent members, the lists, the accounts) are tested by their own tests.

// schema is the part of a JSON Schema that this test compares.
type schema struct {
	Type                 string             `json:"type"`
	Required             []string           `json:"required"`
	Enum                 []any              `json:"enum"`
	Const                any                `json:"const"`
	AdditionalProperties json.RawMessage    `json:"additionalProperties"`
	Properties           map[string]*schema `json:"properties"`
	Items                *schema            `json:"items"`
}

var schemaBlock = regexp.MustCompile("(?s)```json\n(\\{\n\\s*\"\\$schema\".*?)\n```")

// pageSchemas returns the schema blocks of the page in order of appearance.
func pageSchemas(t *testing.T) []*schema {
	t.Helper()
	page := testrepo.Read(t, "docs", "reference", "bundle.md")
	var out []*schema
	for _, m := range schemaBlock.FindAllSubmatch(page, -1) {
		var s schema
		if err := json.Unmarshal(m[1], &s); err != nil {
			t.Fatalf("a schema block of the page is not JSON: %v", err)
		}
		out = append(out, &s)
	}
	return out
}

func names(members []member) []string {
	var out []string
	for _, m := range members {
		out = append(out, m.name)
	}
	sort.Strings(out)
	return out
}

func requiredOf(members []member) []string {
	var out []string
	for _, m := range members {
		if m.required {
			out = append(out, m.name)
		}
	}
	sort.Strings(out)
	return out
}

func keysOf(m map[string]*schema) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	sort.Strings(out)
	return out
}

func stringsOf(t *testing.T, list []any) []string {
	t.Helper()
	var out []string
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("an enum value of the page is not a string: %v", v)
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// compareObject checks one object of the schema against one table of members: the same names, the same
// required members, no additional properties.
func compareObject(t *testing.T, where string, s *schema, table []member) {
	t.Helper()
	if s == nil {
		t.Fatalf("%s: the page has no such object", where)
	}
	if string(s.AdditionalProperties) != "false" {
		t.Errorf("%s: additionalProperties is %s on the page, and the code refuses every unknown member", where, s.AdditionalProperties)
	}
	if got, want := keysOf(s.Properties), names(table); !slices.Equal(got, want) {
		t.Errorf("%s: the page has the members %v, the code %v", where, got, want)
	}
	// The members that the schema requires are the members that the code requires always; a member that the code
	// requires in some cases only is stated by the page's allOf rule and checked by the code, and is not marked.
	if got, want := sorted(s.Required), requiredOf(table); !slices.Equal(got, want) {
		t.Errorf("%s: the page requires %v, the code %v", where, got, want)
	}
}

// compareEnum checks the enum of a member against the code's list.
func compareEnum(t *testing.T, where string, s *schema, code []string) {
	t.Helper()
	if s == nil {
		t.Fatalf("%s: the page has no such member", where)
	}
	if s.Items != nil {
		s = s.Items
	}
	var page []string
	switch {
	case s.Enum != nil:
		page = stringsOf(t, s.Enum)
	case s.Const != nil:
		page = stringsOf(t, []any{s.Const})
	default:
		t.Fatalf("%s: no enum and no const on the page", where)
	}
	if want := sorted(code); !slices.Equal(page, want) {
		t.Errorf("%s: the page has %v, the code %v", where, page, want)
	}
}

// notOnThePageYet are the members of a delegation file that the code reads and the schema of the page does not
// list yet: card, the card of an openpgp-subkey delegation in a personal bundle. The page is corrected apart
// from the code; the entry goes when it lists the member.
var notOnThePageYet = []string{"card"}

func TestTheSchemasOnThePageAreTheTablesOfTheCode(t *testing.T) {
	blocks := pageSchemas(t)
	if len(blocks) != 2 {
		t.Fatalf("the page holds %d schema blocks, want 2 (ritueel.yaml and a delegation file)", len(blocks))
	}
	settings, delegation := blocks[0], blocks[1]

	compareObject(t, "ritueel.yaml", settings, settingsMembers)
	compareEnum(t, "kind", settings.Properties["kind"], kindEnum)
	compareObject(t, "person", settings.Properties["person"], personMembers)
	compareObject(t, "policy", settings.Properties["policy"], policyMembers)
	policy := settings.Properties["policy"]
	compareEnum(t, "policy.stores", policy.Properties["stores"], storeEnum)
	compareEnum(t, "policy.pin_policy", policy.Properties["pin_policy"], pinPolicyEnum)
	compareObject(t, "keyring", settings.Properties["keyring"], keyringMembers)
	compareObject(t, "aws_kms", settings.Properties["aws_kms"], awsKMSMembers)

	compareObject(t, "a delegation file", delegation, slices.DeleteFunc(slices.Clone(delegationMembers), func(m member) bool { return slices.Contains(notOnThePageYet, m.name) }))
	compareEnum(t, "type", delegation.Properties["type"], typeEnum)
	compareEnum(t, "capability", delegation.Properties["capability"], capabilityEnum)
	compareEnum(t, "use", delegation.Properties["use"], useEnum)
}

// The tables hold what the readers use: every member in a table is read by the code, and the page of the delegation
// names the same three types as the constants.
func TestTheTablesAreComplete(t *testing.T) {
	for name, table := range map[string][]member{
		"settings": settingsMembers, "person": personMembers, "policy": policyMembers, "keyring": keyringMembers,
		"aws_kms": awsKMSMembers, "delegation": delegationMembers, "root": rootMembers,
	} {
		if len(table) == 0 {
			t.Errorf("the table %s is empty: a check that finds nothing fails", name)
		}
		seen := map[string]bool{}
		for _, m := range table {
			if m.name == "" || seen[m.name] {
				t.Errorf("table %s: the member %q is empty or twice", name, m.name)
			}
			seen[m.name] = true
		}
	}
	if !slices.Equal(typeEnum, []string{TypeX509Intermediate, TypeOpenPGPSubkey, TypeSSHCAKey}) {
		t.Errorf("types %v", typeEnum)
	}
	if !slices.Equal(rootKindEnum, []string{"x509", "openpgp", "ssh"}) {
		t.Errorf("root kinds %v", rootKindEnum)
	}
	// The kinds of a root are the kinds that the types of a delegation need.
	for _, typ := range typeEnum {
		if !slices.Contains(rootKindEnum, string(rootKindOf(typ))) {
			t.Errorf("the type %s needs the kind %s, which no root file can have", typ, rootKindOf(typ))
		}
	}
	// The members of a root file: the three of the smallest shape, with version and kind required.
	if !slices.Equal(names(rootMembers), []string{"encryption", "keys", "kind", "revocation_reasons", "test", "version"}) || !slices.Equal(requiredOf(rootMembers), []string{"kind", "version"}) {
		t.Errorf("root members %v, required %v", names(rootMembers), requiredOf(rootMembers))
	}
}

// What the schema lists as members is not read beyond what the tables say: a member that the table lacks is
// refused by name (the readers' own tests), and one that the table holds is read here.
func TestEveryMemberOfTheTablesIsAcceptedByItsReader(t *testing.T) {
	const kms = "aws_kms:\n  account: \"111122223333\"\n  region: eu-west-1\n  replica_region: eu-central-1\n  admin_role: arn:aws:iam::111122223333:role/a\n  ceremony_role: arn:aws:iam::111122223333:role/b\n"
	text := "version: 1\nname: Example\nrelease_address: release@example.org\npolicy:\n  stores: [piv]\n  min_firmware: 5.7.0\n  pin_policy: [once]\n  require_name_constraints: true\n  validity_months: 13\nkeyring:\n  license: CC0-1.0\n" + kms
	s, err := ParseSettings(SettingsPath, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if s.KMS == nil || s.KeyringLicense == "" {
		t.Error("a member that the table holds is not read")
	}
	// Every member of the settings table, with kind and person added in the personal form, is in one of the two files.
	company := []string{"version", "name", "release_address", "policy", "keyring", "aws_kms"}
	personal := []string{"version", "kind", "person", "policy"}
	all := append(slices.Clone(company), personal...)
	for _, m := range settingsMembers {
		if !slices.Contains(all, m.name) {
			t.Errorf("the member %q is in neither form of a bundle that this test builds", m.name)
		}
	}
}
